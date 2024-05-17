use std::{fs::File, io::{BufReader, ErrorKind, Write}, net::SocketAddr, process::exit, time::Duration};

use chrono::Utc;
use clap::Parser;
use env_logger::Env;
use serde::Deserialize;
use tokio::{net::UdpSocket, time::timeout};

const RESULT_OK: u64 = 1_000_000;
const RESULT_EXPIRED: u64 = 2_000_000;
const RESULT_INVALID_NAME: u64 = 3_000_000;
const RESULT_INVALID_NAME_LEN: u64 = 3_000_100;
const RESULT_INCORRECTED_PASS: u64 = 4_000_000;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[clap(disable_help_flag = true)]
struct Args {
    /// Config file path
    #[arg(short, long)]
    config: Option<String>,
    /// ReDdns server service host
    #[arg(short('h'), long("host"))]
    service_host: Option<String>,
    /// ReDdns server service port
    #[arg(short('p'), long("port"), default_value_t = 5535)]
    service_port: u16,
    /// ReDdns Record name
    #[arg(short('n'), long("name"))]
    ddns_name: Option<String>,
    /// ReDdns Record secret
    #[arg(short('s'), long("secret"))]
    ddns_password: Option<String>,
    /// Posting package interval (secs)
    #[arg(short, long, default_value_t = 60)]
    interval: u32
}

#[derive(Debug, Deserialize)]
struct Config {
    host: String,
    port: u16,
    name: String,
    secret: String,
    interval: u32
}

struct Notifier {
    service_addr: SocketAddr,
    interval: u32,
    pass: String,
    name: String
}

fn main() {
    let mut args = Args::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    // 优先Config文件
    if let Some(path) = &args.config {
        let file = File::options()
            .read(true)
            .open(path)
            .map_err(|e| {
                log::error!("Could not open config file: {e}");
                exit(-1)
            }).unwrap();
        // Config覆盖参数
        let config: Config = serde_json::from_reader(BufReader::new(file))
            .map_err(|e| {
                log::error!("Could not parse config file: {e}");
                exit(-1)
            })
            .unwrap();
        args.ddns_name = Some(config.name);
        args.ddns_password = Some(config.secret);
        args.service_host = Some(config.host);
        args.service_port = config.port;
        args.interval = config.interval;
    }

    // Interval min limit
    if args.interval < 10 {
        log::error!("Posting interval secs too small!");
        exit(-1)
    }

    let mut notifier = Notifier::new(args).map_err(|msg| {
        log::error!("Notifier initializing failure: {msg}");
        exit(-1)
    }).unwrap();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .worker_threads(1)
        .build()
        .expect("Tokio Runtime build error")
        .block_on(notifier.start());
}

impl Notifier {
    fn gen_pack(password: &str, name: &str) -> [u8; 64] {
        let mut buf = [0u8; 64];
        
        // Timestamp
        let current = Utc::now().timestamp() as u64;
        // let current = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        //println!("Current: {current}");
        buf[16..24].copy_from_slice(&current.to_le_bytes());
        // Name len
        buf[24..26].copy_from_slice(&(name.len() as u16).to_le_bytes());
        // Name
        buf[26..][..name.as_bytes().len()].copy_from_slice(name.as_bytes());
        // Pass hash
        let pass_hash = md5::compute(password.as_bytes()).0;
        // Hash
        let mut ctx = md5::Context::new();
        ctx.write(&buf[16..]).unwrap();
        ctx.write(&pass_hash).unwrap();
        buf[..16].copy_from_slice(&ctx.compute().0);
    
        buf
    }

    pub fn new(arg: Args) -> Result<Self, &'static str> {
        let addr: SocketAddr = format!(
            "{}:{}", 
            arg.service_host.ok_or("ReDdns service host not provided")?, 
            arg.service_port
        ).parse().map_err(|_| "Could not parse ReDdns service host")?;

        Ok(Self {
            service_addr: addr,
            interval: arg.interval,
            pass: arg.ddns_password.ok_or("ReDdns record password not provided")?,
            name: arg.ddns_name.ok_or("ReDdns record name not provided")?
        })
    }

    pub async fn start(&mut self) {
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| {
                log::error!("Could not bind UDP socket: {e}");
                exit(-1)
            }).unwrap();
        
        loop {
            // Send notify pack
            let pack = Self::gen_pack(&self.pass, &self.name);
            socket.send_to(&pack, self.service_addr).await.map_err(|e| {
                log::error!("Sent notify pack to [{}] failure: {}", self.service_addr, e);
                exit(-1)
            }).unwrap();

            // Wait response
            let mut buf = [0u8; 32];
            let code = match timeout(Duration::from_secs(30), Self::recv_from_target(&socket, self.service_addr, &mut buf)).await {
                Ok(Ok(len)) => {
                    if len != 8 {
                        log::error!("Received ReDdns response length is unexpected");
                        exit(-1)
                    }
                    u64::from_le_bytes(buf[..8].try_into().unwrap())
                },
                Ok(Err(e)) => {
                    log::error!("Receiving ReDdns response error: {e}");
                    exit(-1)
                },
                Err(_) => {
                    log::error!("Waiting ReDdns response timeout");
                    exit(-1)
                }
            };

            // Code case
            let msg = match code {
                RESULT_OK => "OK",
                RESULT_EXPIRED => "Local timestamp diff with remote service too large",
                RESULT_INCORRECTED_PASS => "Incorrect ReDdns Record password",
                RESULT_INVALID_NAME => "Invalid ReDdns Record name",
                RESULT_INVALID_NAME_LEN => "Invalid ReDdns Record name length",
                _ => {
                    log::error!("Unexpected response: [{code}]");
                    exit(-1)
                }
            };
            log::info!("ReDdns Response: {msg}");

            tokio::time::sleep(Duration::from_secs(self.interval as u64)).await;
        }
    }

    async fn recv_from_target(udp: &UdpSocket, target_addr: SocketAddr, buf: &mut[u8]) -> Result<usize, std::io::Error> {
        loop {
            match udp.recv_from(buf).await {
                Ok((len, addr)) => {
                    if addr == target_addr {
                        return Ok(len);
                    }
                    continue;
                },
                Err(ref e) if e.kind() == ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e)
            }
        }
    }
}
