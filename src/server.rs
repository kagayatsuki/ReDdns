#![allow(dead_code)]
use std::{collections::HashMap, fs::File, io::{ErrorKind, Read, Write}, net::{IpAddr, Ipv4Addr, SocketAddrV4}, process::exit, sync::Arc};

use base64::Engine;
use chrono::Utc;
use clap::Parser;
use env_logger::Env;
use hmac::Mac;
use http_body_util::{BodyExt, Full};
use hyper::{body::{Bytes, Incoming}, Request, Response};
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::{connect::HttpConnector, Client}, rt::TokioExecutor};
use rand::Rng;
use serde::Deserialize;
use tokio::net::UdpSocket;

const OPEN_API_VERSION: &str = "2015-01-09";
const OPEN_API_SIGN_METHOD: &str = "HMAC-SHA1";
const OPEN_API_ENDPOINT: &str = "alidns.cn-hangzhou.aliyuncs.com";

const ACTION_ADD_DOMAIN_RECORD: &str = "AddDomainRecord";
const ACTION_MOD_DOMAIN_RECORD: &str = "UpdateDomainRecord";
const ACTION_LST_DOMAIN_RECORDS: &str = "DescribeDomainRecords";

// 5min
const MIN_UPDATE_INTERVAL: u64 = 300;
// 60sec
const MAX_TIMESTAMP_DIFF: u64 = 60;

const RESULT_OK: u64 = 1_000_000;
const RESULT_EXPIRED: u64 = 2_000_000;
const RESULT_INVALID_NAME: u64 = 3_000_000;
const RESULT_INVALID_NAME_LEN: u64 = 3_000_100;
const RESULT_INCORRECTED_PASS: u64 = 4_000_000;

type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Aliyun OpenAPI AccessKey ID
    #[arg(short, long)]
    id: String,
    /// Aliyun OpenAPI AccessKey Secret
    #[arg(short, long)]
    secret: String,
    /// Ddns map file (json)
    #[arg(short, long)]
    map: String,
    /// Ddns Domain, example: "example.com", this domain should managed by the account associated to AccessKey
    #[arg(short, long)]
    domain: String,
    /// Ddns RR value suffix, example: "rddns", then ddns full domain is "xx.rddns.example.com"
    #[arg(short, long)]
    name: String,
    /// Service UDP socket bind address
    #[arg(short, long, default_value = "0.0.0.0:5535")]
    listen: String
}

/// Ddns项
#[derive(Debug, Deserialize)]
struct DdnsMapItem {
    name: String,
    password: String
}

/// Ddns表
#[derive(Debug, Deserialize)]
struct DdnsMap {
    items: Vec<DdnsMapItem>
}

/// 签名机制实现
/// ## Reference
/// https://help.aliyun.com/zh/sdk/product-overview/rpc-mechanism?spm=a2c4g.2355661.0.i3#section-wml-y32-4a2
#[derive(Debug)]
struct Signature {
    params: String,
    body: String
}

struct Util;

/// Access Key & Secret
struct AccessKey {
    id: String,
    secret: String
}

/// AddDomainRecord操作响应码为2xx时的响应体
#[derive(Deserialize, Debug)]
struct AddDomainRecordResult {
    #[serde(rename(deserialize = "RequestId"))]
    request_id: String,
    #[serde(rename(deserialize = "RecordId"))]
    record_id: String
}

/// UpdateDomainRecord操作响应码为2xx时的响应体
#[derive(Deserialize, Debug)]
struct UpdateDomainRecordResult {
    #[serde(rename(deserialize = "RequestId"))]
    request_id: String,
    #[serde(rename(deserialize = "RecordId"))]
    record_id: String
}

/// 响应码不为2xx时的响应体
#[derive(Deserialize, Debug)]
struct ErrorResult {
    #[serde(rename(deserialize = "RequestId"))]
    request_id: String,
    #[serde(rename(deserialize = "Message"))]
    message: String,
    #[serde(rename(deserialize = "HostId"))]
    host_id: String,
    #[serde(rename(deserialize = "Code"))]
    code: String
}

struct RecordUpdater {
    password_hash: [u8; 16],
    name: String,
    record_id: Option<String>,
    last_ip: Option<Ipv4Addr>,
    last_update: Option<u64>,
    ak: Arc<AccessKey>,
    https: HttpsClient
}

/// OpenAPI DescribeDomainRecords::DomainRecords 解析记录对象
#[derive(Deserialize, Debug)]
struct RawDomainRecord {
    #[serde(rename(deserialize = "Status"))]
    status: String,
    #[serde(rename(deserialize = "Type"))]
    r_type: String,
    #[serde(rename(deserialize = "Remark"))]
    remark: Option<String>,
    #[serde(rename(deserialize = "TTL"))]
    ttl: u64,
    #[serde(rename(deserialize = "RecordId"))]
    record_id: String,
    #[serde(rename(deserialize = "Priority"))]
    priority: Option<u64>,
    #[serde(rename(deserialize = "RR"))]
    rr: String,
    #[serde(rename(deserialize = "DomainName"))]
    domain_name: String,
    #[serde(rename(deserialize = "Value"))]
    value: String,
    #[serde(rename(deserialize = "Locked"))]
    locked: bool,
    #[serde(rename(deserialize = "CreateTimestamp"))]
    create_timestamp: u64,
    #[serde(rename(deserialize = "UpdateTimestamp"))]
    update_timestamp: u64
}

#[derive(Deserialize, Debug)]
struct DomainRecordsWrapper {
    #[serde(rename(deserialize = "Record"))]
    record: Vec<RawDomainRecord>
}

/// OpenAPI DescribeDomainRecords成功返回值
#[derive(Deserialize, Debug)]
struct DescribeDomainRecords {
    #[serde(rename(deserialize = "TotalCount"))]
    total_count: u64,
    #[serde(rename(deserialize = "PageSize"))]
    page_size: u64,
    #[serde(rename(deserialize = "RequestId"))]
    request_id: String,
    #[serde(rename(deserialize = "DomainRecords"))]
    records: DomainRecordsWrapper,
    #[serde(rename(deserialize = "PageNumber"))]
    page_number: u64
}

#[derive(Debug)]
struct DomainRecord {
    name: String,
    value: Ipv4Addr
}

struct ReDdnsService {
    map: HashMap<String, RecordUpdater>,
    suffix: String,
    ak: Arc<AccessKey>,
    domain: String,
    socket: UdpSocket
}

/// MAIN
fn main() {
    // Startup Arguments
    let args = Args::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let mut file = match File::options().read(true).open(&args.map) {
        Ok(f) => f,
        Err(e) => {
            log::error!("Cannot read map file: {e}");
            exit(-1);
        }
    };
    // Read map raw data
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| {
        log::error!("Read map file error: {e}");
        exit(-1)
    }).unwrap();
    // Parse map
    let map: DdnsMap = serde_json::from_slice(&buf).map_err(|e| {
        log::error!("Parse map file error: {e}");
        exit(-1)
    }).unwrap();
    log::info!("Ddns map parsed");
    // Start
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .expect("Tokio runtime initializing failure");
    rt.block_on(async move {
        let srv = ReDdnsService::new(map, args).await;
        srv.start().await;
    })
}

impl Signature {
    pub fn current_timestamp() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }
    
    pub fn nonce_number() -> String {
        let mut rng = rand::thread_rng();
        rng.gen_range(10_0000_0000..99_9999_9999u64).to_string()
    }

    pub fn request_with_pub_headers(uri: String, body: Full<Bytes>) -> Request<Full<Bytes>> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Accept", "application/json")
            .header("User-Agent", "reDdns/0.1")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .expect("Create Request with public headers failure")
    }

    fn encode_param_pair(key: &str, val: &str) -> String {
        format!("{}={}", urlencoding::encode(key), urlencoding::encode(val))
    }

    /// 将按字母排序后的参数列表构造为规范化字符串
    /// ## Reference
    /// 2-5@https://help.aliyun.com/zh/sdk/product-overview/rpc-mechanism?spm=a2c4g.2355661.0.i3#sectiondiv-y9b-x9s-wvp
    fn canonicalized_query_string(params: &Vec<(&str, &str, bool)>) -> String {
        let pairs: Vec<String> = params
            .iter()
            .map(|(k, v, _)| Self::encode_param_pair(k, v))
            .collect();
        pairs.join("&")
    }

    /// 构造待签名字符串
    /// ## Reference
    /// 1@https://help.aliyun.com/zh/sdk/product-overview/rpc-mechanism?spm=a2c4g.2355661.0.i3#sectiondiv-wqi-l21-nxe
    fn string_to_sign(http_method: &str, cano: &str) -> String {
        let mut string = String::from(http_method);
        let slash = urlencoding::encode("/");
        let cano = urlencoding::encode(&cano);
        string.extend(["&", &slash, "&", &cano]);
        string
    }

    /// Base64(HMAC_SHA1(key + '&', UTF_8_Raw(stringToSign)))
    /// ## Reference
    /// 2@https://help.aliyun.com/zh/sdk/product-overview/rpc-mechanism?spm=a2c4g.2355661.0.i3#sectiondiv-wqi-l21-nxe
    fn sig_base64(raw_sign: &str, key: &str) -> String {
        let secret = key.to_string() + "&";
        let mut mac: hmac::Hmac<sha1::Sha1> =
            hmac::Hmac::new_from_slice(secret.as_bytes()).expect("HMAC invalid key");
        mac.update(raw_sign.as_bytes());
        let res = mac.finalize();
        base64::prelude::BASE64_STANDARD.encode(&res.into_bytes())
    }

    pub fn generate(
        http_method: &str,
        ak_id: &str,
        ak_secret: &str,
        action: &str,
        format: &str,
        timestamp: &str,
        version: &str,
        sig_method: &str,
        sig_nonce: &str,
        sig_ver: &str,
        extra_params: Vec<(&str, &str)>
    ) -> Self {
        // Param(key, value, at_uri)
        let mut params = vec![
            ("AccessKeyId", ak_id, true),
            ("Action", action, true),
            ("Format", format, true),
            ("SignatureMethod", sig_method, true),
            ("SignatureNonce", sig_nonce, true),
            ("SignatureVersion", sig_ver, true),
            ("Timestamp", timestamp, true),
            ("Version", version, true),
        ];
        params.extend(extra_params.iter().map(|(k, v)| (*k, *v, false)));
        params.sort_by(|(a, _, _), (b, _, _)| {
            a.cmp(b)
        });

        // 计算签名
        let sig = Self::sig_base64(
            &Self::string_to_sign(http_method, &Self::canonicalized_query_string(&params)),
            ak_secret,
        );
        params.push(("Signature", &sig, true));

        // 生成请求Queries与请求体
        Self {
            params: params
                .iter()
                .filter(|(_, _, au)| *au)
                .map(|(k, v, _)| Self::encode_param_pair(k, v))
                .collect::<Vec<String>>()
                .join("&"),
            body: params
                .iter()
                .filter(|(_, _, au)| !*au)
                .map(|(k, v, _)| Self::encode_param_pair(k, v))
                .collect::<Vec<String>>()
                .join("&")
        }
    }

    pub fn query_str(&self) -> &str {
        &self.params
    }

    pub fn https_uri_with_queries(&self, end_point: &str) -> String {
        format!("https://{}/?{}", end_point, self.query_str())
    }

    pub fn body(&self) -> Full<Bytes> {
        Full::new(Bytes::copy_from_slice(self.body.as_bytes()))
    }
}

impl Util {
    pub async fn receive_response_body(incoming: &mut Response<Incoming>) -> Result<Vec<u8>, hyper::Error> {
        let mut buf = Vec::<u8>::new();
        while let Some(frame) = incoming.body_mut().frame().await {
            let frame = frame?;
            if let Some(d) = frame.data_ref() {
                buf.extend(d.iter());
            }
        }
        Ok(buf)
    }
}

impl AccessKey {
    pub fn new(key: String, secret: String) -> Self {
        Self {
            secret,
            id: key
        }
    }

    pub fn new_arc(key: String, secret: String) -> Arc<Self> {
        Arc::new(Self::new(key, secret))
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl ToString for ErrorResult {
    fn to_string(&self) -> String {
        format!("Message: {}, HostId: {}, Code: {}", self.message, self.host_id, self.code)
    }
}

impl RecordUpdater {
    pub fn new(ak: Arc<AccessKey>, password: &str, name: String, record: Option<(Ipv4Addr, String)>) -> Self {
        let md5 = md5::compute(password.as_bytes()).0;
        let (ip, rid) = match record {
            Some((ip, id)) => (Some(ip), Some(id)),
            None => (None, None)
        };

        let https = HttpsConnector::new();
        let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https);

        Self {
            password_hash: md5,
            name,
            last_ip: ip,
            last_update: None,
            record_id: rid,
            ak,
            https: client
        }
    }

    pub async fn update(&mut self, ip: Ipv4Addr, suffix: &str, domain: &str) {
        // 最小更新间隔
        let current = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if let Some(last) = self.last_update {           
            if current.abs_diff(last) < MIN_UPDATE_INTERVAL {
                return ();
            }
        }
        // DNS解析记录ID
        let record_id = match &self.last_ip {
            // 已有记录，更新记录
            Some(i) => {
                // 与上次记录相同，不更新
                if i == &ip {
                    return ();
                }
                match self.update_record(ip, suffix).await {
                    Ok(rid) => rid,
                    Err(e) => {
                        log::error!("Update record [{}] failure: {}", self.name, e);
                        return ();
                    }
                }
            },
            // 没有记录，创建记录
            None => match self.create_record(ip, domain, suffix).await {
                Ok(rid) => rid,
                Err(e) => {
                    log::error!("Create record [{}] failure: {}", self.name, e);
                    return ();
                }
            }
        };
        log::info!("Record [{}] updated, new record value [{}]", self.name, ip);
        self.last_ip = Some(ip);
        self.last_update = Some(current);
        self.record_id = Some(record_id);
    }

    async fn create_record(&self, ip: Ipv4Addr, domain: &str, suffix: &str) -> Result<String, String> {
        // 生成签名和请求参数
        let sig = Signature::generate(
            "POST", 
            &self.ak.id, 
            &self.ak.secret, 
            ACTION_ADD_DOMAIN_RECORD, 
            "JSON", 
            &Signature::current_timestamp(), 
            OPEN_API_VERSION,
            OPEN_API_SIGN_METHOD,
            &Signature::nonce_number(), 
            "1.0", 
            vec![
                ("DomainName", domain),
                ("RR", &format!("{}{}", &self.name, suffix)),
                ("Type", "A"),
                ("Value", &ip.to_string())
            ]
        );
        // 发送请求
        let body = sig.body();
        let mut res = self.https
            .request(
                Signature::request_with_pub_headers(
                    sig.https_uri_with_queries(OPEN_API_ENDPOINT), 
                    body
                )
            )
            .await
            .map_err(|e| e.to_string())?;
        
        // 判断请求成功，成功返回Ok(recordId)，失败返回Err(errorCode)
        // 取出响应
        let buf = Util::receive_response_body(&mut res).await.map_err(|e| e.to_string())?;
        // 判断请求成功
        match res.status().is_success() {
            true => {
                let result: AddDomainRecordResult = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;
                Ok(result.record_id)
            },
            false => {
                let result: ErrorResult = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;
                Err(format!("ResCode: {}, {}", res.status().as_u16(), result.to_string()))
            }
        }
    }

    async fn update_record(&self, ip: Ipv4Addr, suffix: &str) -> Result<String, String> {
        if self.record_id.is_none() {
            return Err("RecordId is not available".to_string());
        }
        let sig = Signature::generate(
            "POST", 
            self.ak.id(),
            self.ak.secret(), 
            ACTION_MOD_DOMAIN_RECORD, 
            "JSON", 
            &Signature::current_timestamp(), 
            OPEN_API_VERSION, 
            OPEN_API_SIGN_METHOD, 
            &Signature::nonce_number(), 
            "1.0", 
            vec![
                ("RecordId", self.record_id.as_ref().unwrap()),
                ("RR", &format!("{}{}", &self.name, suffix)),
                ("Type", "A"),
                ("Value", &ip.to_string())
            ]
        );
        // 请求
        let mut res = self.https
            .request(
                Signature::request_with_pub_headers(
                    sig.https_uri_with_queries(OPEN_API_ENDPOINT), 
                    sig.body()
                )
            ).await
            .map_err(|e| e.to_string())?;
        // 判断
        let buf = Util::receive_response_body(&mut res)
            .await
            .map_err(|e| e.to_string())?;
        match res.status().is_success() {
            true => {
                let result: UpdateDomainRecordResult = serde_json::from_slice(&buf)
                    .map_err(|e| format!("Parse result error: {e}"))?;
                Ok(result.record_id)
            },
            false => {
                let result: ErrorResult = serde_json::from_slice(&buf)
                    .map_err(|e| format!("Parse result error: {e}"))?;
                Err(format!("ResCode: {}, {}", res.status().as_u16(), result.to_string()))
            }
        }
    }

    pub fn password_hash(&self) -> &[u8] {
        &self.password_hash
    }
}

impl ReDdnsService {
    async fn new(map: DdnsMap, arg: Args) -> Self {
        // Parse service listening address (only v4)
        let bind: SocketAddrV4 = arg.listen.parse().map_err(|e| {
            log::error!("Could not parse address [{}]: {}", arg.listen, e);
            exit(-1)
        }).unwrap();
        // Bind service udp
        log::info!("Binding udp");
        let udp = UdpSocket::bind(bind).await.map_err(|e| {
            log::error!("Could not bind UDP at [{}]: {}", bind, e);
            exit(-1)
        }).unwrap();
        // Temp init
        let mut tmp = Self {
            map: HashMap::new(),
            suffix: format!(".{}", arg.name),
            ak: AccessKey::new_arc(arg.id, arg.secret),
            domain: arg.domain,
            socket: udp
        };
        // Fetching current records
        let filter_map = Self::fetch_domain_records(&tmp).await.unwrap();
        // Filter
        for item in map.items.iter() {
            let rec = match filter_map.get(&item.name) {
                Some((ip, rid)) => Some((ip.clone(), rid.clone())),
                None => None
            };
            log::info!("Ddns record: [{}] -> {:?}", item.name, rec);
            let updater = RecordUpdater::new(tmp.ak.clone(), &item.password, item.name.clone(), rec);
            tmp.map.insert(item.name.clone(), updater);
        }
    
        tmp
    }

    async fn start(mut self) {
        let mut buf = [0u8; 64];
        loop {
            let (len, addr) = match self.socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(ref e) if e.kind() == ErrorKind::ConnectionReset => continue,
                Err(e) => {
                    log::error!("Receive Error: {e}");
                    continue;
                }
            };
            if !addr.is_ipv4() || len < 64 {
                continue;
            }
            // Data Field
            // 16B - Md5
            // 8B - Timestamp
            // 2B - Name Length
            // 38B - Name Field
            // 校验过期
            let current = Utc::now().timestamp() as u64;
            // let current = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let provided = u64::from_le_bytes(buf[16..24].try_into().unwrap());
            if current.abs_diff(provided) > MAX_TIMESTAMP_DIFF {
                let _ = self.socket.send_to(&RESULT_EXPIRED.to_le_bytes(), addr).await;
                log::info!("[{}] Notify Pack: Expired, current: {}, provided: {}", addr, current, provided);
                continue;
            }
            // 校验名称长度
            let name_length = u16::from_le_bytes(buf[24..26].try_into().unwrap()) as usize;
            if name_length > 38 {
                log::info!("[{}] Notify Pack: Invalid name length", addr.ip());
                let _ = self.socket.send_to(&RESULT_INVALID_NAME_LEN.to_le_bytes(), addr).await;
                continue;
            }
            let ddns_name = String::from_utf8_lossy(&buf[26..][..name_length]).to_string();
            // 校验Ddns项存在
            let ddns = match self.map.get_mut(&ddns_name) {
                Some(updater) => updater,
                None => {
                    log::info!("[{}] Notify Pack: Name not available", addr.ip());
                    let _ = self.socket.send_to(&RESULT_INVALID_NAME.to_le_bytes(), addr).await;
                    continue;
                }
            };
            // 校验安全哈希
            let mut ctx = md5::Context::new();
            ctx.write(&buf[16..64]).unwrap();
            ctx.write(ddns.password_hash()).unwrap();
            let hash = ctx.compute().0;
            if &hash != &buf[..16] {
                log::info!("[{}] Notify Pack: Incorrected password", addr.ip());
                let _ = self.socket.send_to(&RESULT_INCORRECTED_PASS.to_le_bytes(), addr).await;
                continue;
            }
            // 更新DNS解析记录
            if let IpAddr::V4(ip) = addr.ip() {
                ddns.update(ip, &self.suffix, &self.domain).await;
                let _ = self.socket.send_to(&RESULT_OK.to_le_bytes(), addr).await;
            }
        }
    }

    async fn fetch_domain_records(srv: &Self) -> Result<HashMap<String, (Ipv4Addr, String)>, ()> {
        let client = Client::builder(TokioExecutor::new()).build(HttpsConnector::new());
        let mut page = 1;
        let mut filter_map = HashMap::<String, (Ipv4Addr, String)>::new();
        loop {
            // 执行DescribeDomainRecords动作
            let records = Self::describe_domain_a_records(&client, srv.ak.clone(), page, &srv.domain, &srv.suffix)
                .await
                .map_err(|e| {
                    log::error!("Fetching dns records failure: {e}");
                    exit(-1)
                })
                .unwrap();
            // 计算总页数
            let page_total = records.total_count.div_ceil(records.page_size);
            // Push to filter map
            for item in records.records.record.iter() {
                // 排除非suffix结尾的记录
                if !item.rr.ends_with(&srv.suffix) {
                    continue;
                }
                if let (Ok(ip), record_id) = (item.value.parse(), item.record_id.clone()) {
                    log::info!("Fetched record [{}] -> [{}]", item.rr, ip);
                    filter_map.insert(
                        item.rr[..item.rr.len() - srv.suffix.len()].to_string(), 
                        (ip, record_id)
                    );
                } else {
                    log::warn!("Record [{}] Id [{}] parsing value [{}] to ip failed", item.rr, item.record_id, item.value);
                }
            }
            // 记录读完
            if records.page_number >= page_total {
                break;
            }
            page += 1;
        }
        Ok(filter_map)
    }

    /// DescribeDomainRecords
    /// ## Reference
    /// https://help.aliyun.com/document_detail/2357159.html#api-detail-21
    async fn describe_domain_a_records(client: &HttpsClient, ak: Arc<AccessKey>, page: u64, domain: &str, suffix: &str) -> Result<DescribeDomainRecords, String> {
        let sig = Signature::generate(
            "POST", 
            &ak.id, 
            &ak.secret, 
            ACTION_LST_DOMAIN_RECORDS, 
            "JSON", 
            &Signature::current_timestamp(), 
            OPEN_API_VERSION,
            OPEN_API_SIGN_METHOD,
            &Signature::nonce_number(), 
            "1.0",
            vec![
                ("DomainName", domain),
                ("PageNumber", &page.to_string()),
                ("RRKeyWord", suffix),
                ("Type", "A")
            ]
        );
        let mut res = client.request(
            Signature::request_with_pub_headers(
                sig.https_uri_with_queries(OPEN_API_ENDPOINT), 
                sig.body()
            )
        ).await.map_err(|e| format!("Request error: {}", e))?;
        let buf = Util::receive_response_body(&mut res)
            .await.map_err(|e| format!("Receive error: {}", e))?;
        
        match res.status().is_success() {
            true => {
                let res: DescribeDomainRecords = serde_json::from_slice(&buf).map_err(|e| format!("Deserialize error: {}", e))?;
                Ok(res)
            },
            false => {
                let err: ErrorResult = serde_json::from_slice(&buf).map_err(|e| format!("Deserialize error: {}", e))?;
                Err(format!("ResCode: {}, {}", res.status().as_u16(), err.to_string()))
            }
        }
    }
}
