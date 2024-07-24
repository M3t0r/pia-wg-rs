use std::{
    collections::HashMap, error::Error, fmt::{Debug, Display}, fs, net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs}, path::PathBuf, str::FromStr, sync::{Arc, RwLock}, time::Duration
};

use base64ct::Encoding;
use clap::{Args, Parser, Subcommand};
use fastping_rs::Pinger;
use rand::RngCore;
use serde::{de::Visitor, Deserialize, Serialize};
use slog::{debug, error, info, o, Drain};
use thiserror::Error;

const PIA_SERVER_API_PORT: u16 = 1337u16;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Timeout for every request
    #[arg(
        global = true,
        long,
        short = 't',
        value_name = "SECONDS",
        default_value_t = 3
    )]
    timeout: u64,

    #[arg(global = true, long, env = "DEBUG")]
    debug: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Login with user+password and echo a API token
    Token {
        #[arg(long, requires = "password", env = "PIA_USER")]
        username: String,
        #[arg(long, requires = "username", env = "PIA_PASS")]
        password: String,
    },
    /// List available servers
    Servers {
        /// Filter servers in a specific country (ISO Alpha-2 country codes)
        #[arg(long)]
        country: Option<String>,
        /// Filter servers of a specific region
        #[arg(long)]
        region: Option<String>,
        /// Filter servers that support port forwarding
        #[arg(long)]
        port_forward: bool,
        /// Measure latency to servers by pinging them N times
        #[arg(long, value_name = "N", require_equals = true, num_args = 0..=1, default_missing_value = "3")]
        measure: Option<u8>,
        /// Only list the closest N servers
        #[arg(long, value_name = "N", require_equals = true, num_args = 0..=1, default_missing_value = "5")]
        top: Option<u8>,
    },
    /// Generates a new wireguard config
    Create {
        #[command(flatten)]
        auth: AuthOptions,
        /// The name of the region to generate the wg.conf for. Use the servers command to find an
        /// appropiate one for you.
        #[arg(long)]
        region: String,
        /// Use PIA's DNS when active (requires to use wg-quick)
        #[arg(long)]
        dns: bool,
        /// Measure latency to servers by pinging them N times
        #[arg(long, value_name = "N", default_value_t = 3)]
        measure: u8,
        /// Filter servers that support port forwarding
        #[arg(long)]
        port_forward: bool,
    },
    /// Verify the VPN connection is active and used
    Check {
        conf: PathBuf,
    },
}

#[derive(Args, Debug, Clone)]
#[group(required = true)]
struct AuthOptions {
    #[arg(long, conflicts_with = "username", env = "PIA_TOKEN")]
    token: Option<String>,
    #[arg(long, requires = "password", env = "PIA_USER")]
    username: Option<String>,
    #[arg(long, requires = "username", env = "PIA_PASS")]
    password: Option<String>,
}
impl AuthOptions {
    fn get_token(
        &self,
        log: &slog::Logger,
        http_agent: &ureq::Agent,
    ) -> Result<Token, Box<dyn Error>> {
        match &self.token {
            Some(token) => Ok(token.clone()),
            None => Ok(get_token(
                log,
                http_agent,
                self.username.clone().expect("username has to be set"),
                self.password.clone().expect("password has to be set"),
            )?),
        }
    }
}

type Token = String;

fn make_logger(debug: bool) -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain)
        .overflow_strategy(slog_async::OverflowStrategy::Block)
        .build()
        .fuse();
    let drain = drain
        .filter_level(if debug {
            slog::Level::Debug
        } else {
            slog::Level::Info
        })
        .fuse();

    slog::Logger::root(drain, o!())
}

#[derive(Clone)]
struct ResolverStore {
    db: Arc<RwLock<HashMap<String, SocketAddr>>>,
    log: slog::Logger,
}
impl ResolverStore {
    fn new(log: &slog::Logger) -> Self {
        Self {
            db: Default::default(),
            log: log.clone(),
        }
    }
    fn add<S>(&self, fqdn: S, port: u16, addr: IpAddr)
    where
        S: Display,
    {
        let name = format!("{fqdn}:{port}");
        let addr = SocketAddr::new(addr, port);
        debug!(self.log, "adding new resolver entry"; "name" => name.clone(), "addr" => addr.to_string());
        self.db
            .write()
            .expect("ResolverStore could not acquire write lock")
            .insert(name, addr);
    }
}
impl ureq::Resolver for ResolverStore {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let db = self.db.read().expect("ResolverStore RwLock was poisend");
        let num_entries = db.len();
        let entry = db.get(netloc).copied();
        drop(db);

        let res = match entry {
            Some(addr) => Ok(vec![addr]),
            None => netloc.to_socket_addrs().map(Iterator::collect),
        };
        debug!(self.log, "resolved addr"; "name" => netloc, "addr" => format!("{:?}", res), "entries" => num_entries);
        res
    }
}

fn make_tls_config() -> rustls::client::ClientConfig {
    let pia_ca = include_bytes!("../ca.rsa.4096.crt");
    let pia_ca = rustls_pemfile::read_one_from_slice(pia_ca).expect("Error parsing the PIA CA pem");
    let (pia_ca, remaining_bytes) = pia_ca.expect("No cert in embedded PIA CA pem found");
    assert_eq!(
        remaining_bytes.len(),
        0,
        "Embedded PIA CA pem has unhandled data"
    );
    let rustls_pemfile::Item::X509Certificate(pia_ca) = pia_ca else {
        panic!("Embedde PIA CA pem is not a certificate")
    };
    let pia_ca = webpki::anchor_from_trusted_cert(&pia_ca)
        .expect("Could not parse embedded PIA CA certificate");
    let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots([pia_ca.to_owned()]);

    rustls::ClientConfig::builder()
        .dangerous() // required to provide our own verifier, but that verifier is safe
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}

fn make_http_agent(log: &slog::Logger, timeout: Duration) -> (ureq::Agent, ResolverStore) {
    let store: ResolverStore = ResolverStore::new(log);
    let http_agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .resolver(store.clone())
        .tls_config(Arc::new(make_tls_config()))
        .user_agent(format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")).as_str())
        .build();

    (http_agent, store)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = Cli::parse();
    let timeout = Duration::from_secs(cli_args.timeout);

    let log = make_logger(cli_args.debug);
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("could not install default crypto provider");
    let (http_agent, resolver_store) = make_http_agent(&log, timeout);

    debug!(log, "startup"; "args" => format!("{:?}", cli_args));

    match cli_args.command {
        Commands::Token { username, password } => {
            println!("{}", get_token(&log, &http_agent, username, password)?);
        }
        Commands::Servers {
            country,
            region,
            port_forward,
            measure,
            top,
        } => {
            let mut servers = get_server_list(&log, &http_agent)?;

            if let Some(country) = country {
                servers.retain(|s| s.country.to_lowercase() == country.to_lowercase());
            }

            if let Some(region) = region {
                servers.retain(|s| s.region_id == region || s.region_name == region);
            }

            if port_forward {
                servers.retain(|s| s.port_forward);
            }

            if servers.is_empty() {
                error!(log, "no servers found matching your criteria");
                Err("no servers found matching your criteria")?;
            }

            if let Some(measure) = measure {
                let ping_results = ping_servers(&log, &servers, measure, timeout)?;
                let mut servers = servers.enrich(&ping_results);

                if let Some(top) = top {
                    servers.top(top);
                }

                drop(log); // flush all log messages
                for (median_ping, s) in servers.into_iter() {
                    let median_ping = median_ping.map_or("unreachable".to_string(), |p| {
                        format!("{:>6.2}ms", p.as_nanos() as f32 / 1000000f32)
                    });
                    println!(
                        "found server: {} {:16} {:16} {:2} {:19} {:34} {:12} dns {}",
                        median_ping,
                        s.name,
                        s.ip.to_string(),
                        s.country,
                        s.region_id,
                        s.region_name,
                        if s.port_forward { "port forward" } else { "" },
                        s.dns_server,
                    );
                }
            } else {
                drop(log); // flush all log messages
                for s in servers.into_iter() {
                    println!(
                        "found server: {:2} {:16} {:16} {:19} {:34} {:12} dns {}",
                        s.name,
                        s.ip.to_string(),
                        s.country,
                        s.region_id,
                        s.region_name,
                        if s.port_forward { "port forward" } else { "" },
                        s.dns_server,
                    );
                }
            }
        }
        Commands::Create {
            auth,
            region,
            measure,
            port_forward,
            dns,
        } => {
            let servers = get_server_list(&log, &http_agent)?;
            let mut servers = servers.get_region(&region);
            if port_forward {
                servers.retain(|s| s.port_forward);
            }
            if servers.is_empty() {
                error!(log, "requested region not found");
                Err("requested region not found")?;
            }

            let ping_results = ping_servers(&log, &servers, measure, timeout)?;
            let mut servers = servers.enrich(&ping_results);
            let server = servers.best().ok_or("No suitable server found")?;

            let token = auth.get_token(&log, &http_agent)?;
            let private_key = WGPrivateKey::new();
            let public_key = private_key.public();

            resolver_store.add(&server.name, PIA_SERVER_API_PORT, server.ip);
            let added = add_wg_key(&log, &http_agent, token, &server, &public_key)?;

            let mut conf = WGConf::from(added, private_key);
            if !dns {
                conf.disable_dns()
            }

            let ini = conf.to_ini()?;
            println!("{ini}");
        }
        Commands::Check{ conf } => {
            let conf = fs::read_to_string(conf)?;
            let conf = WGConf::from_ini(conf)?;
            let public = get_public_ip(&log, &http_agent)?;
            println!("IP: {}, country: {}, ISP: {}", public.ip, public.country, public.isp);
            if public.ip != conf.peer.endpoint.ip() {
                error!(log, "Not connected to PIA. Request went through the open internet");
                return Err("Not connected to PIA. Request went through the open internet".into());
            } else {
                info!(log, "IP matches our VPN server, request got routed through VPN");
            }
        }
    }

    Ok(())
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Token,
}

fn get_token(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
    username: String,
    password: String,
) -> Result<Token, Box<dyn Error>> {
    let endpoint = "https://www.privateinternetaccess.com/api/client/v2/token";
    debug!(log, "logging in"; "user" => username.clone());
    let resp: TokenResponse = http_agent
        .post(endpoint)
        .send_form(&[
            ("username", username.as_str()),
            ("password", password.as_str()),
        ])?
        .into_json()?;
    Ok(resp.token)
}

#[derive(Debug, Clone)]
struct Server {
    ip: IpAddr,
    name: String,
    region_id: String,
    region_name: String,
    country: String,
    dns_server: String,
    port_forward: bool,
}

struct ServerList(Vec<Server>);
impl<'a> IntoIterator for &'a ServerList {
    type Item = &'a Server;
    type IntoIter = std::slice::Iter<'a, Server>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
impl IntoIterator for ServerList {
    type Item = Server;
    type IntoIter = std::vec::IntoIter<Server>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
impl ServerList {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Server) -> bool,
    {
        self.0.retain(f)
    }
    fn get_region(self, region: &str) -> Self {
        Self(
            self.0
                .into_iter()
                .filter(|s| s.region_name == region || s.region_id == region)
                .collect(),
        )
    }
    fn enrich(self, ping_results: &PingResults) -> PingedServerList {
        let mut servers: Vec<(Option<Duration>, Server)> = self
            .0
            .into_iter()
            .map(|s| {
                let (median_ping, _) = ping_results.get(&s.ip).expect("didn't ping all servers");
                (*median_ping, s)
            })
            .collect();

        servers.sort_by(|(p1, _), (p2, _)| match (p1, p2) {
            (Some(p1), Some(p2)) => p2.cmp(p1),
            (None, None) => std::cmp::Ordering::Equal,
            (None, _) => std::cmp::Ordering::Less,
            (_, None) => std::cmp::Ordering::Greater,
        });

        PingedServerList(servers)
    }
}

struct PingedServerList(Vec<(Option<Duration>, Server)>);
impl<'a> IntoIterator for &'a PingedServerList {
    type Item = &'a (Option<Duration>, Server);
    type IntoIter = std::slice::Iter<'a, (Option<Duration>, Server)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
impl IntoIterator for PingedServerList {
    type Item = (Option<Duration>, Server);
    type IntoIter = std::vec::IntoIter<(Option<Duration>, Server)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
impl PingedServerList {
    // fn is_empty(&self) -> bool { self.0.is_empty() }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn top(&mut self, top: u8) {
        self.0.drain(..self.len().saturating_sub(top.into()));
    }
    fn best(&mut self) -> Option<Server> {
        self.0.last().map(|(_, s)| s).cloned()
    }
}

// structure: https://github.com/pia-foss/mobile-ios-library/blob/40c1afb5f143bd061e322093a6d11e798739c10c/Sources/PIALibrary/WebServices/Server.swift#L33
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ServerListResponse {
    groups: HashMap<String, serde_json::Value>,
    regions: Vec<Region>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Region {
    id: String,
    name: String,
    country: String,
    auto_region: bool,
    #[serde(rename = "dns")]
    dns_server: String,
    port_forward: bool,
    geo: bool,
    offline: bool,
    servers: RegionServers,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RegionServers {
    wg: Option<Vec<WGServer>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct WGServer {
    ip: IpAddr,
    #[serde(rename = "cn")]
    name: String,
}

fn get_server_list(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
) -> Result<ServerList, Box<dyn Error>> {
    let endpoint = "https://serverlist.piaservers.net/vpninfo/servers/v6";
    let resp = http_agent.get(endpoint).call()?.into_string()?;

    debug!(log, "network: server list"; "resp" => &resp);

    let mut split = resp.rsplit("\n\n");
    // todo: verify signature
    // algo: https://github.com/pia-foss/mobile-shared-regions/blob/592fc4f403df3006e98396fc5b063ad624d470b6/regions/src/androidMain/kotlin/com/privateinternetaccess/regions/internals/MessageVerificator.kt#L32-L41
    // key: https://github.com/pia-foss/mobile-shared-regions/blob/592fc4f403df3006e98396fc5b063ad624d470b6/regions/src/commonMain/kotlin/com/privateinternetaccess/regions/internals/Regions.kt#L50-L58
    let _signature = split
        .next()
        .ok_or("serverlist response did not have a signature")?;
    let server_list = split.next().ok_or("serverlist was malformed")?;
    let server_list: ServerListResponse = serde_json::from_str(server_list)?;

    info!(
        log, "got server list";
        "wg_servers" => server_list.regions.iter().map(|r| r.servers.wg.clone().unwrap_or_default().len()).sum::<usize>(),
        "regions" => server_list.regions.len()
    );

    let mut servers = Vec::new();

    for region in server_list.regions {
        let template = Server {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            name: String::new(),

            region_name: region.name,
            region_id: region.id,
            country: region.country,
            port_forward: region.port_forward,
            dns_server: region.dns_server,
        };
        for server in region.servers.wg.unwrap_or(vec![]) {
            servers.push(Server {
                ip: server.ip,
                name: server.name,
                ..template.clone()
            });
        }
    }

    Ok(ServerList(servers))
}

type PingResults = HashMap<IpAddr, (Option<Duration>, Vec<Option<Duration>>)>;

fn ping_servers(
    log: &slog::Logger,
    servers: &ServerList,
    pings: u8,
    timeout: Duration,
) -> Result<PingResults, Box<dyn Error>> {
    let mut measurements: HashMap<IpAddr, Vec<Option<Duration>>> = HashMap::new();
    info!(
        log, "pinging";
        "servers" => servers.len(),
        "measurements" => pings,
    );

    let (pinger, result_stream) = Pinger::new(Some(timeout.as_millis() as u64), None)?;
    for s in servers {
        pinger.add_ipaddr(&s.ip.to_string());
    }
    let mut num_responses = servers.len().saturating_mul(pings.into());
    pinger.run_pinger();
    loop {
        let result = result_stream.recv()?;
        let (measurement, addr) = match result {
            fastping_rs::PingResult::Idle { addr } => (None, addr),
            fastping_rs::PingResult::Receive { addr, rtt } => (Some(rtt), addr),
        };
        debug!(
            log, "network: received ICMP Echo";
            "addr" => format!("{}", addr),
            "rtt" => format!("{:?}", measurement)
        );
        measurements.entry(addr).or_default().push(measurement);
        num_responses = num_responses.saturating_sub(1);
        if num_responses == 0 {
            pinger.stop_pinger();
            break;
        }
    }

    let results = measurements
        .into_iter()
        .map(|(addr, measurements)| {
            let mut sorted = measurements.iter().filter_map(|m| *m).collect::<Vec<_>>();
            sorted.sort();
            let median = sorted.get(sorted.len() / 2);
            (addr, (median.cloned(), measurements.clone()))
        })
        .collect();
    Ok(results)
}

const WG_KEY_LEN: usize = 32usize;
type WGKeyBytes = [u8; WG_KEY_LEN];
#[derive(Clone)]
struct WGPrivateKey(WGKeyBytes);
impl WGPrivateKey {
    fn new() -> Self {
        let mut key_material = Self::get_random_bytes();
        Self::curve25519_clamp_secret(&mut key_material);
        Self(key_material)
    }
    fn public(&self) -> WGPublicKey {
        self.into()
    }
    fn get_random_bytes() -> [u8; WG_KEY_LEN] {
        let mut bytes: WGKeyBytes = Default::default();
        // OsRng is good enough, `wg` also only reads from /dev/urandom
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    }
    fn curve25519_clamp_secret(secret: &mut WGKeyBytes) {
        // https://datatracker.ietf.org/doc/html/rfc7748#page-8
        // https://git.zx2c4.com/wireguard-tools/tree/src/curve25519.h#n18
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
    }
}
impl FromStr for WGPrivateKey {
    type Err = Box<dyn Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes: WGKeyBytes = Default::default();
        base64ct::Base64::decode(s, &mut bytes)?;

        // a small sanity check
        if !(bytes[0] & 7 == 0 && bytes[31] & 128 == 0 && bytes[31] & 64 == 64) {
            return Err("unexpected bit pattern in wg private key".into());
        }

        Ok(Self(bytes))
    }
}
impl Display for WGPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&base64ct::Base64::encode_string(&self.0))
    }
}
impl<'de> Deserialize<'de> for WGPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = WGPrivateKey;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a base64 encoded string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}
impl Serialize for WGPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}
impl Debug for WGPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}
#[derive(Clone)]
struct WGPublicKey(WGKeyBytes);
impl From<&WGPrivateKey> for WGPublicKey {
    fn from(private: &WGPrivateKey) -> Self {
        let secret = x25519_dalek::StaticSecret::from(private.0);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self(public.to_bytes())
    }
}
impl FromStr for WGPublicKey {
    type Err = Box<dyn Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes: WGKeyBytes = Default::default();
        base64ct::Base64::decode(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}
impl<'de> Deserialize<'de> for WGPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = WGPublicKey;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a base64 encoded string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}
impl Serialize for WGPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}
impl Display for WGPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&base64ct::Base64::encode_string(&self.0))
    }
}
impl Debug for WGPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

#[derive(Deserialize, Clone, Debug)]
struct WGAddedKeyResponse {
    status: String,
    server_key: WGPublicKey,
    server_port: u16,
    #[serde(rename = "server_ip")]
    server_public_ip: IpAddr,
    #[serde(rename = "server_vip")]
    server_vpn_ip: IpAddr,
    #[serde(rename = "peer_ip")]
    client_vpn_ip: IpAddr,
    #[serde(rename = "peer_pubkey")]
    client_key: WGPublicKey,
    dns_servers: Vec<IpAddr>,
}
struct WGAddedKey {
    server_name: String,
    server_key: WGPublicKey,
    server_port: u16,
    server_public_ip: IpAddr,
    server_vpn_ip: IpAddr,
    client_vpn_ip: IpAddr,
    client_key: WGPublicKey,
    dns_servers: Vec<IpAddr>,
}

fn add_wg_key(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
    token: Token,
    server: &Server,
    public_key: &WGPublicKey,
) -> Result<WGAddedKey, Box<dyn Error>> {
    let server = &server.name;
    let resp: WGAddedKeyResponse = http_agent
        .get(&format!("https://{server}:{PIA_SERVER_API_PORT}/addKey"))
        .query_pairs([
            ("pt", token.as_str()),
            ("pubkey", public_key.to_string().as_str()),
        ])
        .call()?
        .into_json()?;
    if resp.status != "OK" {
        debug!(log, "Failed to add WG pub key to server"; "server" => server, "resp" => format!("{:?}", resp));
        return Err("Error response from server".into());
    }
    debug!(log, "network: Added WG pub key to server"; "server" => server, "resp" => format!("{:?}", resp));
    Ok(WGAddedKey {
        server_name: server.to_owned(),
        server_key: resp.server_key,
        server_port: resp.server_port,
        server_public_ip: resp.server_public_ip,
        server_vpn_ip: resp.server_vpn_ip,
        client_vpn_ip: resp.client_vpn_ip,
        client_key: resp.client_key,
        dns_servers: resp.dns_servers,
    })
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
struct WGConf {
    interface: WGConfInterface,
    peer: WGConfPeer,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
struct WGConfInterface {
    address: IpAddr,
    private_key: WGPrivateKey,
    // #[serde(rename = "DNS")]
    // dns: Option<Vec<IpAddr>>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
struct WGConfPeer {
    public_key: WGPublicKey,
    // #[serde(rename = "AllowedIPs")]
    // allowed_ips: Vec<String>, // to lazy to write a cidr ser+de impl
    allowed_ips: String,
    endpoint: SocketAddr,
    hostname: Option<String>,
    persistent_keepalive: Option<u16>,
}
impl WGConf {
    fn from(server: WGAddedKey, private_key: WGPrivateKey) -> Self {
        Self {
            interface: WGConfInterface {
                address: server.client_vpn_ip,
                private_key,
                // dns: Some(server.dns_servers),
            },
            peer: WGConfPeer {
                public_key: server.server_key,
                // allowed_ips: vec!["0.0.0.0/0".to_owned()],
                allowed_ips: "0.0.0.0/0".to_owned(),
                endpoint: SocketAddr::new(server.server_public_ip, server.server_port),
                hostname: Some(server.server_name),
                persistent_keepalive: Some(25),
            },
        }
    }
    fn to_ini(&self) -> Result<String, serde_ini::ser::Error> {
        let ini = serde_ini::to_string(&self)?;

        // "mask" our hostname, since `wg setconf` errors out on unkown keys
        let ini = ini.replace("Hostname=", "#Hostname=");

        // strip CRs on non-windows platforms, aesthetic choice, functionally equivalent
        #[cfg(not(target_os = "windows"))]
        let ini = ini.replace('\u{000d}', "");

        Ok(ini)
    }
    fn from_ini(ini: String) -> Result<Self, serde_ini::de::Error> {
        // "unmask" hostname again
        let ini = ini.replace("#Hostname=", "Hostname=");
        
        serde_ini::from_str(&ini)
    }
    // fn disable_keepalive(&mut self) {
    //     self.peer.persistent_keepalive.take();
    // }
    fn disable_dns(&mut self) {
        //     self.interface.dns.take();
    }
    // fn restict_to_public_ips(&mut self) {
    //     self.peer.allowed_ips = vec![
    //         "0.0.0.0/5".to_owned(),
    //         "8.0.0.0/7".to_owned(),
    //         "11.0.0.0/8".to_owned(),
    //         "12.0.0.0/6".to_owned(),
    //         "16.0.0.0/4".to_owned(),
    //         "32.0.0.0/3".to_owned(),
    //         "64.0.0.0/2".to_owned(),
    //         "128.0.0.0/3".to_owned(),
    //         "160.0.0.0/5".to_owned(),
    //         "168.0.0.0/6".to_owned(),
    //         "172.0.0.0/12".to_owned(),
    //         "172.32.0.0/11".to_owned(),
    //         "172.64.0.0/10".to_owned(),
    //         "172.128.0.0/9".to_owned(),
    //         "173.0.0.0/8".to_owned(),
    //         "174.0.0.0/7".to_owned(),
    //         "176.0.0.0/4".to_owned(),
    //         "192.0.0.0/9".to_owned(),
    //         "192.128.0.0/11".to_owned(),
    //         "192.160.0.0/13".to_owned(),
    //         "192.169.0.0/16".to_owned(),
    //         "192.170.0.0/15".to_owned(),
    //         "192.172.0.0/14".to_owned(),
    //         "192.176.0.0/12".to_owned(),
    //         "192.192.0.0/10".to_owned(),
    //         "193.0.0.0/8".to_owned(),
    //         "194.0.0.0/7".to_owned(),
    //         "196.0.0.0/6".to_owned(),
    //         "200.0.0.0/5".to_owned(),
    //         "208.0.0.0/4".to_owned(),
    //     ];
    // }
}

#[derive(Deserialize, Clone, Debug)]
struct PublicIPCheck {
    ip: IpAddr,
    isp: String,
    #[serde(rename = "cc")]
    country: String,
}

fn get_public_ip(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
) -> Result<PublicIPCheck, Box<dyn Error>> {
    let resp: PublicIPCheck = http_agent
        .get("https://www.privateinternetaccess.com/site-api/get-location-info")
        .call()?
        .into_json()?;
    debug!(log, "network: got public IP"; "ip" => format!("{}", resp.ip), "isp" => resp.isp.to_owned());
    Ok(resp)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_public_key_creation() {
        let private_base64 = "QAM7WznFnTrfi/HFIxWnGkDhDfVPa2jGknQXjp1/6Ew="; // wg genkey
        let public_base64 = "xtL+3mUlWqagf7rG74sSZm0L+CcysyJXUwaKzPWFgh8="; // wg pubkey

        let private: WGPrivateKey = private_base64.parse().expect("didn't parse baked key");
        let public = private.public();

        assert_eq!(public_base64, public.to_string());
    }
}
