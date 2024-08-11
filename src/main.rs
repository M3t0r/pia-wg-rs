use std::{
    collections::HashMap,
    error::Error,
    fmt::Display,
    fs,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use slog::{debug, error, info, o, Drain};

// all network related code is there, and only there
mod network;
use self::network::{
    add_wg_key, get_public_ip, get_server_list, get_token, ping_servers, PIA_SERVER_API_PORT,
};

mod servers;
mod token;
use self::token::Token;
mod wg;
use self::wg::{WGConf, WGPrivateKey};
mod check;

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
    Check { conf: PathBuf },
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
                dbg!(dns);
                conf.disable_dns()
            }

            let ini = conf.to_ini()?;
            println!("{ini}");
        }
        Commands::Check { conf } => {
            let conf = fs::read_to_string(conf)?;
            let conf = WGConf::from_ini(conf)?;
            let public = get_public_ip(&log, &http_agent)?;
            println!(
                "IP: {}, country: {}, ISP: {}",
                public.ip, public.country, public.isp
            );
            if public.ip != conf.peer.endpoint.ip() {
                error!(
                    log,
                    "Not connected to PIA. Request went through the open internet"
                );
                return Err("Not connected to PIA. Request went through the open internet".into());
            } else {
                info!(
                    log,
                    "IP matches our VPN server, request got routed through VPN"
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli_help_in_readme() {
        let mut cmd = Cli::command();
        let help = cmd.render_help().to_string();
        let expected_help = include_str!("../README.md")
            .split("```")
            .nth(1)
            .unwrap()
            .trim();
        assert_eq!(help.trim(), expected_help);
    }

    #[test]
    fn verify_rust_version_consistency() {
        let cargo_toml = include_str!("../Cargo.toml");
        let readme = include_str!("../README.md");
        let ci_yml = include_str!("../.github/workflows/ci.yml");

        let cargo_version = cargo_toml
            .lines()
            .find(|line| line.starts_with("rust-version"))
            .and_then(|line| line.split('"').nth(1))
            .expect("Rust version not found in Cargo.toml");

        let readme_version = readme
            .lines()
            .find(|line| line.contains("rust-") && line.contains("%2B"))
            .and_then(|line| line.split('-').nth(1))
            .and_then(|v| v.split('%').next())
            .expect("Rust version not found in README.md");

        let ci_version = ci_yml
            .lines()
            .find(|line| line.contains("'1."))
            .and_then(|line| line.split('\'').nth(1))
            .expect("Rust version not found in ci.yml");

        assert_eq!(cargo_version, readme_version, "Cargo.toml and README.md versions don't match");
        assert_eq!(cargo_version, ci_version, "Cargo.toml and ci.yml versions don't match");
    }
}
