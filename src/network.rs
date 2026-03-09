use crate::check::PublicIPCheck;
use crate::port_forward::{
    BindResponse as PortForwardBindResponse, BindStatus as PortForwardBindStatus,
    Signature as PortForwardSignature, SignatureResponse as PortForwardSignatureResponse,
};
use crate::servers::Server;
use crate::wg::WGAddedKey;
use crate::wg::WGAddedKeyResponse;
use crate::wg::WGPublicKey;
use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use fastping_rs::Pinger;
use slog::{debug, info};

use crate::servers::{PingResults, ServerList, ServerListResponse};
use crate::token::{Response as TokenResponse, Token};

pub const PIA_SERVER_API_PORT: u16 = 1337u16;
pub const PIA_PORT_FORWARD_API_PORT: u16 = 19999u16;

pub fn get_token(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
    username: &str,
    password: &str,
) -> Result<Token, Box<dyn Error>> {
    let endpoint = "https://www.privateinternetaccess.com/api/client/v2/token";
    debug!(log, "logging in"; "user" => username.to_string());
    let resp: TokenResponse = http_agent
        .post(endpoint)
        .send_form([("username", username), ("password", password)])?
        .body_mut()
        .read_json()?;
    Ok(resp.token)
}

pub fn get_server_list(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
) -> Result<ServerList, Box<dyn Error>> {
    let endpoint = "https://serverlist.piaservers.net/vpninfo/servers/v6";
    let resp = http_agent
        .get(endpoint)
        .call()?
        .body_mut()
        .read_to_string()?;

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

pub fn ping_servers(
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

    let (pinger, result_stream) = Pinger::new(Some(u64::try_from(timeout.as_millis())?), None)?;
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
            (addr, (median.copied(), measurements.clone()))
        })
        .collect();
    Ok(results)
}

pub fn add_wg_key(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
    token: &Token,
    server: &Server,
    public_key: &WGPublicKey,
) -> Result<WGAddedKey, Box<dyn Error>> {
    let server = &server.name;
    let public_key = public_key.to_string();
    let resp: WGAddedKeyResponse = http_agent
        .get(&format!("https://{server}:{PIA_SERVER_API_PORT}/addKey"))
        .query_pairs([("pt", token.as_str()), ("pubkey", public_key.as_str())])
        .call()?
        .body_mut()
        .read_json()?;
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

pub fn get_public_ip(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
) -> Result<PublicIPCheck, Box<dyn Error>> {
    let resp: PublicIPCheck = http_agent
        .get("https://www.privateinternetaccess.com/site-api/get-location-info")
        .call()?
        .body_mut()
        .read_json()?;
    debug!(log, "network: got public IP"; "ip" => format!("{}", resp.ip), "isp" => resp.isp.clone());
    Ok(resp)
}

pub fn get_port_forward_signature(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
    token: &Token,
    server_name: &str,
) -> Result<PortForwardSignature, Box<dyn Error>> {
    let resp: PortForwardSignatureResponse = http_agent
        .get(&format!(
            "https://{server_name}:{PIA_PORT_FORWARD_API_PORT}/getSignature"
        ))
        .query("token", token.as_str())
        .call()?
        .body_mut()
        .read_json()?;
    if resp.status != "OK" {
        debug!(log, "Failed to get port-forward signature"; "server" => server_name, "resp" => format!("{:?}", resp));
        return Err("Error response from port-forward getSignature".into());
    }
    let signature = PortForwardSignature::try_from(resp)?;
    debug!(
        log,
        "network: got port-forward signature";
        "server" => server_name,
        "port" => signature.payload.port,
        "expires_at" => signature.payload.expires_at.to_string()
    );
    Ok(signature)
}

pub fn bind_port_forward_port(
    log: &slog::Logger,
    http_agent: &ureq::Agent,
    server_name: &str,
    signature: &PortForwardSignature,
) -> Result<PortForwardBindResponse, Box<dyn Error>> {
    let resp: PortForwardBindResponse = http_agent
        .get(&format!(
            "https://{server_name}:{PIA_PORT_FORWARD_API_PORT}/bindPort"
        ))
        .query("payload", &signature.payload_raw)
        .query("signature", &signature.signature)
        .call()?
        .body_mut()
        .read_json()?;
    if resp.status != PortForwardBindStatus::Ok {
        debug!(log, "Failed to bind port-forward port"; "server" => server_name, "resp" => format!("{:?}", resp));
        return Err("Error response from port-forward bindPort".into());
    }
    debug!(
        log,
        "network: bound port-forward port";
        "server" => server_name,
        "port" => signature.payload.port,
        "message" => resp.message.as_str()
    );
    Ok(resp)
}
