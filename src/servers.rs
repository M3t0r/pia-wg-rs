use std::{collections::HashMap, net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Server {
    pub ip: IpAddr,
    pub name: String,
    pub region_id: String,
    pub region_name: String,
    pub country: String,
    pub dns_server: String,
    pub port_forward: bool,
}

pub struct ServerList(pub Vec<Server>);
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
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Server) -> bool,
    {
        self.0.retain(f)
    }
    pub fn get_region(self, region: &str) -> Self {
        Self(
            self.0
                .into_iter()
                .filter(|s| s.region_name == region || s.region_id == region)
                .collect(),
        )
    }
    pub fn enrich(self, ping_results: &PingResults) -> PingedServerList {
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

pub struct PingedServerList(Vec<(Option<Duration>, Server)>);
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
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn top(&mut self, top: u8) {
        self.0.drain(..self.len().saturating_sub(top.into()));
    }
    pub fn best(&mut self) -> Option<Server> {
        self.0.last().map(|(_, s)| s).cloned()
    }
}

// structure: https://github.com/pia-foss/mobile-ios-library/blob/40c1afb5f143bd061e322093a6d11e798739c10c/Sources/PIALibrary/WebServices/Server.swift#L33
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerListResponse {
    pub groups: HashMap<String, serde_json::Value>,
    pub regions: Vec<Region>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Region {
    pub id: String,
    pub name: String,
    pub country: String,
    pub auto_region: bool,
    #[serde(rename = "dns")]
    pub dns_server: String,
    pub port_forward: bool,
    pub geo: bool,
    pub offline: bool,
    pub servers: RegionServers,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegionServers {
    pub wg: Option<Vec<WGServer>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WGServer {
    pub ip: IpAddr,
    #[serde(rename = "cn")]
    pub name: String,
}

pub type PingResults = HashMap<IpAddr, (Option<Duration>, Vec<Option<Duration>>)>;
