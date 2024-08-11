use std::{
    error::Error,
    fmt::{Debug, Display},
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use base64ct::Encoding;
use rand::RngCore;
use serde::{de::Visitor, Deserialize, Serialize};

const WG_KEY_LEN: usize = 32usize;
type WGKeyBytes = [u8; WG_KEY_LEN];
#[derive(Clone)]
pub struct WGPrivateKey(WGKeyBytes);
impl WGPrivateKey {
    pub fn new() -> Self {
        let mut key_material = Self::get_random_bytes();
        Self::curve25519_clamp_secret(&mut key_material);
        Self(key_material)
    }
    pub fn public(&self) -> WGPublicKey {
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
pub struct WGPublicKey(WGKeyBytes);
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
pub struct WGAddedKeyResponse {
    pub status: String,
    pub server_key: WGPublicKey,
    pub server_port: u16,
    #[serde(rename = "server_ip")]
    pub server_public_ip: IpAddr,
    #[serde(rename = "server_vip")]
    pub server_vpn_ip: IpAddr,
    #[serde(rename = "peer_ip")]
    pub client_vpn_ip: IpAddr,
    #[serde(rename = "peer_pubkey")]
    pub client_key: WGPublicKey,
    pub dns_servers: Vec<IpAddr>,
}
pub struct WGAddedKey {
    pub server_name: String,
    pub server_key: WGPublicKey,
    pub server_port: u16,
    pub server_public_ip: IpAddr,
    pub server_vpn_ip: IpAddr,
    pub client_vpn_ip: IpAddr,
    pub client_key: WGPublicKey,
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WGConf {
    pub interface: WGConfInterface,
    pub peer: WGConfPeer,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WGConfInterface {
    pub address: IpAddr,
    pub private_key: WGPrivateKey,
    // #[serde(rename = "DNS")]
    // pub dns: Option<Vec<IpAddr>>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WGConfPeer {
    pub public_key: WGPublicKey,
    // #[serde(rename = "AllowedIPs")]
    // pub allowed_ips: Vec<String>, // to lazy to write a cidr ser+de impl
    pub allowed_ips: String,
    pub endpoint: SocketAddr,
    pub hostname: Option<String>,
    pub persistent_keepalive: Option<u16>,
}
impl WGConf {
    pub fn from(server: WGAddedKey, private_key: WGPrivateKey) -> Self {
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
    pub fn to_ini(&self) -> Result<String, serde_ini::ser::Error> {
        let ini = serde_ini::to_string(&self)?;

        // "mask" our hostname, since `wg setconf` errors out on unkown keys
        let ini = ini.replace("Hostname=", "#Hostname=");

        // strip CRs on non-windows platforms, aesthetic choice, functionally equivalent
        #[cfg(not(target_os = "windows"))]
        let ini = ini.replace('\u{000d}', "");

        Ok(ini)
    }
    pub fn from_ini(ini: String) -> Result<Self, serde_ini::de::Error> {
        // "unmask" hostname again
        let ini = ini.replace("#Hostname=", "Hostname=");

        serde_ini::from_str(&ini)
    }
    // pub fn disable_keepalive(&mut self) {
    //     self.peer.persistent_keepalive.take();
    // }
    pub fn disable_dns(&mut self) {
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
