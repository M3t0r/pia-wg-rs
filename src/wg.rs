use std::{
    error::Error,
    fmt::{Debug, Display},
    net::IpAddr,
    str::FromStr,
};

use base64ct::Encoding;
use rand::TryRng;
use serde::{Deserialize, Serialize, de::Visitor};

const WG_KEY_LEN: usize = 32usize;
type WGKeyBytes = [u8; WG_KEY_LEN];
#[derive(Clone, PartialEq)]
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
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .expect("Could not generate randomness for WG key");
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
#[derive(Clone, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wgprivatekey_creation_and_conversion() {
        let private_key = WGPrivateKey::new();
        let public_key = private_key.public();
        assert_ne!(private_key.to_string(), public_key.to_string());
    }

    #[test]
    fn test_wgprivatekey_serialization() {
        let private_key = WGPrivateKey::new();
        let serialized = serde_json::to_string(&private_key).unwrap();
        let deserialized: WGPrivateKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(private_key, deserialized);
    }
}
