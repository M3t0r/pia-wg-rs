use std::{
    error::Error,
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::port_forward::Signature as PortForwardSignature;
use crate::wg::{WGAddedKey, WGPrivateKey, WGPublicKey};

const COMMENT_ESCAPED_FIELDS: [(&str, &str); 5] = [
    ("Hostname=", "#Hostname="),
    ("ForwardedPort=", "#ForwardedPort="),
    (
        "ForwardedPortExpirationDate=",
        "#ForwardedPortExpirationDate=",
    ),
    (
        "ForwardedPortActivationPayload=",
        "#ForwardedPortActivationPayload=",
    ),
    (
        "ForwardedPortActivationSignature=",
        "#ForwardedPortActivationSignature=",
    ),
];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct WGConf {
    pub interface: WGConfInterface,
    pub peer: WGConfPeer,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct WGConfInterface {
    pub address: IpAddr,
    pub private_key: WGPrivateKey,
    #[serde(
        rename = "DNS",
        with = "optional_csv_vec",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dns: Option<Vec<IpAddr>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct WGConfPeer {
    pub public_key: WGPublicKey,
    #[serde(rename = "AllowedIPs", with = "csv_vec")]
    pub allowed_ips: Vec<String>,
    pub endpoint: SocketAddr,
    pub hostname: Option<String>,
    #[serde(flatten, with = "port_forward_metadata", default)]
    pub port_forward: Option<PortForwardMetadata>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PortForwardMetadata {
    #[serde(rename = "ForwardedPort")]
    pub port: u16,
    #[serde(rename = "ForwardedPortExpirationDate")]
    pub expiration: String,
    #[serde(rename = "ForwardedPortActivationPayload")]
    pub payload: String,
    #[serde(rename = "ForwardedPortActivationSignature")]
    pub signature: String,
}

impl PortForwardMetadata {
    pub fn from_signature(signature: &PortForwardSignature) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            port: signature.payload.port,
            expiration: signature.payload.expires_at.format(&Rfc3339)?,
            payload: signature.payload_raw.clone(),
            signature: signature.signature.clone(),
        })
    }

    pub fn try_into_signature(self) -> Result<PortForwardSignature, Box<dyn Error>> {
        let Self {
            port,
            expiration,
            payload,
            signature,
        } = self;
        let signature = PortForwardSignature::try_from_parts(payload, signature)?;
        if signature.payload.port != port {
            return Err("Stored #ForwardedPort metadata does not match the payload".into());
        }
        let expiration = OffsetDateTime::parse(&expiration, &Rfc3339)?;
        if signature.payload.expires_at != expiration {
            return Err(
                "Stored #ForwardedPortExpirationDate metadata does not match the payload".into(),
            );
        }
        Ok(signature)
    }
}

impl WGConf {
    pub fn from(server: WGAddedKey, private_key: WGPrivateKey) -> Self {
        Self {
            interface: WGConfInterface {
                address: server.client_vpn_ip,
                private_key,
                dns: Some(server.dns_servers),
            },
            peer: WGConfPeer {
                public_key: server.server_key,
                allowed_ips: vec!["0.0.0.0/0".to_owned()],
                endpoint: SocketAddr::new(server.server_public_ip, server.server_port),
                hostname: Some(server.server_name),
                port_forward: None,
                persistent_keepalive: Some(25),
            },
        }
    }

    pub fn to_ini(&self) -> Result<String, serde_ini::ser::Error> {
        let mut ini = serde_ini::to_string(self)?;

        for (plain, escaped) in COMMENT_ESCAPED_FIELDS {
            ini = ini.replace(plain, escaped);
        }

        #[cfg(not(target_os = "windows"))]
        {
            ini = ini.replace('\u{000d}', "");
        }

        Ok(ini)
    }

    pub fn from_ini(ini: &str) -> Result<Self, serde_ini::de::Error> {
        let mut ini = ini.to_owned();
        for (plain, escaped) in COMMENT_ESCAPED_FIELDS {
            ini = ini.replace(escaped, plain);
        }
        serde_ini::from_str(&ini)
    }

    pub fn from_path<P>(path: P) -> Result<Self, Box<dyn Error>>
    where
        P: AsRef<Path>,
    {
        let conf = fs::read_to_string(path)?;
        Ok(Self::from_ini(&conf)?)
    }

    pub fn disable_dns(&mut self) {
        self.interface.dns.take();
    }

    pub fn restict_to_public_ips(&mut self) {
        self.peer.allowed_ips = vec![
            "0.0.0.0/5".to_owned(),
            "8.0.0.0/7".to_owned(),
            "11.0.0.0/8".to_owned(),
            "12.0.0.0/6".to_owned(),
            "16.0.0.0/4".to_owned(),
            "32.0.0.0/3".to_owned(),
            "64.0.0.0/2".to_owned(),
            "128.0.0.0/3".to_owned(),
            "160.0.0.0/5".to_owned(),
            "168.0.0.0/6".to_owned(),
            "172.0.0.0/12".to_owned(),
            "172.32.0.0/11".to_owned(),
            "172.64.0.0/10".to_owned(),
            "172.128.0.0/9".to_owned(),
            "173.0.0.0/8".to_owned(),
            "174.0.0.0/7".to_owned(),
            "176.0.0.0/4".to_owned(),
            "192.0.0.0/9".to_owned(),
            "192.128.0.0/11".to_owned(),
            "192.160.0.0/13".to_owned(),
            "192.169.0.0/16".to_owned(),
            "192.170.0.0/15".to_owned(),
            "192.172.0.0/14".to_owned(),
            "192.176.0.0/12".to_owned(),
            "192.192.0.0/10".to_owned(),
            "193.0.0.0/8".to_owned(),
            "194.0.0.0/7".to_owned(),
            "196.0.0.0/6".to_owned(),
            "200.0.0.0/5".to_owned(),
            "208.0.0.0/4".to_owned(),
        ];
    }

    pub fn port_forward_target(&self) -> Result<(&str, IpAddr), Box<dyn Error>> {
        let server_name = self
            .peer
            .hostname
            .as_deref()
            .ok_or("WireGuard config does not include #Hostname metadata")?;
        Ok((server_name, self.peer.endpoint.ip()))
    }

    pub fn port_forward_signature(&self) -> Result<PortForwardSignature, Box<dyn Error>> {
        let metadata = self
            .peer
            .port_forward
            .clone()
            .ok_or("WireGuard config does not include port-forward metadata")?;
        metadata.try_into_signature()
    }
}

mod optional_csv_vec {
    use super::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, T>(option: &Option<Vec<T>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToString,
    {
        match option {
            Some(vec) => {
                let csv = vec
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                serializer.serialize_str(&csv)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        s.map(|s| {
            s.split(',')
                .map(|item| item.trim().parse::<T>().map_err(serde::de::Error::custom))
                .collect()
        })
        .transpose()
    }
}

mod csv_vec {
    use super::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, T>(vec: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToString,
    {
        let csv = vec
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        serializer.serialize_str(&csv)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let s: String = String::deserialize(deserializer)?;
        s.split(',')
            .map(|item| item.trim().parse::<T>().map_err(serde::de::Error::custom))
            .collect()
    }
}

mod port_forward_metadata {
    use super::{Deserialize, Deserializer, PortForwardMetadata, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Fields {
        #[serde(
            rename = "ForwardedPort",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        port: Option<String>,
        #[serde(
            rename = "ForwardedPortExpirationDate",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        expiration: Option<String>,
        #[serde(
            rename = "ForwardedPortActivationPayload",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        payload: Option<String>,
        #[serde(
            rename = "ForwardedPortActivationSignature",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signature: Option<String>,
    }

    pub fn serialize<S>(
        metadata: &Option<PortForwardMetadata>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let fields = match metadata {
            Some(metadata) => Fields {
                port: Some(metadata.port.to_string()),
                expiration: Some(metadata.expiration.clone()),
                payload: Some(metadata.payload.clone()),
                signature: Some(metadata.signature.clone()),
            },
            None => Fields {
                port: None,
                expiration: None,
                payload: None,
                signature: None,
            },
        };
        fields.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<PortForwardMetadata>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = Fields::deserialize(deserializer)?;
        match (
            fields.port,
            fields.expiration,
            fields.payload,
            fields.signature,
        ) {
            (None, None, None, None) => Ok(None),
            (Some(port), Some(expiration), Some(payload), Some(signature)) => {
                let port = port
                    .parse()
                    .map_err(|err| serde::de::Error::custom(format!("invalid port: {err}")))?;
                Ok(Some(PortForwardMetadata {
                    port,
                    expiration,
                    payload,
                    signature,
                }))
            }
            _ => Err(serde::de::Error::custom(
                "WireGuard config includes incomplete port-forward metadata",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_wgconf_serialization_deserialization() {
        let wg_conf = create_test_wgconf();
        let serialized = wg_conf.to_ini().expect("Failed to serialize WGConf");
        let deserialized = WGConf::from_ini(&serialized).expect("Failed to deserialize WGConf");

        assert_eq!(
            wg_conf, deserialized,
            "Serialized and deserialized WGConf should be equal"
        );
    }

    #[test]
    fn test_wgconf_serialization_with_disabled_dns() {
        let mut wg_conf = create_test_wgconf();
        wg_conf.disable_dns();
        let serialized = wg_conf.to_ini().unwrap();
        assert!(!serialized.contains("DNS"));
        let deserialized = WGConf::from_ini(&serialized).unwrap();
        assert_eq!(wg_conf, deserialized);
    }

    #[test]
    fn test_wgconf_serialization_with_restricted_public_ips() {
        let mut wg_conf = create_test_wgconf();
        wg_conf.restict_to_public_ips();
        let serialized = wg_conf.to_ini().unwrap();
        assert!(serialized.contains("0.0.0.0/5,8.0.0.0/7,11.0.0.0/8"));
        let deserialized = WGConf::from_ini(&serialized).unwrap();
        assert_eq!(wg_conf, deserialized);
    }

    #[test]
    fn test_wgconf_serialization_with_port_forward_metadata() {
        let mut wg_conf = create_test_wgconf();
        let signature = PortForwardSignature::try_from_parts(
            "eyJwb3J0IjoxMjM0NSwiZXhwaXJlc19hdCI6IjIwMzgtMDEtMTlUMDM6MTQ6MDhaIn0=".to_owned(),
            "signature".to_owned(),
        )
        .unwrap();
        wg_conf.peer.port_forward = Some(PortForwardMetadata::from_signature(&signature).unwrap());

        let serialized = wg_conf.to_ini().unwrap();
        assert!(serialized.contains("#ForwardedPort=12345"));
        assert!(serialized.contains("#ForwardedPortExpirationDate=2038-01-19T03:14:08Z"));
        assert!(serialized.contains("#ForwardedPortActivationPayload="));
        assert!(serialized.contains("#ForwardedPortActivationSignature="));

        let deserialized = WGConf::from_ini(&serialized).unwrap();
        assert_eq!(deserialized.port_forward_signature().unwrap(), signature);
    }

    fn create_test_wgconf() -> WGConf {
        WGConf {
            interface: WGConfInterface {
                address: IpAddr::from_str("10.0.0.1").unwrap(),
                private_key: WGPrivateKey::new(),
                dns: Some(vec![
                    IpAddr::from_str("10.0.0.1").unwrap(),
                    IpAddr::from_str("10.0.0.2").unwrap(),
                ]),
            },
            peer: WGConfPeer {
                public_key: WGPublicKey::from(&WGPrivateKey::new()),
                allowed_ips: vec!["0.0.0.0/0".to_owned()],
                endpoint: SocketAddr::from_str("10.0.0.128:5336").unwrap(),
                hostname: Some("test-server".to_owned()),
                port_forward: None,
                persistent_keepalive: Some(25),
            },
        }
    }
}
