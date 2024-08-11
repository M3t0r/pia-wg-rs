use std::net::IpAddr;

use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct PublicIPCheck {
    pub ip: IpAddr,
    pub isp: String,
    #[serde(rename = "cc")]
    pub country: String,
}
