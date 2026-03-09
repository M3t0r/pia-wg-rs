use base64ct::Encoding;
use serde::{Deserialize, Deserializer};
use std::error::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Deserialize)]
pub struct SignatureResponse {
    pub status: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct BindResponse {
    pub status: BindStatus,
    pub message: BindMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum BindStatus {
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "ERROR")]
    Error,
}
impl BindStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindMessage {
    Added,
    Refreshed,
    Unknown(String),
}
impl BindMessage {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Added => "added",
            Self::Refreshed => "refreshed",
            Self::Unknown(message) => message.as_str(),
        }
    }
}
impl<'de> Deserialize<'de> for BindMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let message = String::deserialize(deserializer)?;
        Ok(match message.as_str() {
            "port scheduled for add" => Self::Added,
            "timer refreshed" => Self::Refreshed,
            _ => Self::Unknown(message),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PayloadResponse {
    port: u16,
    expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub port: u16,
    pub expires_at: OffsetDateTime,
}
impl Payload {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    // send back to the server
    pub payload_raw: String,
    // send back to the server
    pub signature: String,
    // for us to handle
    pub payload: Payload,
}
impl Signature {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.payload.is_expired(now)
    }

    pub fn try_from_parts(payload_raw: String, signature: String) -> Result<Self, Box<dyn Error>> {
        let decoded = base64ct::Base64::decode_vec(&payload_raw)?;
        let payload: PayloadResponse = serde_json::from_slice(&decoded)?;
        let payload = Payload {
            port: payload.port,
            expires_at: OffsetDateTime::parse(&payload.expires_at, &Rfc3339)?,
        };
        Ok(Self {
            payload_raw,
            payload,
            signature,
        })
    }
}

impl TryFrom<SignatureResponse> for Signature {
    type Error = Box<dyn Error>;

    fn try_from(response: SignatureResponse) -> Result<Self, Self::Error> {
        Self::try_from_parts(response.payload, response.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_payload() {
        let response = SignatureResponse {
            status: "OK".to_owned(),
            payload: "eyJwb3J0IjoxMjM0NSwiZXhwaXJlc19hdCI6IjIwMzgtMDEtMTlUMDM6MTQ6MDhaIn0="
                .to_owned(),
            signature: "signature".to_owned(),
        };
        let payload = Signature::try_from(response)
            .expect("signature should decode")
            .payload;
        assert_eq!(
            payload,
            Payload {
                port: 12345,
                expires_at: OffsetDateTime::parse("2038-01-19T03:14:08Z", &Rfc3339)
                    .expect("timestamp should parse"),
            }
        );
    }

    #[test]
    fn decode_bind_response() {
        let response: BindResponse =
            serde_json::from_str(r#"{"status":"OK","message":"timer refreshed"}"#)
                .expect("bind response should decode");
        assert_eq!(response.status, BindStatus::Ok);
        assert_eq!(response.message, BindMessage::Refreshed);
    }

    #[test]
    fn decode_bind_response_with_unknown_message() {
        let response: BindResponse =
            serde_json::from_str(r#"{"status":"OK","message":"something new"}"#)
                .expect("bind response should decode");
        assert_eq!(response.status, BindStatus::Ok);
        assert_eq!(
            response.message,
            BindMessage::Unknown("something new".to_owned())
        );
    }
}
