use serde::Deserialize;

pub type Token = String;

#[derive(Deserialize)]
pub struct TokenResponse {
    pub token: Token,
}
