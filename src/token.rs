use serde::Deserialize;

pub type Token = String;

#[derive(Deserialize)]
pub struct Response {
    pub token: Token,
}
