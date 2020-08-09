use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct DoneMessage {
    pub auth_token: String,
    pub done_name: String,
    pub host_name: String,
}

#[derive(Deserialize, Serialize)]
pub struct DoneResponse {
    pub notification_sent: bool,
    pub remote_response: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct ValidateTokenRequest {
    pub auth_token: String,
}

#[derive(Deserialize, Serialize)]
pub struct ValidateTokenResponse {
    pub is_valid: bool,
}

pub const ROOT_URL: &str = "https://igmas.io";
