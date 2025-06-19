//! Authentication-related data models.

use paperclip::actix::Apiv2Schema;
use serde::{Deserialize, Serialize};

/// Request model for user login
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Response model for login attempts
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct LoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub message: String,
}

/// Request model for token validation
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct TokenValidationRequest {
    pub token: String,
}

/// Response model for token validation
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct TokenValidationResponse {
    pub valid: bool,
    pub message: String,
}