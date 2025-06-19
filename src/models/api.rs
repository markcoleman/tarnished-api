//! API response models for standard endpoints.

use paperclip::actix::Apiv2Schema;
use serde::{Deserialize, Serialize};

/// Response model for the health check endpoint
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct HealthResponse {
    pub status: String,
}

/// Response model for the version information endpoint
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct VersionResponse {
    pub version: String,
    pub commit: String,
    pub build_time: String,
}