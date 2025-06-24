//! API response models for standard endpoints.

use paperclip::actix::Apiv2Schema;
use serde::{Deserialize, Serialize};

/// Response model for the health check endpoint
#[derive(Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct HealthResponse {
    pub status: String,
}

/// Response model for the version information endpoint
#[derive(Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct VersionResponse {
    pub version: String,
    pub commit: String,
    pub build_time: String,
}

/// Request query parameters for the weather endpoint
#[derive(Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct WeatherQuery {
    /// ZIP code (e.g., "90210")
    pub zip: Option<String>,
    /// Latitude coordinate 
    pub lat: Option<f64>,
    /// Longitude coordinate
    pub lon: Option<f64>,
}

/// Response model for the weather endpoint
#[derive(Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct WeatherResponse {
    /// Location name (e.g., "Los Angeles, CA")
    pub location: String,
    /// Weather condition description (e.g., "Clear")
    pub weather: String,
    /// Weather emoji representation (e.g., "☀️")
    pub emoji: String,
}