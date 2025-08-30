//! HMAC signature configuration.

use std::env;

/// Configuration for HMAC signature validation
#[derive(Clone)]
pub struct HmacConfig {
    pub secret: String,
    pub timestamp_tolerance_seconds: u64,
    pub require_signature: bool,
}

impl Default for HmacConfig {
    fn default() -> Self {
        Self {
            secret: "default-secret-key".to_string(),
            timestamp_tolerance_seconds: 300, // 5 minutes
            require_signature: false,
        }
    }
}

impl HmacConfig {
    /// Load configuration from environment variables, falling back to defaults
    pub fn from_env() -> Self {
        let secret = env::var("HMAC_SECRET").unwrap_or_else(|_| "default-secret-key".to_string());

        let timestamp_tolerance_seconds = env::var("HMAC_TIMESTAMP_TOLERANCE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);

        let require_signature = env::var("HMAC_REQUIRE_SIGNATURE")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            secret,
            timestamp_tolerance_seconds,
            require_signature,
        }
    }
}
