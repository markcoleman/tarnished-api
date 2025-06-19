//! Security headers configuration.

use std::env;

/// Configuration for security headers middleware
#[derive(Clone)]
pub struct SecurityHeadersConfig {
    pub csp_enabled: bool,
    pub csp_directives: String,
    pub hsts_enabled: bool,
    pub hsts_max_age: u32,
    pub frame_options: String,
    pub content_type_options: bool,
    pub xss_protection: bool,
    pub referrer_policy: String,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            csp_enabled: true,
            csp_directives: "default-src 'none'; frame-ancestors 'none'".to_string(),
            hsts_enabled: true,
            hsts_max_age: 31536000, // 1 year
            frame_options: "DENY".to_string(),
            content_type_options: true,
            xss_protection: true,
            referrer_policy: "no-referrer".to_string(),
        }
    }
}

impl SecurityHeadersConfig {
    /// Load configuration from environment variables, falling back to defaults
    pub fn from_env() -> Self {
        let csp_enabled = env::var("SECURITY_CSP_ENABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);

        let csp_directives = env::var("CSP_DIRECTIVES")
            .unwrap_or_else(|_| "default-src 'none'; frame-ancestors 'none'".to_string());

        let hsts_enabled = env::var("HSTS_ENABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);

        let hsts_max_age = env::var("HSTS_MAX_AGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(31536000);

        let frame_options = env::var("X_FRAME_OPTIONS")
            .unwrap_or_else(|_| "DENY".to_string());

        let content_type_options = env::var("X_CONTENT_TYPE_OPTIONS")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);

        let xss_protection = env::var("X_XSS_PROTECTION")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);

        let referrer_policy = env::var("REFERRER_POLICY")
            .unwrap_or_else(|_| "no-referrer".to_string());

        Self {
            csp_enabled,
            csp_directives,
            hsts_enabled,
            hsts_max_age,
            frame_options,
            content_type_options,
            xss_protection,
            referrer_policy,
        }
    }
}