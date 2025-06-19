//! Metrics configuration.

use std::env;

/// Configuration for application metrics collection
#[derive(Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl MetricsConfig {
    /// Load configuration from environment variables, falling back to defaults
    pub fn from_env() -> Self {
        let enabled = env::var("METRICS_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        Self { enabled }
    }
}