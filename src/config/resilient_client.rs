//! Configuration for resilient HTTP client
//!
//! Provides environment-based configuration for the resilient HTTP client
//! with sensible defaults for production use.

use std::env;
use crate::services::resilient_client::{ResilientClientConfig, RetryConfig, CircuitBreakerConfig};

impl ResilientClientConfig {
    /// Load configuration from environment variables, falling back to defaults
    pub fn from_env() -> Self {
        let read_timeout_seconds = env::var("RESILIENT_CLIENT_READ_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let write_timeout_seconds = env::var("RESILIENT_CLIENT_WRITE_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let connect_timeout_seconds = env::var("RESILIENT_CLIENT_CONNECT_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        let enable_detailed_logging = env::var("RESILIENT_CLIENT_DETAILED_LOGGING")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(true);

        Self {
            read_timeout_seconds,
            write_timeout_seconds,
            connect_timeout_seconds,
            retry: RetryConfig::from_env(),
            circuit_breaker: CircuitBreakerConfig::from_env(),
            enable_detailed_logging,
        }
    }
}

impl RetryConfig {
    /// Load retry configuration from environment variables
    pub fn from_env() -> Self {
        let max_attempts = env::var("RESILIENT_CLIENT_RETRY_MAX_ATTEMPTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        let initial_delay_ms = env::var("RESILIENT_CLIENT_RETRY_INITIAL_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let max_delay_ms = env::var("RESILIENT_CLIENT_RETRY_MAX_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000);

        let jitter_factor = env::var("RESILIENT_CLIENT_RETRY_JITTER_FACTOR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.1);

        // Parse retry status codes from comma-separated values
        let retry_on_status = env::var("RESILIENT_CLIENT_RETRY_ON_STATUS")
            .ok()
            .map(|v| {
                v.split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect()
            })
            .unwrap_or_else(|| vec![408, 429, 500, 502, 503, 504]);

        Self {
            max_attempts,
            initial_delay_ms,
            max_delay_ms,
            jitter_factor,
            retry_on_status,
        }
    }
}

impl CircuitBreakerConfig {
    /// Load circuit breaker configuration from environment variables
    pub fn from_env() -> Self {
        let failure_threshold = env::var("RESILIENT_CLIENT_CB_FAILURE_THRESHOLD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let success_threshold = env::var("RESILIENT_CLIENT_CB_SUCCESS_THRESHOLD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        let timeout_seconds = env::var("RESILIENT_CLIENT_CB_TIMEOUT_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Self {
            failure_threshold,
            success_threshold,
            timeout_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Mutex to synchronize tests that modify environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_resilient_client_config_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        // Clear any existing environment variables to ensure clean test
        unsafe {
            env::remove_var("RESILIENT_CLIENT_READ_TIMEOUT");
            env::remove_var("RESILIENT_CLIENT_WRITE_TIMEOUT");
            env::remove_var("RESILIENT_CLIENT_CONNECT_TIMEOUT");
            env::remove_var("RESILIENT_CLIENT_DETAILED_LOGGING");
            env::remove_var("RESILIENT_CLIENT_RETRY_MAX_ATTEMPTS");
            env::remove_var("RESILIENT_CLIENT_RETRY_INITIAL_DELAY_MS");
            env::remove_var("RESILIENT_CLIENT_RETRY_MAX_DELAY_MS");
            env::remove_var("RESILIENT_CLIENT_RETRY_JITTER_FACTOR");
            env::remove_var("RESILIENT_CLIENT_RETRY_ON_STATUS");
            env::remove_var("RESILIENT_CLIENT_CB_FAILURE_THRESHOLD");
            env::remove_var("RESILIENT_CLIENT_CB_SUCCESS_THRESHOLD");
            env::remove_var("RESILIENT_CLIENT_CB_TIMEOUT_SECONDS");
        }
        
        let config = ResilientClientConfig::from_env();
        assert_eq!(config.read_timeout_seconds, 1);
        assert_eq!(config.write_timeout_seconds, 5);
        assert_eq!(config.connect_timeout_seconds, 3);
        assert!(config.enable_detailed_logging);
        assert_eq!(config.retry.max_attempts, 3);
        assert_eq!(config.circuit_breaker.failure_threshold, 5);
    }

    #[test]
    fn test_resilient_client_config_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        unsafe {
            env::set_var("RESILIENT_CLIENT_READ_TIMEOUT", "2");
            env::set_var("RESILIENT_CLIENT_WRITE_TIMEOUT", "10");
            env::set_var("RESILIENT_CLIENT_CONNECT_TIMEOUT", "5");
            env::set_var("RESILIENT_CLIENT_DETAILED_LOGGING", "false");
            env::set_var("RESILIENT_CLIENT_RETRY_MAX_ATTEMPTS", "5");
            env::set_var("RESILIENT_CLIENT_CB_FAILURE_THRESHOLD", "10");
        }
        
        let config = ResilientClientConfig::from_env();
        assert_eq!(config.read_timeout_seconds, 2);
        assert_eq!(config.write_timeout_seconds, 10);
        assert_eq!(config.connect_timeout_seconds, 5);
        assert!(!config.enable_detailed_logging);
        assert_eq!(config.retry.max_attempts, 5);
        assert_eq!(config.circuit_breaker.failure_threshold, 10);
        
        // Clean up
        unsafe {
            env::remove_var("RESILIENT_CLIENT_READ_TIMEOUT");
            env::remove_var("RESILIENT_CLIENT_WRITE_TIMEOUT");
            env::remove_var("RESILIENT_CLIENT_CONNECT_TIMEOUT");
            env::remove_var("RESILIENT_CLIENT_DETAILED_LOGGING");
            env::remove_var("RESILIENT_CLIENT_RETRY_MAX_ATTEMPTS");
            env::remove_var("RESILIENT_CLIENT_CB_FAILURE_THRESHOLD");
        }
    }

    #[test]
    fn test_retry_status_codes_parsing() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        unsafe {
            env::set_var("RESILIENT_CLIENT_RETRY_ON_STATUS", "500,502,503");
        }
        
        let config = RetryConfig::from_env();
        assert_eq!(config.retry_on_status, vec![500, 502, 503]);
        
        unsafe {
            env::remove_var("RESILIENT_CLIENT_RETRY_ON_STATUS");
        }
    }
}