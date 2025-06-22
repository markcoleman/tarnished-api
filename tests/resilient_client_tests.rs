//! Integration tests for the resilient HTTP client
//!
//! Tests the full resilience functionality including retries, timeouts,
//! circuit breakers, and metrics collection.

use tarnished_api::{ResilientClient, ResilientClientConfig, ResilientClientMetrics, ResilientClientError};
use prometheus::Registry;
use std::time::Duration;

#[tokio::test]
async fn test_resilient_client_creation() {
    let config = ResilientClientConfig::default();
    let registry = Registry::new();
    let metrics = ResilientClientMetrics::new(&registry).expect("Failed to create metrics");
    
    let client = ResilientClient::new(config, Some(metrics));
    assert!(client.is_ok(), "Failed to create resilient client");
}

#[tokio::test]
async fn test_resilient_client_config_from_env() {
    // Test that configuration can be loaded from environment
    unsafe {
        std::env::set_var("RESILIENT_CLIENT_READ_TIMEOUT", "2");
        std::env::set_var("RESILIENT_CLIENT_WRITE_TIMEOUT", "10");
        std::env::set_var("RESILIENT_CLIENT_RETRY_MAX_ATTEMPTS", "5");
    }
    
    let config = ResilientClientConfig::from_env();
    assert_eq!(config.read_timeout_seconds, 2);
    assert_eq!(config.write_timeout_seconds, 10);
    assert_eq!(config.retry.max_attempts, 5);
    
    // Clean up
    unsafe {
        std::env::remove_var("RESILIENT_CLIENT_READ_TIMEOUT");
        std::env::remove_var("RESILIENT_CLIENT_WRITE_TIMEOUT");
        std::env::remove_var("RESILIENT_CLIENT_RETRY_MAX_ATTEMPTS");
    }
}

#[tokio::test]
async fn test_circuit_breaker_functionality() {
    use tarnished_api::services::resilient_client::{SimpleCircuitBreaker, CircuitBreakerConfig, CircuitBreakerState};
    
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 2,
        timeout_seconds: 1,
    };
    
    let mut cb = SimpleCircuitBreaker::new(config);
    
    // Initially closed
    assert_eq!(cb.state(), &CircuitBreakerState::Closed);
    assert!(cb.call_allowed());
    
    // Trigger failures to open circuit
    for _ in 0..3 {
        cb.on_failure();
    }
    
    assert_eq!(cb.state(), &CircuitBreakerState::Open);
    assert!(!cb.call_allowed());
    
    // Wait for timeout to allow half-open
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Should now allow calls in half-open state
    assert!(cb.call_allowed());
    assert_eq!(cb.state(), &CircuitBreakerState::HalfOpen);
    
    // Success should move towards closed
    cb.on_success();
    cb.on_success();
    
    assert_eq!(cb.state(), &CircuitBreakerState::Closed);
}

#[tokio::test]
async fn test_metrics_creation_and_client_integration() {
    let registry = Registry::new();
    let metrics_result = ResilientClientMetrics::new(&registry);
    assert!(metrics_result.is_ok(), "Should be able to create metrics");
    
    let config = ResilientClientConfig::default();
    let client_result = ResilientClient::new(config, Some(metrics_result.unwrap()));
    assert!(client_result.is_ok(), "Should be able to create client with metrics");
}

#[tokio::test]
async fn test_error_user_messages() {
    let errors = vec![
        ResilientClientError::Timeout,
        ResilientClientError::CircuitBreakerOpen,
        ResilientClientError::RetryableStatus(503),
        ResilientClientError::Fallback("Service unavailable".to_string()),
        ResilientClientError::SerializationError("Invalid JSON".to_string()),
    ];
    
    for error in errors {
        let message = error.user_message();
        assert!(!message.is_empty(), "Error message should not be empty");
        assert!(message.len() > 10, "Error message should be descriptive");
    }
}

#[tokio::test]
async fn test_configuration_validation() {
    let config = ResilientClientConfig::default();
    
    // Test that timeouts are reasonable
    assert!(config.read_timeout_seconds > 0);
    assert!(config.write_timeout_seconds > 0);
    assert!(config.connect_timeout_seconds > 0);
    
    // Test retry configuration
    assert!(config.retry.max_attempts > 0);
    assert!(config.retry.initial_delay_ms > 0);
    assert!(config.retry.max_delay_ms >= config.retry.initial_delay_ms);
    assert!(config.retry.jitter_factor >= 0.0 && config.retry.jitter_factor <= 1.0);
    assert!(!config.retry.retry_on_status.is_empty());
    
    // Test circuit breaker configuration
    assert!(config.circuit_breaker.failure_threshold > 0);
    assert!(config.circuit_breaker.success_threshold > 0);
    assert!(config.circuit_breaker.timeout_seconds > 0);
}

#[tokio::test]
async fn test_resilient_client_invalid_url() {
    let config = ResilientClientConfig::default();
    let mut client = ResilientClient::new(config, None).expect("Failed to create client");
    
    // Test with invalid URL - this would fail immediately, not through retries
    let result = client.get("not-a-valid-url").await;
    assert!(result.is_err(), "Invalid URL should result in error");
}

// Note: More comprehensive integration tests would require setting up mock HTTP servers
// to test actual retry behavior, timeouts, and circuit breaker triggering.
// For a production system, consider using libraries like `wiremock` or `mockito`.

#[test]
fn test_retry_status_defaults() {
    let config = ResilientClientConfig::default();
    let retry_statuses = &config.retry.retry_on_status;
    
    // Should include common retry statuses
    assert!(retry_statuses.contains(&500));
    assert!(retry_statuses.contains(&503));
    assert!(retry_statuses.contains(&429));
    
    // Should not include success statuses
    assert!(!retry_statuses.contains(&200));
    assert!(!retry_statuses.contains(&201));
}