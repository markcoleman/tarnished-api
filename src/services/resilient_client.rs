//! Resilient HTTP client service with retries, timeouts, and circuit breakers.
//!
//! This module provides a configurable HTTP client that implements:
//! - Exponential backoff with jitter retry strategies
//! - Configurable timeouts for read and write operations
//! - Circuit breaker pattern to prevent cascading failures
//! - Comprehensive logging and metrics collection
//! - Integration with New Relic monitoring

use std::time::Duration;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use prometheus::{CounterVec, HistogramVec, GaugeVec, Opts, Registry};
use reqwest::Client;
use tokio_retry::{strategy::ExponentialBackoff, Retry};
use tracing::{error, warn, info};
use chrono::{Utc, DateTime};

/// Configuration for resilient HTTP client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilientClientConfig {
    /// Timeout for read operations (in seconds)
    pub read_timeout_seconds: u64,
    
    /// Timeout for write operations (in seconds) 
    pub write_timeout_seconds: u64,
    
    /// Connection timeout (in seconds)
    pub connect_timeout_seconds: u64,
    
    /// Retry configuration
    pub retry: RetryConfig,
    
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
    
    /// Enable detailed logging
    pub enable_detailed_logging: bool,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: usize,
    
    /// Initial retry delay in milliseconds
    pub initial_delay_ms: u64,
    
    /// Maximum retry delay in milliseconds
    pub max_delay_ms: u64,
    
    /// Jitter factor (0.0 to 1.0)
    pub jitter_factor: f64,
    
    /// Retry on these HTTP status codes
    pub retry_on_status: Vec<u16>,
}

/// Simple circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open the circuit
    pub failure_threshold: usize,
    
    /// Success threshold to close the circuit
    pub success_threshold: usize,
    
    /// Timeout before attempting to close circuit (in seconds)
    pub timeout_seconds: u64,
}

/// Circuit breaker state
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Simple circuit breaker implementation
#[derive(Debug)]
pub struct SimpleCircuitBreaker {
    state: CircuitBreakerState,
    failure_count: usize,
    success_count: usize,
    config: CircuitBreakerConfig,
    last_failure_time: Option<std::time::Instant>,
}

impl SimpleCircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            success_count: 0,
            config,
            last_failure_time: None,
        }
    }

    pub fn call_allowed(&mut self) -> bool {
        match self.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed() >= Duration::from_secs(self.config.timeout_seconds) {
                        self.state = CircuitBreakerState::HalfOpen;
                        self.success_count = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }

    pub fn on_success(&mut self) {
        self.failure_count = 0;
        
        if self.state == CircuitBreakerState::HalfOpen {
            self.success_count += 1;
            if self.success_count >= self.config.success_threshold {
                self.state = CircuitBreakerState::Closed;
            }
        }
    }

    pub fn on_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(std::time::Instant::now());
        
        if self.failure_count >= self.config.failure_threshold {
            self.state = CircuitBreakerState::Open;
        }
    }

    pub fn state(&self) -> &CircuitBreakerState {
        &self.state
    }
}

impl Default for ResilientClientConfig {
    fn default() -> Self {
        Self {
            read_timeout_seconds: 1,
            write_timeout_seconds: 5,
            connect_timeout_seconds: 3,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            enable_detailed_logging: true,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            jitter_factor: 0.1,
            retry_on_status: vec![408, 429, 500, 502, 503, 504],
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout_seconds: 60,
        }
    }
}

/// Metrics for resilient HTTP client operations
#[derive(Clone)]
pub struct ResilientClientMetrics {
    /// HTTP requests by destination, method, and outcome
    pub http_requests_total: CounterVec,
    
    /// HTTP request duration by destination and method
    pub http_request_duration_seconds: HistogramVec,
    
    /// Retry attempts by destination and reason
    pub retry_attempts_total: CounterVec,
    
    /// Circuit breaker state by destination
    pub circuit_breaker_state: GaugeVec,
    
    /// Timeout occurrences by destination and type
    pub timeouts_total: CounterVec,
}

impl ResilientClientMetrics {
    /// Create new metrics collector
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let http_requests_total = CounterVec::new(
            Opts::new("resilient_http_requests_total", "Total resilient HTTP requests by destination, method, and outcome"),
            &["destination", "method", "outcome"]
        )?;
        
        let http_request_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "resilient_http_request_duration_seconds",
                "Duration of resilient HTTP requests"
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["destination", "method"]
        )?;
        
        let retry_attempts_total = CounterVec::new(
            Opts::new("resilient_http_retry_attempts_total", "Total retry attempts by destination and reason"),
            &["destination", "reason"]
        )?;
        
        let circuit_breaker_state = GaugeVec::new(
            Opts::new("resilient_http_circuit_breaker_state", "Circuit breaker state (0=closed, 1=open, 2=half-open)"),
            &["destination"]
        )?;
        
        let timeouts_total = CounterVec::new(
            Opts::new("resilient_http_timeouts_total", "Total timeouts by destination and type"),
            &["destination", "timeout_type"]
        )?;

        // Register all metrics
        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;
        registry.register(Box::new(retry_attempts_total.clone()))?;
        registry.register(Box::new(circuit_breaker_state.clone()))?;
        registry.register(Box::new(timeouts_total.clone()))?;

        Ok(Self {
            http_requests_total,
            http_request_duration_seconds,
            retry_attempts_total,
            circuit_breaker_state,
            timeouts_total,
        })
    }
}

/// Request context for logging and metrics
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub destination: String,
    pub method: String,
    pub url: String,
    pub request_id: Option<String>,
    pub start_time: DateTime<Utc>,
}

/// Resilient HTTP client with retries, timeouts, and circuit breakers
pub struct ResilientClient {
    client: Client,
    config: ResilientClientConfig,
    metrics: Option<ResilientClientMetrics>,
    circuit_breakers: HashMap<String, SimpleCircuitBreaker>,
}

impl ResilientClient {
    /// Create a new resilient HTTP client
    pub fn new(config: ResilientClientConfig, metrics: Option<ResilientClientMetrics>) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(std::cmp::max(config.read_timeout_seconds, config.write_timeout_seconds)))
            .connect_timeout(Duration::from_secs(config.connect_timeout_seconds))
            .build()?;

        Ok(Self {
            client,
            config,
            metrics,
            circuit_breakers: HashMap::new(),
        })
    }

    /// Execute an HTTP GET request with resilience patterns
    pub async fn get(&mut self, url: &str) -> Result<reqwest::Response, ResilientClientError> {
        let context = RequestContext {
            destination: self.extract_destination(url),
            method: "GET".to_string(),
            url: url.to_string(),
            request_id: None, // Could be enhanced to take from context
            start_time: Utc::now(),
        };

        self.execute_request(url, None::<&()>, context, OperationType::Read).await
    }

    /// Execute an HTTP POST request with resilience patterns
    pub async fn post<T: serde::Serialize + Send + Sync>(&mut self, url: &str, json: &T) -> Result<reqwest::Response, ResilientClientError> {
        let context = RequestContext {
            destination: self.extract_destination(url),
            method: "POST".to_string(),
            url: url.to_string(),
            request_id: None,
            start_time: Utc::now(),
        };

        self.execute_request(url, Some(json), context, OperationType::Write).await
    }

    /// Extract destination (host) from URL for metrics and circuit breaker grouping
    fn extract_destination(&self, url: &str) -> String {
        url::Url::parse(url)
            .map(|u| u.host_str().unwrap_or("unknown").to_string())
            .unwrap_or_else(|_| "invalid_url".to_string())
    }

    /// Execute request with full resilience pattern implementation
    async fn execute_request<T: serde::Serialize + Send + Sync>(
        &mut self,
        url: &str,
        json: Option<&T>,
        context: RequestContext,
        operation_type: OperationType,
    ) -> Result<reqwest::Response, ResilientClientError>
    {
        let destination = &context.destination;
        
        // Get or create circuit breaker for this destination
        let circuit_breaker = self.circuit_breakers
            .entry(destination.clone())
            .or_insert_with(|| SimpleCircuitBreaker::new(self.config.circuit_breaker.clone()));
        
        // Check circuit breaker first
        if !circuit_breaker.call_allowed() {
            self.record_circuit_breaker_state(destination, 1.0);
            warn!(
                destination = %destination,
                url = %context.url,
                "Circuit breaker is open, rejecting request"
            );
            return Err(ResilientClientError::CircuitBreakerOpen);
        }

        // Update circuit breaker state metric
        let state_value = match circuit_breaker.state() {
            CircuitBreakerState::Closed => 0.0,
            CircuitBreakerState::Open => 1.0,
            CircuitBreakerState::HalfOpen => 2.0,
        };
        self.record_circuit_breaker_state(destination, state_value);

        // Determine timeout based on operation type
        let timeout = match operation_type {
            OperationType::Read => Duration::from_secs(self.config.read_timeout_seconds),
            OperationType::Write => Duration::from_secs(self.config.write_timeout_seconds),
        };

        // Create retry strategy with exponential backoff and jitter
        let retry_strategy = ExponentialBackoff::from_millis(self.config.retry.initial_delay_ms)
            .max_delay(Duration::from_millis(self.config.retry.max_delay_ms))
            .map(tokio_retry::strategy::jitter)
            .take(self.config.retry.max_attempts);

        let url = url.to_string();
        let json_value = json.map(serde_json::to_value).transpose()
            .map_err(|e| ResilientClientError::SerializationError(e.to_string()))?;
        
        let client = self.client.clone();
        let context_clone = context.clone();
        let config = self.config.clone();

        let result = Retry::spawn(retry_strategy, || {
            let client = client.clone();
            let url = url.clone();
            let json_value = json_value.clone();
            let context = context_clone.clone();
            let config = config.clone();
            
            async move {
                let start = std::time::Instant::now();
                
                // Build request
                let request_builder = match json_value {
                    Some(ref value) => client.post(&url).json(value),
                    None => client.get(&url),
                };
                
                // Execute request with timeout
                let result = tokio::time::timeout(timeout, request_builder.send()).await;
                
                match result {
                    Ok(Ok(response)) => {
                        let duration = start.elapsed();
                        
                        if is_retry_status(response.status().as_u16(), &config.retry.retry_on_status) {
                            if config.enable_detailed_logging {
                                warn!(
                                    destination = %context.destination,
                                    method = %context.method,
                                    url = %context.url,
                                    status = response.status().as_u16(),
                                    duration_ms = duration.as_millis(),
                                    "Request failed with retryable status"
                                );
                            }
                            Err(ResilientClientError::RetryableStatus(response.status().as_u16()))
                        } else {
                            if config.enable_detailed_logging {
                                info!(
                                    destination = %context.destination,
                                    method = %context.method,
                                    url = %context.url,
                                    status = response.status().as_u16(),
                                    duration_ms = duration.as_millis(),
                                    "Request completed successfully"
                                );
                            }
                            Ok(response)
                        }
                    }
                    Ok(Err(e)) => {
                        let duration = start.elapsed();
                        
                        if config.enable_detailed_logging {
                            error!(
                                destination = %context.destination,
                                method = %context.method,
                                url = %context.url,
                                error = %e,
                                duration_ms = duration.as_millis(),
                                "Request failed with network error"
                            );
                        }
                        Err(ResilientClientError::NetworkError(e))
                    }
                    Err(_) => {
                        if config.enable_detailed_logging {
                            warn!(
                                destination = %context.destination,
                                method = %context.method,
                                url = %context.url,
                                timeout_seconds = timeout.as_secs(),
                                "Request timed out"
                            );
                        }
                        Err(ResilientClientError::Timeout)
                    }
                }
            }
        })
        .await;

        // Record metrics based on result  
        let final_duration = Duration::from_secs(
            (Utc::now().timestamp() - context.start_time.timestamp()).max(0) as u64
        );
        
        match &result {
            Ok(_response) => {
                self.record_request_metrics(&context, "success", final_duration);
                if let Some(cb) = self.circuit_breakers.get_mut(destination) {
                    cb.on_success();
                }
            }
            Err(err) => {
                match err {
                    ResilientClientError::RetryableStatus(_) => {
                        self.record_request_metrics(&context, "retry_exhausted", final_duration);
                        self.record_retry_attempt(&context, "http_status");
                    }
                    ResilientClientError::NetworkError(_) => {
                        self.record_request_metrics(&context, "network_error", final_duration);
                        self.record_retry_attempt(&context, "network_error");
                    }
                    ResilientClientError::Timeout => {
                        self.record_request_metrics(&context, "timeout", final_duration);
                        self.record_timeout(&context, &operation_type);
                        self.record_retry_attempt(&context, "timeout");
                    }
                    _ => {
                        self.record_request_metrics(&context, "error", final_duration);
                    }
                }
                if let Some(cb) = self.circuit_breakers.get_mut(destination) {
                    cb.on_failure();
                }
            }
        }

        result
    }

    /// Record request metrics
    fn record_request_metrics(&self, context: &RequestContext, outcome: &str, duration: Duration) {
        if let Some(metrics) = &self.metrics {
            metrics.http_requests_total
                .with_label_values(&[context.destination.as_str(), context.method.as_str(), outcome])
                .inc();
            
            metrics.http_request_duration_seconds
                .with_label_values(&[context.destination.as_str(), context.method.as_str()])
                .observe(duration.as_secs_f64());
        }
    }

    /// Record retry attempt
    fn record_retry_attempt(&self, context: &RequestContext, reason: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.retry_attempts_total
                .with_label_values(&[context.destination.as_str(), reason])
                .inc();
        }
    }

    /// Record timeout occurrence
    fn record_timeout(&self, context: &RequestContext, operation_type: &OperationType) {
        if let Some(metrics) = &self.metrics {
            let timeout_type = match operation_type {
                OperationType::Read => "read",
                OperationType::Write => "write",
            };
            metrics.timeouts_total
                .with_label_values(&[context.destination.as_str(), timeout_type])
                .inc();
        }
    }

    /// Record circuit breaker state
    fn record_circuit_breaker_state(&self, destination: &str, state: f64) {
        if let Some(metrics) = &self.metrics {
            metrics.circuit_breaker_state
                .with_label_values(&[destination])
                .set(state);
        }
    }
}

/// Operation type for determining appropriate timeout
#[derive(Debug, Clone)]
enum OperationType {
    Read,
    Write,
}

/// Check if status code should trigger a retry
fn is_retry_status(status: u16, retry_statuses: &[u16]) -> bool {
    retry_statuses.contains(&status)
}

/// Errors that can occur with the resilient client
#[derive(Debug, thiserror::Error)]
pub enum ResilientClientError {
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Request timed out")]
    Timeout,
    
    #[error("Circuit breaker is open")]
    CircuitBreakerOpen,
    
    #[error("Retryable status code: {0}")]
    RetryableStatus(u16),
    
    #[error("Service unavailable, fallback response: {0}")]
    Fallback(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl ResilientClientError {
    /// Get a user-friendly error message for API responses
    pub fn user_message(&self) -> String {
        match self {
            ResilientClientError::NetworkError(_) => "Service temporarily unavailable due to network issues".to_string(),
            ResilientClientError::Timeout => "Service temporarily unavailable due to timeout".to_string(),
            ResilientClientError::CircuitBreakerOpen => "Service temporarily unavailable, please try again later".to_string(),
            ResilientClientError::RetryableStatus(status) => format!("Service returned error status {}, please try again", status),
            ResilientClientError::Fallback(msg) => msg.clone(),
            ResilientClientError::SerializationError(_) => "Invalid request data".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;

    #[test]
    fn test_config_defaults() {
        let config = ResilientClientConfig::default();
        assert_eq!(config.read_timeout_seconds, 1);
        assert_eq!(config.write_timeout_seconds, 5);
        assert_eq!(config.retry.max_attempts, 3);
        assert!(config.enable_detailed_logging);
    }

    #[test]
    fn test_metrics_creation() {
        let registry = Registry::new();
        let metrics = ResilientClientMetrics::new(&registry);
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_extract_destination() {
        let config = ResilientClientConfig::default();
        let client = ResilientClient::new(config, None).unwrap();
        
        assert_eq!(client.extract_destination("https://api.example.com/path"), "api.example.com");
        assert_eq!(client.extract_destination("invalid_url"), "invalid_url");
    }

    #[test]
    fn test_error_user_messages() {
        let timeout_error = ResilientClientError::Timeout;
        assert!(timeout_error.user_message().contains("timeout"));
        
        let circuit_error = ResilientClientError::CircuitBreakerOpen;
        assert!(circuit_error.user_message().contains("try again later"));
    }

    #[test]
    fn test_circuit_breaker() {
        let config = CircuitBreakerConfig::default();
        let mut cb = SimpleCircuitBreaker::new(config);
        
        // Initially closed
        assert_eq!(cb.state(), &CircuitBreakerState::Closed);
        assert!(cb.call_allowed());
        
        // Trigger failures to open circuit
        for _ in 0..5 {
            cb.on_failure();
        }
        
        assert_eq!(cb.state(), &CircuitBreakerState::Open);
        assert!(!cb.call_allowed());
        
        // Success should reset failure count but not close open circuit immediately
        cb.on_success();
        assert_eq!(cb.state(), &CircuitBreakerState::Open);
    }

    #[test]
    fn test_retry_status() {
        let retry_statuses = vec![500, 502, 503, 504];
        assert!(is_retry_status(500, &retry_statuses));
        assert!(is_retry_status(503, &retry_statuses));
        assert!(!is_retry_status(404, &retry_statuses));
        assert!(!is_retry_status(200, &retry_statuses));
    }
}