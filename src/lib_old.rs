use actix_web::{
    App, Error, HttpMessage, HttpRequest, HttpResponse, Result,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue},
};
use hmac::{Hmac, Mac};
use paperclip::actix::{Apiv2Schema, OpenApiExt, api_v2_operation, web};
use paperclip::v2::models::{DefaultApiRaw, Info};
use prometheus::{
    CounterVec, Encoder, Gauge, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use std::{
    future::{Ready, ready},
    pin::Pin,
};
use uuid::Uuid;

pub mod newrelic;

/// Metrics configuration
#[derive(Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

use chrono::{DateTime, Utc};
use tracing::{error, info, warn};
use crate::newrelic::redact_sensitive_data;

/// Audit event types for authentication logging
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEventType {
    LoginSuccess,
    LoginFailure,
    TokenValidationSuccess,
    TokenValidationFailure,
    TokenExpired,
    TokenRevoked,
    SuspiciousActivity,
}

/// Audit event outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEventOutcome {
    Success,
    Failure,
    Blocked,
}

/// Structured audit log entry for authentication events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAuditEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuthEventType,
    pub outcome: AuthEventOutcome,
    pub ip_address: String,
    pub user_id: Option<String>,
    pub method: String,
    pub endpoint: String,
    pub user_agent: Option<String>,
    pub details: Option<String>,
}

impl AuthAuditEvent {
    /// Create a new auth audit event
    pub fn new(
        event_type: AuthEventType,
        outcome: AuthEventOutcome,
        ip_address: String,
        method: String,
        endpoint: String,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            outcome,
            ip_address,
            user_id: None,
            method,
            endpoint,
            user_agent: None,
            details: None,
        }
    }

    /// Set user ID for the event
    pub fn with_user_id(mut self, user_id: Option<String>) -> Self {
        self.user_id = user_id;
        self
    }

    /// Set user agent for the event
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Set additional details for the event
    pub fn with_details(mut self, details: Option<String>) -> Self {
        self.details = details;
        self
    }

    /// Log the audit event using structured logging with New Relic correlation
    pub fn log(&self) {
        let event_json = serde_json::to_string(self)
            .unwrap_or_else(|_| "Failed to serialize audit event".to_string());
        
        // Redact sensitive data from the JSON
        let redacted_json = redact_sensitive_data(&event_json);

        // Get environment metadata for enhanced logging
        let commit_sha = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "unknown".to_string());
        let git_ref = std::env::var("GITHUB_REF").unwrap_or_else(|_| "unknown".to_string());
        let environment = std::env::var("NEW_RELIC_ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

        match self.outcome {
            AuthEventOutcome::Success => {
                info!(
                    target: "auth_audit",
                    event_id = %self.event_id,
                    event_type = ?self.event_type,
                    outcome = ?self.outcome,
                    ip_address = %self.ip_address,
                    user_id = ?self.user_id,
                    method = %self.method,
                    endpoint = %self.endpoint,
                    user_agent = ?self.user_agent,
                    commit_sha = %commit_sha,
                    git_ref = %git_ref,
                    environment = %environment,
                    "{}",
                    redacted_json
                );
            }
            AuthEventOutcome::Failure => {
                warn!(
                    target: "auth_audit",
                    event_id = %self.event_id,
                    event_type = ?self.event_type,
                    outcome = ?self.outcome,
                    ip_address = %self.ip_address,
                    user_id = ?self.user_id,
                    method = %self.method,
                    endpoint = %self.endpoint,
                    user_agent = ?self.user_agent,
                    commit_sha = %commit_sha,
                    git_ref = %git_ref,
                    environment = %environment,
                    "{}",
                    redacted_json
                );
            }
            AuthEventOutcome::Blocked => {
                error!(
                    target: "auth_audit",
                    event_id = %self.event_id,
                    event_type = ?self.event_type,
                    outcome = ?self.outcome,
                    ip_address = %self.ip_address,
                    user_id = ?self.user_id,
                    method = %self.method,
                    endpoint = %self.endpoint,
                    user_agent = ?self.user_agent,
                    commit_sha = %commit_sha,
                    git_ref = %git_ref,
                    environment = %environment,
                    "{}",
                    redacted_json
                );
            }
        }
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

/// Metrics middleware function-based approach
pub fn metrics_middleware(
    req: &HttpRequest,
    metrics: &AppMetrics,
    start_time: Instant,
    status: u16,
) {
    let duration = start_time.elapsed();
    let method = req.method().as_str();
    let route = extract_route_pattern(req);

    metrics.record_request(method, &route, status, duration);
    metrics.update_uptime();
}

/// Extract route pattern from request, handling common patterns
fn extract_route_pattern(req: &HttpRequest) -> String {
    let path = req.path();

    // Return the actual path for our API routes since they're well-defined
    // This could be enhanced to group similar routes if needed
    if path.starts_with('/') {
        path.to_string()
    } else {
        "/unknown".to_string()
    }
}

/// Application metrics collector
#[derive(Clone)]
pub struct AppMetrics {
    pub registry: Registry,
    pub http_requests_total: CounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub app_uptime_seconds: Gauge,
    pub app_info: CounterVec,
    pub start_time: Instant,
}

impl AppMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // HTTP request counter by method, status, and route
        let http_requests_total = CounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests"),
            &["method", "status", "route"],
        )?;

        // HTTP request duration histogram
        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "route"],
        )?;

        // Application uptime gauge
        let app_uptime_seconds = Gauge::new("app_uptime_seconds", "Application uptime in seconds")?;

        // Application info counter
        let app_info = CounterVec::new(
            Opts::new("app_info", "Application information"),
            &["version", "commit", "build_time"],
        )?;

        // Register all metrics
        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;
        registry.register(Box::new(app_uptime_seconds.clone()))?;
        registry.register(Box::new(app_info.clone()))?;

        let start_time = Instant::now();

        // Set application info
        app_info
            .with_label_values(&[
                env!("CARGO_PKG_VERSION"),
                env!("VERGEN_GIT_SHA"),
                env!("VERGEN_BUILD_TIMESTAMP"),
            ])
            .inc();

        Ok(Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            app_uptime_seconds,
            app_info,
            start_time,
        })
    }

    pub fn record_request(&self, method: &str, route: &str, status: u16, duration: Duration) {
        if route == "/api/metrics" {
            // Don't record metrics for the metrics endpoint itself to avoid noise
            return;
        }

        self.http_requests_total
            .with_label_values(&[method, &status.to_string(), route])
            .inc();

        self.http_request_duration_seconds
            .with_label_values(&[method, route])
            .observe(duration.as_secs_f64());
    }

    pub fn update_uptime(&self) {
        let uptime = self.start_time.elapsed().as_secs_f64();
        self.app_uptime_seconds.set(uptime);
    }
}

/// Extract client IP address from request
pub fn extract_client_ip(req: &HttpRequest) -> String {
    // Check for X-Forwarded-For header first (common in load balancers)
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    // Check for X-Real-IP header
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            return real_ip_str.to_string();
        }
    }

    // Fall back to connection info
    req.connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string()
}

/// Extract user agent from request
pub fn extract_user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|s| s.to_string())
}

/// Simple login request structure
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Simple login response structure
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct LoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub message: String,
}

/// Token validation request structure
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct TokenValidationRequest {
    pub token: String,
}

/// Token validation response structure
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct TokenValidationResponse {
    pub valid: bool,
    pub user_id: Option<String>,
    pub message: String,
}

/// Simple authentication endpoint - login
#[api_v2_operation(
    summary = "User Login",
    description = "Authenticate user and return access token",
    tags("Authentication"),
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Login failed", body = LoginResponse),
        (status = 429, description = "Too many requests")
    )
)]
pub async fn login(
    req: HttpRequest,
    payload: web::Json<LoginRequest>,
) -> Result<web::Json<LoginResponse>, Error> {
    let ip_address = extract_client_ip(&req);
    let user_agent = extract_user_agent(&req);
    let method = req.method().to_string();
    let endpoint = req.uri().path().to_string();

    // Simple mock authentication - in real implementation, this would check against a database
    let success = payload.username == "admin" && payload.password == "password123";

    if success {
        let token = format!("token_{}", Uuid::new_v4());
        let response = LoginResponse {
            success: true,
            token: Some(token),
            message: "Login successful".to_string(),
        };

        // Log successful login
        AuthAuditEvent::new(
            AuthEventType::LoginSuccess,
            AuthEventOutcome::Success,
            ip_address,
            method,
            endpoint,
        )
        .with_user_id(Some(payload.username.clone()))
        .with_user_agent(user_agent)
        .log();

        Ok(web::Json(response))
    } else {
        let response = LoginResponse {
            success: false,
            token: None,
            message: "Invalid credentials".to_string(),
        };

        // Log failed login
        AuthAuditEvent::new(
            AuthEventType::LoginFailure,
            AuthEventOutcome::Failure,
            ip_address,
            method,
            endpoint,
        )
        .with_user_id(Some(payload.username.clone()))
        .with_user_agent(user_agent)
        .log();

        Err(actix_web::error::ErrorUnauthorized(
            serde_json::to_string(&response).unwrap(),
        ))
    }
}

/// Simple token validation endpoint
#[api_v2_operation(
    summary = "Token Validation",
    description = "Validate an access token",
    tags("Authentication"),
    responses(
        (status = 200, description = "Token validation response", body = TokenValidationResponse)
    )
)]
pub async fn validate_token(
    req: HttpRequest,
    payload: web::Json<TokenValidationRequest>,
) -> Result<web::Json<TokenValidationResponse>, Error> {
    let ip_address = extract_client_ip(&req);
    let user_agent = extract_user_agent(&req);
    let method = req.method().to_string();
    let endpoint = req.uri().path().to_string();

    // Simple mock token validation - in real implementation, this would verify JWT or check database
    let valid = payload.token.starts_with("token_");

    if valid {
        let response = TokenValidationResponse {
            valid: true,
            user_id: Some("admin".to_string()),
            message: "Token is valid".to_string(),
        };

        // Log successful token validation
        AuthAuditEvent::new(
            AuthEventType::TokenValidationSuccess,
            AuthEventOutcome::Success,
            ip_address,
            method,
            endpoint,
        )
        .with_user_id(Some("admin".to_string()))
        .with_user_agent(user_agent)
        .log();

        Ok(web::Json(response))
    } else {
        let response = TokenValidationResponse {
            valid: false,
            user_id: None,
            message: "Invalid token".to_string(),
        };

        // Log failed token validation
        AuthAuditEvent::new(
            AuthEventType::TokenValidationFailure,
            AuthEventOutcome::Failure,
            ip_address,
            method,
            endpoint,
        )
        .with_user_agent(user_agent)
        .log();

        Ok(web::Json(response))
    }
}

/// Simple tracking for suspicious activity detection
#[derive(Clone)]
pub struct SuspiciousActivityTracker {
    failed_attempts: Arc<Mutex<HashMap<String, (usize, Instant)>>>,
    max_failures: usize,
    window_seconds: u64,
}

impl Default for SuspiciousActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SuspiciousActivityTracker {
    pub fn new() -> Self {
        let max_failures = env::var("AUTH_MAX_FAILURES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let window_seconds = env::var("AUTH_FAILURE_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300); // 5 minutes

        Self {
            failed_attempts: Arc::new(Mutex::new(HashMap::new())),
            max_failures,
            window_seconds,
        }
    }

    /// Record a failed authentication attempt
    pub fn record_failure(&self, ip: &str) -> bool {
        let mut attempts = self.failed_attempts.lock().unwrap();
        let now = Instant::now();

        // Clean up old entries
        attempts.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < Duration::from_secs(self.window_seconds)
        });

        match attempts.get_mut(ip) {
            Some((count, timestamp)) => {
                if now.duration_since(*timestamp) < Duration::from_secs(self.window_seconds) {
                    *count += 1;
                    *count >= self.max_failures
                } else {
                    *count = 1;
                    *timestamp = now;
                    false
                }
            }
            None => {
                attempts.insert(ip.to_string(), (1, now));
                false
            }
        }
    }

    /// Check if IP has too many failures (is suspicious)
    pub fn is_suspicious(&self, ip: &str) -> bool {
        let attempts = self.failed_attempts.lock().unwrap();
        if let Some((count, timestamp)) = attempts.get(ip) {
            let now = Instant::now();
            if now.duration_since(*timestamp) < Duration::from_secs(self.window_seconds) {
                return *count >= self.max_failures;
            }
        }
        false
    }
}

/// Configuration for rate limiting
#[derive(Clone)]
pub struct RateLimitConfig {
    pub requests_per_minute: usize,
    pub period_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 100,
            period_seconds: 60,
        }
    }
}

impl RateLimitConfig {
    /// Load configuration from environment variables, falling back to defaults
    pub fn from_env() -> Self {
        let requests_per_minute = env::var("RATE_LIMIT_RPM")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let period_seconds = env::var("RATE_LIMIT_PERIOD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Self {
            requests_per_minute,
            period_seconds,
        }
    }
}

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
            secret: "default-secret-change-in-production".to_string(),
            timestamp_tolerance_seconds: 300, // 5 minutes
            require_signature: false,         // Optional by default for backward compatibility
        }
    }
}

impl HmacConfig {
    /// Load configuration from environment variables, falling back to defaults
    pub fn from_env() -> Self {
        let secret = env::var("HMAC_SECRET")
            .unwrap_or_else(|_| "default-secret-change-in-production".to_string());

        let timestamp_tolerance_seconds = env::var("HMAC_TIMESTAMP_TOLERANCE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);

        let require_signature = env::var("HMAC_REQUIRE_SIGNATURE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        Self {
            secret,
            timestamp_tolerance_seconds,
            require_signature,
        }
    }
}

/// Simple in-memory rate limiter
#[derive(Clone)]
pub struct SimpleRateLimiter {
    config: RateLimitConfig,
    storage: Arc<Mutex<HashMap<String, (usize, Instant)>>>,
}

impl SimpleRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn check_rate_limit(&self, key: &str) -> bool {
        let mut storage = self.storage.lock().unwrap();
        let now = Instant::now();

        // Clean up expired entries
        storage.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < Duration::from_secs(self.config.period_seconds)
        });

        match storage.get_mut(key) {
            Some((count, timestamp)) => {
                if now.duration_since(*timestamp) < Duration::from_secs(self.config.period_seconds)
                {
                    if *count >= self.config.requests_per_minute {
                        false // Rate limit exceeded
                    } else {
                        *count += 1;
                        true
                    }
                } else {
                    // Reset the counter for a new period
                    *count = 1;
                    *timestamp = now;
                    true
                }
            }
            None => {
                storage.insert(key.to_string(), (1, now));
                true
            }
        }
    }
}

/// Rate limiting middleware using a function-based approach
pub fn rate_limit_middleware(
    req: &HttpRequest,
    limiter: &SimpleRateLimiter,
) -> Result<(), HttpResponse> {
    // Extract IP from request
    let ip = req
        .connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string();

    if !limiter.check_rate_limit(&ip) {
        // Rate limit exceeded, return 429
        return Err(HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Too Many Requests",
            "message": "Rate limit exceeded. Please try again later."
        })));
    }

    Ok(())
}

/// HMAC signature utility functions
pub mod hmac_utils {
    use super::*;

    type HmacSha256 = Hmac<Sha256>;

    /// Generate HMAC-SHA256 signature for the given payload and timestamp
    pub fn generate_signature(
        secret: &str,
        payload: &str,
        timestamp: u64,
    ) -> Result<String, String> {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| format!("Invalid secret key: {}", e))?;

        let message = format!("{}.{}", timestamp, payload);
        mac.update(message.as_bytes());

        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    /// Validate HMAC-SHA256 signature
    pub fn validate_signature(
        secret: &str,
        payload: &str,
        timestamp: u64,
        signature: &str,
        tolerance_seconds: u64,
    ) -> Result<bool, String> {
        // Check timestamp validity first
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("System time error: {}", e))?
            .as_secs();

        let time_diff = current_time.abs_diff(timestamp);

        if time_diff > tolerance_seconds {
            return Ok(false);
        }

        // Generate expected signature
        let expected_signature = generate_signature(secret, payload, timestamp)?;

        // Compare signatures using constant-time comparison
        let signature_bytes =
            hex::decode(signature).map_err(|_| "Invalid signature format".to_string())?;
        let expected_bytes = hex::decode(expected_signature)
            .map_err(|_| "Invalid expected signature format".to_string())?;

        if signature_bytes.len() != expected_bytes.len() {
            return Ok(false);
        }

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| format!("Invalid secret key: {}", e))?;

        mac.update(format!("{}.{}", timestamp, payload).as_bytes());

        mac.verify_slice(&signature_bytes)
            .map(|_| true)
            .or(Ok(false))
    }
}

/// HMAC signature middleware
pub fn hmac_signature_middleware(
    req: &HttpRequest,
    body: &str,
    config: &HmacConfig,
) -> Result<(), HttpResponse> {
    // If signature is not required, skip validation
    if !config.require_signature {
        return Ok(());
    }

    // Extract signature and timestamp headers
    let signature = req
        .headers()
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Missing X-Signature header"
            }))
        })?;

    let timestamp_str = req
        .headers()
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Missing X-Timestamp header"
            }))
        })?;

    let timestamp: u64 = timestamp_str.parse().map_err(|_| {
        HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized",
            "message": "Invalid X-Timestamp format"
        }))
    })?;

    // Validate signature
    match hmac_utils::validate_signature(
        &config.secret,
        body,
        timestamp,
        signature,
        config.timestamp_tolerance_seconds,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized",
            "message": "Invalid signature or timestamp"
        }))),
        Err(e) => Err(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Internal Server Error",
            "message": format!("Signature validation error: {}", e)
        }))),
    }
}

/// Add HMAC signature to outgoing response
pub fn add_response_signature(
    response: &mut HttpResponse,
    body: &str,
    config: &HmacConfig,
) -> Result<(), String> {
    if config.secret.is_empty() {
        return Err("HMAC secret is empty".to_string());
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs();

    let signature = hmac_utils::generate_signature(&config.secret, body, timestamp)?;

    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-signature"),
        actix_web::http::header::HeaderValue::from_str(&signature)
            .map_err(|e| format!("Invalid signature format: {}", e))?,
    );

    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-timestamp"),
        actix_web::http::header::HeaderValue::from_str(&timestamp.to_string())
            .map_err(|e| format!("Invalid timestamp format: {}", e))?,
    );

    Ok(())
}

/// Configuration for security headers
#[derive(Clone)]
pub struct SecurityHeadersConfig {
    pub enable_csp: bool,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self { enable_csp: true }
    }
}

impl SecurityHeadersConfig {
    /// Load configuration from environment variables, falling back to defaults
    pub fn from_env() -> Self {
        let enable_csp = env::var("SECURITY_CSP_ENABLED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(true);

        Self { enable_csp }
    }
}

/// Middleware that adds security headers to all responses
pub struct SecurityHeaders {
    config: SecurityHeadersConfig,
}

impl SecurityHeaders {
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: actix_web::dev::Service<
            ServiceRequest,
            Response = ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware {
            service,
            config: self.config.clone(),
        }))
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: S,
    config: SecurityHeadersConfig,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: actix_web::dev::Service<
            ServiceRequest,
            Response = ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        let config = self.config.clone();

        Box::pin(async move {
            let mut res = fut.await?;

            // Add security headers to the response
            let headers = res.headers_mut();

            // X-Content-Type-Options: nosniff
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );

            // X-Frame-Options: DENY
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );

            // X-XSS-Protection: 1; mode=block
            headers.insert(
                HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static("1; mode=block"),
            );

            // Referrer-Policy: no-referrer
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            );

            // Content-Security-Policy (configurable)
            if config.enable_csp {
                headers.insert(
                    HeaderName::from_static("content-security-policy"),
                    HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
                );
            }

            Ok(res)
        })
    }
}

/// Metrics middleware to automatically record request metrics
pub struct MetricsMiddleware;

impl<S, B> Transform<S, ServiceRequest> for MetricsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = MetricsService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(MetricsService { service }))
    }
}

pub struct MetricsService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for MetricsService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start_time = Instant::now();
        let method = req.method().to_string();
        let path = req.path().to_string();

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            let status = res.status().as_u16();
            let duration = start_time.elapsed();

            // Record metrics if available
            if let Some(metrics) = res.request().app_data::<web::Data<AppMetrics>>() {
                metrics.record_request(&method, &path, status, duration);
            }

            Ok(res)
        })
    }
}

/// Request ID middleware to add unique request IDs to all requests
pub struct RequestIdMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RequestIdMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = RequestIdService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestIdService { service }))
    }
}

pub struct RequestIdService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestIdService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start_time = std::time::Instant::now();
        
        // Extract or generate Request ID
        let request_id = req
            .headers()
            .get("X-Request-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Create New Relic fields for enhanced logging
        let newrelic_fields = crate::newrelic::NewRelicFields::from_request(req.request());

        // Store Request ID in request extensions for potential use in handlers
        req.extensions_mut().insert(request_id.clone());

        // Log incoming request with New Relic fields
        tracing::info!(
            target: "request",
            request_id = %request_id,
            method = %newrelic_fields.method,
            path = %newrelic_fields.path,
            ip_address = %newrelic_fields.ip_address,
            user_agent = ?newrelic_fields.user_agent,
            commit_sha = %std::env::var("GITHUB_SHA").unwrap_or_else(|_| "unknown".to_string()),
            git_ref = %std::env::var("GITHUB_REF").unwrap_or_else(|_| "unknown".to_string()),
            environment = %std::env::var("NEW_RELIC_ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            "Incoming request"
        );

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            let duration = start_time.elapsed();

            // Add Request ID to response headers
            res.headers_mut().insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str(&request_id)
                    .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
            );

            // Log completed request with response details
            tracing::info!(
                target: "request",
                request_id = %request_id,
                status = %res.status().as_u16(),
                duration_ms = %duration.as_millis(),
                commit_sha = %std::env::var("GITHUB_SHA").unwrap_or_else(|_| "unknown".to_string()),
                git_ref = %std::env::var("GITHUB_REF").unwrap_or_else(|_| "unknown".to_string()),
                environment = %std::env::var("NEW_RELIC_ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
                "Request completed"
            );

            Ok(res)
        })
    }
}

// Define a schema for the health response
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct HealthResponse {
    pub status: String,
}

// Define a schema for the version response
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct VersionResponse {
    pub version: String,
    pub commit: String,
    pub build_time: String,
}

#[api_v2_operation(
    summary = "Health Check Endpoint",
    description = "Returns the current health status of the API in JSON format.",
    tags("Health"),
    responses(
        (status = 200, description = "Successful response", body = HealthResponse),
        (status = 401, description = "Unauthorized - Invalid or missing HMAC signature")
    )
)]
pub async fn health(req: HttpRequest) -> Result<web::Json<HealthResponse>, Error> {
    // Check if HMAC config is available and validate signature
    if let Some(hmac_config) = req.app_data::<web::Data<HmacConfig>>() {
        // For GET requests, the body is typically empty
        if let Err(_response) = hmac_signature_middleware(&req, "", hmac_config) {
            return Err(actix_web::error::ErrorUnauthorized(
                "Invalid or missing HMAC signature",
            ));
        }
    }

    let response = HealthResponse {
        status: "healthy".to_string(),
    };

    Ok(web::Json(response))
}

#[api_v2_operation(
    summary = "Version Information Endpoint",
    description = "Returns the current API version, commit hash, and build time.",
    tags("Version"),
    responses(
        (status = 200, description = "Successful response", body = VersionResponse),
        (status = 401, description = "Unauthorized - Invalid or missing HMAC signature"),
        (status = 429, description = "Too Many Requests")
    )
)]
pub async fn version(req: HttpRequest) -> Result<web::Json<VersionResponse>, Error> {
    // Check if HMAC config is available and validate signature
    if let Some(hmac_config) = req.app_data::<web::Data<HmacConfig>>() {
        // For GET requests, the body is typically empty
        if let Err(_response) = hmac_signature_middleware(&req, "", hmac_config) {
            return Err(actix_web::error::ErrorUnauthorized(
                "Invalid or missing HMAC signature",
            ));
        }
    }

    // Check if rate limiter is available in app data
    if let Some(limiter) = req.app_data::<web::Data<SimpleRateLimiter>>() {
        // Apply rate limiting to version endpoint
        if let Err(_response) = rate_limit_middleware(&req, limiter) {
            return Err(actix_web::error::ErrorTooManyRequests(
                "Rate limit exceeded. Please try again later.",
            ));
        }
    }

    let response = VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("VERGEN_GIT_SHA").to_string(),
        build_time: env!("VERGEN_BUILD_TIMESTAMP").to_string(),
    };

    Ok(web::Json(response))
}

#[api_v2_operation(
    summary = "Prometheus Metrics Endpoint", 
    description = "Returns Prometheus-formatted metrics for monitoring API performance and usage patterns.",
    tags("Metrics"),
    responses(
        (status = 200, description = "Prometheus metrics in text format", content_type = "text/plain"),
        (status = 503, description = "Metrics collection disabled")
    )
)]
pub async fn get_metrics(req: HttpRequest) -> Result<HttpResponse, Error> {
    // Check if metrics are enabled
    if let Some(config) = req.app_data::<web::Data<MetricsConfig>>() {
        if !config.enabled {
            return Ok(HttpResponse::ServiceUnavailable()
                .content_type("text/plain")
                .body("Metrics collection is disabled"));
        }
    }

    // Get metrics from app data
    if let Some(metrics) = req.app_data::<web::Data<AppMetrics>>() {
        // Update uptime before encoding
        metrics.update_uptime();

        // Encode metrics in Prometheus format
        let encoder = TextEncoder::new();
        let metric_families = metrics.registry.gather();

        let mut buffer = Vec::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            return Err(actix_web::error::ErrorInternalServerError(format!(
                "Failed to encode metrics: {}",
                e
            )));
        }

        let metrics_output = String::from_utf8(buffer).map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to convert metrics to string: {}",
                e
            ))
        })?;

        Ok(HttpResponse::Ok()
            .content_type("text/plain; version=0.0.4; charset=utf-8")
            .body(metrics_output))
    } else {
        Err(actix_web::error::ErrorServiceUnavailable(
            "Metrics not available",
        ))
    }
}

/// Creates the shared OpenAPI configuration for the app
pub fn create_openapi_spec() -> DefaultApiRaw {
    DefaultApiRaw {
        info: Info {
            title: "Tarnished API".into(),
            version: "1.0.0".into(),
            description: Some(
                "A sample API built with Actix and Paperclip\n\n\
                ## HMAC Signature Authentication\n\
                This API supports optional HMAC-SHA256 signature validation for enhanced security.\n\
                \n\
                **Headers for signed requests:**\n\
                - `X-Signature`: HMAC-SHA256 signature in hexadecimal format\n\
                - `X-Timestamp`: Unix timestamp (seconds since epoch)\n\
                \n\
                **Signature calculation:**\n\
                1. Create message: `{timestamp}.{request_body}`\n\
                2. Calculate HMAC-SHA256 using shared secret\n\
                3. Encode result as hexadecimal string\n\
                \n\
                **Configuration:**\n\
                - Set `HMAC_REQUIRE_SIGNATURE=true` to enforce signature validation\n\
                - Set `HMAC_SECRET` to configure the shared secret\n\
                - Set `HMAC_TIMESTAMP_TOLERANCE` to configure timestamp tolerance (default: 300 seconds)\n\
                \n\
                **Response signatures:**\n\
                - Responses may include `X-Signature` and `X-Timestamp` headers for client verification\n\
                - Signature is calculated using the same method as request signatures".into()
            ),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Creates a basic app with shared configuration (health endpoint + OpenAPI + rate limiting + HMAC)
/// Creates a basic app with shared configuration (health endpoint + OpenAPI + rate limiting + security headers)
/// Creates a basic app with shared configuration (health endpoint + OpenAPI + rate limiting + metrics)
/// Creates a basic app with shared configuration (health endpoint + OpenAPI + rate limiting + auth)
/// This can be used both for testing and as a base for the main application
pub fn create_base_app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let config = RateLimitConfig::from_env();
    let limiter = SimpleRateLimiter::new(config.clone());
    let hmac_config = HmacConfig::from_env();
    let security_config = SecurityHeadersConfig::from_env();
    let metrics_config = MetricsConfig::from_env();
    let metrics = AppMetrics::new().expect("Failed to create metrics");

    let activity_tracker = SuspiciousActivityTracker::new();

    App::new()
        .wrap(SecurityHeaders::new(security_config))
        .wrap(RequestIdMiddleware)
        .wrap(MetricsMiddleware)
        .wrap_api_with_spec(create_openapi_spec())
        .app_data(web::Data::new(config))
        .app_data(web::Data::new(limiter))
        .app_data(web::Data::new(hmac_config))
        .app_data(web::Data::new(metrics_config))
        .app_data(web::Data::new(metrics))
        .app_data(web::Data::new(activity_tracker))
        .service(web::resource("/api/health").route(web::get().to(health)))
        .service(web::resource("/api/version").route(web::get().to(version)))
        .service(web::resource("/api/metrics").route(web::get().to(get_metrics)))
        .service(web::resource("/auth/login").route(web::post().to(login)))
        .service(web::resource("/auth/validate").route(web::post().to(validate_token)))
        .with_json_spec_at("/api/spec/v2")
        .build()
}
