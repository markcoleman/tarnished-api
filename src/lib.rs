use actix_web::{
    App, Error, HttpResponse, HttpRequest, Result,
    dev::{ServiceRequest, ServiceResponse, forward_ready, Service, Transform},
    http::header::{HeaderName, HeaderValue},
    HttpMessage,
};
use paperclip::actix::{OpenApiExt, api_v2_operation, Apiv2Schema, web};
use paperclip::v2::models::{DefaultApiRaw, Info};
use serde::{Serialize, Deserialize};
use prometheus::{CounterVec, HistogramVec, Gauge, Registry, Encoder, TextEncoder, Opts, HistogramOpts};
use std::{
    env, 
    collections::HashMap, 
    sync::{Arc, Mutex}, 
    time::{Duration, Instant},
    future::{Ready, ready},
    pin::Pin,
};
use uuid::Uuid;

/// Metrics configuration
#[derive(Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};
use uuid::Uuid;

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

    /// Log the audit event using structured logging
    pub fn log(&self) {
        let event_json = serde_json::to_string(self)
            .unwrap_or_else(|_| "Failed to serialize audit event".to_string());

        match self.outcome {
            AuthEventOutcome::Success => {
                info!(
                    target: "auth_audit",
                    event_type = ?self.event_type,
                    outcome = ?self.outcome,
                    ip_address = %self.ip_address,
                    user_id = ?self.user_id,
                    "{}",
                    event_json
                );
            }
            AuthEventOutcome::Failure => {
                warn!(
                    target: "auth_audit",
                    event_type = ?self.event_type,
                    outcome = ?self.outcome,
                    ip_address = %self.ip_address,
                    user_id = ?self.user_id,
                    "{}",
                    event_json
                );
            }
            AuthEventOutcome::Blocked => {
                error!(
                    target: "auth_audit",
                    event_type = ?self.event_type,
                    outcome = ?self.outcome,
                    ip_address = %self.ip_address,
                    user_id = ?self.user_id,
                    "{}",
                    event_json
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
            &["method", "status", "route"]
        )?;
        
        // HTTP request duration histogram
        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds"
            ).buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["method", "route"]
        )?;
        
        // Application uptime gauge
        let app_uptime_seconds = Gauge::new(
            "app_uptime_seconds", 
            "Application uptime in seconds"
        )?;
        
        // Application info counter
        let app_info = CounterVec::new(
            Opts::new("app_info", "Application information"),
            &["version", "commit", "build_time"]
        )?;
        
        // Register all metrics
        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;
        registry.register(Box::new(app_uptime_seconds.clone()))?;
        registry.register(Box::new(app_info.clone()))?;
        
        let start_time = Instant::now();
        
        // Set application info
        app_info.with_label_values(&[
            env!("CARGO_PKG_VERSION"),
            env!("VERGEN_GIT_SHA"),
            env!("VERGEN_BUILD_TIMESTAMP")
        ]).inc();
        
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

        Err(actix_web::error::ErrorUnauthorized(serde_json::to_string(&response).unwrap()))
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
                if now.duration_since(*timestamp) < Duration::from_secs(self.config.period_seconds) {
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
        return Err(HttpResponse::TooManyRequests()
            .json(serde_json::json!({
                "error": "Too Many Requests",
                "message": "Rate limit exceeded. Please try again later."
            })));
    }

    Ok(())
}

/// Configuration for security headers
#[derive(Clone)]
pub struct SecurityHeadersConfig {
    pub enable_csp: bool,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enable_csp: true,
        }
    }
}

impl SecurityHeadersConfig {
    /// Load configuration from environment variables, falling back to defaults
    pub fn from_env() -> Self {
        let enable_csp = env::var("SECURITY_CSP_ENABLED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(true);
        
        Self {
            enable_csp,
        }
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
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
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
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
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
        // Extract or generate Request ID
        let request_id = req
            .headers()
            .get("X-Request-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Store Request ID in request extensions for potential use in handlers
        req.extensions_mut().insert(request_id.clone());

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            
            // Add Request ID to response headers
            res.headers_mut().insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str(&request_id).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
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
        (status = 200, description = "Successful response", body = HealthResponse)
    )
)]
pub async fn health(req: HttpRequest) -> Result<web::Json<HealthResponse>, Error> {
    let start_time = Instant::now();
    
    let response = HealthResponse {
        status: "healthy".to_string(),
    };
    
    // Record metrics if available
    if let Some(metrics) = req.app_data::<web::Data<AppMetrics>>() {
        metrics.record_request("GET", "/api/health", 200, start_time.elapsed());
    }
    
    Ok(web::Json(response))
}

#[api_v2_operation(
    summary = "Version Information Endpoint",
    description = "Returns the current API version, commit hash, and build time.",
    tags("Version"),
    responses(
        (status = 200, description = "Successful response", body = VersionResponse),
        (status = 429, description = "Too Many Requests")
    )
)]
pub async fn version(req: HttpRequest) -> Result<web::Json<VersionResponse>, Error> {
    let start_time = Instant::now();
    
    // Check if rate limiter is available in app data
    if let Some(limiter) = req.app_data::<web::Data<SimpleRateLimiter>>() {
        // Apply rate limiting to version endpoint
        if let Err(_response) = rate_limit_middleware(&req, limiter) {
            // Record metrics for rate limited request
            if let Some(metrics) = req.app_data::<web::Data<AppMetrics>>() {
                metrics.record_request("GET", "/api/version", 429, start_time.elapsed());
            }
            return Err(actix_web::error::ErrorTooManyRequests(
                "Rate limit exceeded. Please try again later."
            ));
        }
    }

    let response = VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("VERGEN_GIT_SHA").to_string(),
        build_time: env!("VERGEN_BUILD_TIMESTAMP").to_string(),
    };
    
    // Record metrics if available
    if let Some(metrics) = req.app_data::<web::Data<AppMetrics>>() {
        metrics.record_request("GET", "/api/version", 200, start_time.elapsed());
    }
    
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
            return Err(actix_web::error::ErrorInternalServerError(
                format!("Failed to encode metrics: {}", e)
            ));
        }
        
        let metrics_output = String::from_utf8(buffer)
            .map_err(|e| actix_web::error::ErrorInternalServerError(
                format!("Failed to convert metrics to string: {}", e)
            ))?;
            
        Ok(HttpResponse::Ok()
            .content_type("text/plain; version=0.0.4; charset=utf-8")
            .body(metrics_output))
    } else {
        Err(actix_web::error::ErrorServiceUnavailable(
            "Metrics not available"
        ))
    }
}

/// Creates the shared OpenAPI configuration for the app
pub fn create_openapi_spec() -> DefaultApiRaw {
    DefaultApiRaw {
        info: Info {
            title: "Tarnished API".into(),
            version: "1.0.0".into(),
            description: Some("A sample API built with Actix and Paperclip".into()),
            ..Default::default()
        },
        ..Default::default()
    }
}

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
    let security_config = SecurityHeadersConfig::from_env();
    let metrics_config = MetricsConfig::from_env();
    let metrics = AppMetrics::new().expect("Failed to create metrics");

    let activity_tracker = SuspiciousActivityTracker::new();
    
    App::new()
        .wrap(SecurityHeaders::new(security_config))
        .wrap(RequestIdMiddleware)
        .wrap_api_with_spec(create_openapi_spec())
        .app_data(web::Data::new(config))
        .app_data(web::Data::new(limiter))
        .app_data(web::Data::new(metrics_config))
        .app_data(web::Data::new(metrics))
        .app_data(web::Data::new(activity_tracker))
        .service(
            web::resource("/api/health")
                .route(web::get().to(health))
        )
        .service(
            web::resource("/api/version")
                .route(web::get().to(version))
        )
        .service(
            web::resource("/api/metrics")
                .route(web::get().to(get_metrics))
            web::resource("/auth/login")
                .route(web::post().to(login))
        )
        .service(
            web::resource("/auth/validate")
                .route(web::post().to(validate_token))
        )
        .with_json_spec_at("/api/spec/v2")
        .build()
}