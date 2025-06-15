use actix_web::{App, Error, HttpResponse, HttpRequest, Result};
use paperclip::actix::{OpenApiExt, api_v2_operation, Apiv2Schema, web};
use paperclip::v2::models::{DefaultApiRaw, Info};
use serde::{Serialize, Deserialize};
use std::{
    env, 
    collections::HashMap, 
    sync::{Arc, Mutex}, 
    time::{Duration, Instant},
};
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
pub async fn health() -> Result<web::Json<HealthResponse>, Error> {
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
        (status = 429, description = "Too Many Requests")
    )
)]
pub async fn version(req: HttpRequest) -> Result<web::Json<VersionResponse>, Error> {
    // Check if rate limiter is available in app data
    if let Some(limiter) = req.app_data::<web::Data<SimpleRateLimiter>>() {
        // Apply rate limiting to version endpoint
        if let Err(_response) = rate_limit_middleware(&req, limiter) {
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
    Ok(web::Json(response))
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
    let activity_tracker = SuspiciousActivityTracker::new();
    
    App::new()
        .wrap_api_with_spec(create_openapi_spec())
        .app_data(web::Data::new(config))
        .app_data(web::Data::new(limiter))
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