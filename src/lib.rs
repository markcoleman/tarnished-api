use actix_web::{App, Error, HttpResponse, HttpRequest, Result};
use paperclip::actix::{OpenApiExt, api_v2_operation, Apiv2Schema, web};
use paperclip::v2::models::{DefaultApiRaw, Info};
use serde::{Serialize, Deserialize};
use std::{
    env, 
    collections::HashMap, 
    sync::{Arc, Mutex}, 
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

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
            require_signature: false, // Optional by default for backward compatibility
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

/// HMAC signature utility functions
pub mod hmac_utils {
    use super::*;
    
    type HmacSha256 = Hmac<Sha256>;
    
    /// Generate HMAC-SHA256 signature for the given payload and timestamp
    pub fn generate_signature(secret: &str, payload: &str, timestamp: u64) -> Result<String, String> {
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
        tolerance_seconds: u64
    ) -> Result<bool, String> {
        // Check timestamp validity first
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("System time error: {}", e))?
            .as_secs();
        
        let time_diff = if current_time > timestamp {
            current_time - timestamp
        } else {
            timestamp - current_time
        };
        
        if time_diff > tolerance_seconds {
            return Ok(false);
        }
        
        // Generate expected signature
        let expected_signature = generate_signature(secret, payload, timestamp)?;
        
        // Compare signatures using constant-time comparison
        let signature_bytes = hex::decode(signature)
            .map_err(|_| "Invalid signature format".to_string())?;
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
    let signature = req.headers()
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Unauthorized()
                .json(serde_json::json!({
                    "error": "Unauthorized",
                    "message": "Missing X-Signature header"
                }))
        })?;
    
    let timestamp_str = req.headers()
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Unauthorized()
                .json(serde_json::json!({
                    "error": "Unauthorized", 
                    "message": "Missing X-Timestamp header"
                }))
        })?;
    
    let timestamp: u64 = timestamp_str.parse()
        .map_err(|_| {
            HttpResponse::Unauthorized()
                .json(serde_json::json!({
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
        config.timestamp_tolerance_seconds
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(HttpResponse::Unauthorized()
            .json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Invalid signature or timestamp"
            }))),
        Err(e) => Err(HttpResponse::InternalServerError()
            .json(serde_json::json!({
                "error": "Internal Server Error",
                "message": format!("Signature validation error: {}", e)
            })))
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
            .map_err(|e| format!("Invalid signature format: {}", e))?
    );
    
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-timestamp"),
        actix_web::http::header::HeaderValue::from_str(&timestamp.to_string())
            .map_err(|e| format!("Invalid timestamp format: {}", e))?
    );
    
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
                "Invalid or missing HMAC signature"
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
                "Invalid or missing HMAC signature"
            ));
        }
    }
    
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
    
    App::new()
        .wrap_api_with_spec(create_openapi_spec())
        .app_data(web::Data::new(config))
        .app_data(web::Data::new(limiter))
        .app_data(web::Data::new(hmac_config))
        .service(
            web::resource("/api/health")
                .route(web::get().to(health))
        )
        .service(
            web::resource("/api/version")
                .route(web::get().to(version))
        )
        .with_json_spec_at("/api/spec/v2")
        .build()
}