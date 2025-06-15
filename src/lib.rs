use actix_web::{
    App, Error, HttpResponse, HttpRequest, Result,
    dev::{ServiceRequest, ServiceResponse, forward_ready},
    http::header::{HeaderName, HeaderValue},
    HttpMessage,
};
use actix_web::dev::{Service, Transform};
use paperclip::actix::{OpenApiExt, api_v2_operation, Apiv2Schema, web};
use paperclip::v2::models::{DefaultApiRaw, Info};
use serde::{Serialize, Deserialize};
use std::{
    env, 
    collections::HashMap, 
    sync::{Arc, Mutex}, 
    time::{Duration, Instant},
    future::{Ready, ready},
    pin::Pin,
};
use uuid::Uuid;

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

/// Request ID middleware to add unique request IDs to all requests
pub struct RequestIdMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RequestIdMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
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
    type Error = Error;
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

/// Creates a basic app with shared configuration (health endpoint + OpenAPI + rate limiting)
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
    
    App::new()
        .wrap(RequestIdMiddleware)
        .wrap_api_with_spec(create_openapi_spec())
        .app_data(web::Data::new(config))
        .app_data(web::Data::new(limiter))
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