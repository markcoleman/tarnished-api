use actix_web::{App, Error, HttpResponse, HttpRequest, Result};
use paperclip::actix::{OpenApiExt, api_v2_operation, Apiv2Schema, web};
use paperclip::v2::models::{DefaultApiRaw, Info};
use serde::{Serialize, Deserialize};
use prometheus::{CounterVec, HistogramVec, Gauge, Registry, Encoder, TextEncoder, Opts, HistogramOpts};
use std::{
    env, 
    collections::HashMap, 
    sync::{Arc, Mutex}, 
    time::{Duration, Instant},
};

/// Metrics configuration
#[derive(Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
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

/// Creates a basic app with shared configuration (health endpoint + OpenAPI + rate limiting + metrics)
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
    let metrics_config = MetricsConfig::from_env();
    let metrics = AppMetrics::new().expect("Failed to create metrics");
    
    App::new()
        .wrap_api_with_spec(create_openapi_spec())
        .app_data(web::Data::new(config))
        .app_data(web::Data::new(limiter))
        .app_data(web::Data::new(metrics_config))
        .app_data(web::Data::new(metrics))
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
        )
        .with_json_spec_at("/api/spec/v2")
        .build()
}