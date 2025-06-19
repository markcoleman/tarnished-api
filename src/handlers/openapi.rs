//! OpenAPI specification generation and app factory.

use paperclip::v2::models::{DefaultApiRaw, Info};
use actix_web::App;
use crate::{
    config::{RateLimitConfig, SecurityHeadersConfig, MetricsConfig},
    services::{rate_limit::SimpleRateLimiter, AppMetrics, SuspiciousActivityTracker},
    middleware::{SecurityHeaders, RequestIdMiddleware},
    handlers::{health, version, get_metrics, login, validate_token},
};
use paperclip::actix::{OpenApiExt, web};

/// Creates the shared OpenAPI specification for the API
/// 
/// This includes comprehensive documentation about HMAC signature authentication,
/// available endpoints, and configuration options.
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

/// Creates a basic app with shared configuration
/// 
/// This factory function creates a pre-configured Actix Web application with:
/// - Health and version endpoints
/// - OpenAPI specification
/// - Rate limiting
/// - Security headers
/// - Metrics collection
/// - Authentication endpoints
/// 
/// This can be used both for testing and as a base for the main application.
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
        .service(web::resource("/api/health").route(web::get().to(health)))
        .service(web::resource("/api/version").route(web::get().to(version)))
        .service(web::resource("/api/metrics").route(web::get().to(get_metrics)))
        .service(web::resource("/auth/login").route(web::post().to(login)))
        .service(web::resource("/auth/validate").route(web::post().to(validate_token)))
        .with_json_spec_at("/api/spec/v2")
        .build()
}