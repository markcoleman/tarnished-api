//! Version information endpoint handler.

use crate::{
    config::HmacConfig,
    models::VersionResponse,
    services::{auth::hmac_signature_middleware, rate_limit::{rate_limit_middleware, SimpleRateLimiter}},
};
use actix_web::{web, Error, HttpRequest, Result};
use paperclip::actix::api_v2_operation;

/// Version information endpoint
/// 
/// Returns the current API version, commit hash, and build time.
/// This endpoint includes rate limiting and optional HMAC signature validation.
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