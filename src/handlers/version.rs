//! Version information endpoint handler.

use crate::{
    config::HmacConfig,
    middleware::extract_mcp_context,
    models::{McpResponse, VersionResponse},
    services::{
        auth::hmac_signature_middleware,
        rate_limit::{SimpleRateLimiter, rate_limit_middleware},
    },
};
use actix_web::{Error, HttpRequest, Result, web};
use paperclip::actix::api_v2_operation;

/// Version information endpoint
///
/// Returns the current API version, commit hash, and build time.
/// This endpoint includes rate limiting and optional HMAC signature validation.
/// For MCP-aware clients, the response will include context metadata.
#[api_v2_operation(
    summary = "Version Information Endpoint",
    description = "Returns the current API version, commit hash, and build time. MCP-aware clients receive enriched responses with context metadata.",
    tags("Version"),
    responses(
        (status = 200, description = "Successful response", body = McpResponse<VersionResponse>),
        (status = 401, description = "Unauthorized - Invalid or missing HMAC signature"),
        (status = 429, description = "Too Many Requests")
    )
)]
pub async fn version(req: HttpRequest) -> Result<web::Json<McpResponse<VersionResponse>>, Error> {
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

    let version_data = VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("VERGEN_GIT_SHA").to_string(),
        build_time: env!("VERGEN_BUILD_TIMESTAMP").to_string(),
    };

    // Check if this is an MCP-aware request
    let response = if let Some(context) = extract_mcp_context(&req) {
        tracing::debug!(
            trace_id = %context.trace_id,
            "Returning MCP-enhanced version response"
        );
        McpResponse::with_context(version_data, context)
    } else {
        tracing::trace!("Returning standard version response");
        McpResponse::new(version_data)
    };

    Ok(web::Json(response))
}
