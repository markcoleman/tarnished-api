//! Health check endpoint handler.

use crate::{
    config::HmacConfig,
    middleware::extract_mcp_context,
    models::{HealthResponse, McpResponse},
    services::auth::hmac_signature_middleware,
};
use actix_web::{Error, HttpRequest, Result, web};
use paperclip::actix::api_v2_operation;

/// Health check endpoint
///
/// Returns the current health status of the API. This endpoint can be used
/// by load balancers, monitoring systems, and health check probes.
///
/// For MCP-aware clients, the response will include context metadata.
#[api_v2_operation(
    summary = "Health Check Endpoint",
    description = "Returns the current health status of the API in JSON format. MCP-aware clients receive enriched responses with context metadata.",
    tags("Health"),
    responses(
        (status = 200, description = "Successful response", body = McpResponse<HealthResponse>),
        (status = 401, description = "Unauthorized - Invalid or missing HMAC signature")
    )
)]
pub async fn health(req: HttpRequest) -> Result<web::Json<McpResponse<HealthResponse>>, Error> {
    // Check if HMAC config is available and validate signature
    if let Some(hmac_config) = req.app_data::<web::Data<HmacConfig>>() {
        // For GET requests, the body is typically empty
        if let Err(_response) = hmac_signature_middleware(&req, "", hmac_config) {
            return Err(actix_web::error::ErrorUnauthorized(
                "Invalid or missing HMAC signature",
            ));
        }
    }

    let health_data = HealthResponse {
        status: "healthy".to_string(),
    };

    // Check if this is an MCP-aware request
    let response = if let Some(context) = extract_mcp_context(&req) {
        tracing::debug!(
            trace_id = %context.trace_id,
            "Returning MCP-enhanced health response"
        );
        McpResponse::with_context(health_data, context)
    } else {
        tracing::trace!("Returning standard health response");
        McpResponse::new(health_data)
    };

    Ok(web::Json(response))
}
