//! Health check endpoint handler.

use crate::{
    config::HmacConfig,
    models::HealthResponse,
    services::auth::hmac_signature_middleware,
};
use actix_web::{web, Error, HttpRequest, Result};
use paperclip::actix::api_v2_operation;

/// Health check endpoint
/// 
/// Returns the current health status of the API. This endpoint can be used
/// by load balancers, monitoring systems, and health check probes.
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