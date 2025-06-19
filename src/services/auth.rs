//! Authentication and authorization services.

use crate::{
    config::HmacConfig,
    utils::hmac,
};
use actix_web::{HttpRequest, HttpResponse};
use std::time::{SystemTime, UNIX_EPOCH};

/// HMAC signature middleware for request validation
/// 
/// This function validates HMAC signatures on incoming requests
/// to ensure request integrity and authenticity.
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
    let signature = req
        .headers()
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Missing X-Signature header"
            }))
        })?;

    let timestamp_str = req
        .headers()
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Missing X-Timestamp header"
            }))
        })?;

    let timestamp: u64 = timestamp_str.parse().map_err(|_| {
        HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized",
            "message": "Invalid X-Timestamp format"
        }))
    })?;

    // Validate signature
    match hmac::validate_signature(
        &config.secret,
        body,
        timestamp,
        signature,
        config.timestamp_tolerance_seconds,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized",
            "message": "Invalid signature or timestamp"
        }))),
        Err(e) => Err(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Internal Server Error",
            "message": format!("Signature validation error: {}", e)
        }))),
    }
}

/// Add HMAC signature to outgoing response
/// 
/// This function adds HMAC signatures to outgoing responses
/// for response integrity verification.
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

    let signature = hmac::generate_signature(&config.secret, body, timestamp)?;

    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-response-signature"),
        actix_web::http::header::HeaderValue::from_str(&signature)
            .map_err(|e| format!("Invalid signature header value: {}", e))?,
    );

    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-response-timestamp"),
        actix_web::http::header::HeaderValue::from_str(&timestamp.to_string())
            .map_err(|e| format!("Invalid timestamp header value: {}", e))?,
    );

    Ok(())
}