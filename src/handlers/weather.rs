//! Weather endpoint handler.

use crate::{
    config::HmacConfig,
    models::{WeatherQuery, WeatherResponse, McpResponse},
    services::{
        auth::hmac_signature_middleware, 
        rate_limit::{rate_limit_middleware, SimpleRateLimiter},
        weather::WeatherService,
    },
    middleware::extract_mcp_context,
};
use actix_web::{web, Error, HttpRequest, Result};
use paperclip::actix::api_v2_operation;

/// Weather endpoint
/// 
/// Returns current weather information as an emoji for a given location.
/// Accepts either ZIP code or latitude/longitude coordinates.
/// For MCP-aware clients, the response will include context metadata.
#[api_v2_operation(
    summary = "Weather Information Endpoint",
    description = "Returns current weather information with emoji representation for a given location. Accepts either ZIP code (e.g., ?zip=90210) or latitude/longitude coordinates (e.g., ?lat=34.05&lon=-118.25). MCP-aware clients receive enriched responses with context metadata.",
    tags("Weather"),
    parameters(
        ("zip" = Option<String>, Query, description = "ZIP code (e.g., 90210)"),
        ("lat" = Option<f64>, Query, description = "Latitude coordinate"),
        ("lon" = Option<f64>, Query, description = "Longitude coordinate"),
    ),
    responses(
        (status = 200, description = "Successful response", body = McpResponse<WeatherResponse>),
        (status = 400, description = "Bad Request - Invalid or missing location parameters"),
        (status = 401, description = "Unauthorized - Invalid or missing HMAC signature"),
        (status = 429, description = "Too Many Requests"),
        (status = 500, description = "Internal Server Error - Weather service unavailable")
    )
)]
pub async fn weather(
    req: HttpRequest,
    query: web::Query<WeatherQuery>,
) -> Result<web::Json<McpResponse<WeatherResponse>>, Error> {
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
        // Apply rate limiting to weather endpoint
        if let Err(_response) = rate_limit_middleware(&req, limiter) {
            return Err(actix_web::error::ErrorTooManyRequests(
                "Rate limit exceeded. Please try again later.",
            ));
        }
    }

    // Validate query parameters
    let (location, weather_condition, emoji) = if let Some(zip) = &query.zip {
        // Use ZIP code
        if zip.is_empty() {
            return Err(actix_web::error::ErrorBadRequest(
                "ZIP code cannot be empty",
            ));
        }
        get_weather_by_zip(zip).await?
    } else if let (Some(lat), Some(lon)) = (query.lat, query.lon) {
        // Use coordinates
        if !(-90.0..=90.0).contains(&lat) {
            return Err(actix_web::error::ErrorBadRequest(
                "Latitude must be between -90 and 90",
            ));
        }
        if !(-180.0..=180.0).contains(&lon) {
            return Err(actix_web::error::ErrorBadRequest(
                "Longitude must be between -180 and 180",
            ));
        }
        get_weather_by_coords(lat, lon).await?
    } else {
        return Err(actix_web::error::ErrorBadRequest(
            "Either 'zip' or both 'lat' and 'lon' parameters are required",
        ));
    };

    let weather_data = WeatherResponse {
        location,
        weather: weather_condition,
        emoji,
    };

    // Check if this is an MCP-aware request
    let response = if let Some(context) = extract_mcp_context(&req) {
        tracing::debug!(
            trace_id = %context.trace_id,
            location = %weather_data.location,
            "Returning MCP-enhanced weather response"
        );
        McpResponse::with_context(weather_data, context)
    } else {
        tracing::trace!("Returning standard weather response");
        McpResponse::new(weather_data)
    };

    Ok(web::Json(response))
}

/// Helper function to get weather by ZIP code
async fn get_weather_by_zip(zip: &str) -> Result<(String, String, String), Error> {
    let mut weather_service = WeatherService::new()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Weather service initialization failed: {e}")))?;
    
    weather_service.get_weather_by_zip(zip).await
        .map_err(|e| {
            tracing::error!("Weather API error for ZIP {}: {}", zip, e);
            actix_web::error::ErrorInternalServerError("Weather service temporarily unavailable")
        })
}

/// Helper function to get weather by coordinates
async fn get_weather_by_coords(lat: f64, lon: f64) -> Result<(String, String, String), Error> {
    let mut weather_service = WeatherService::new()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Weather service initialization failed: {e}")))?;
    
    weather_service.get_weather_by_coords(lat, lon).await
        .map_err(|e| {
            tracing::error!("Weather API error for coords ({}, {}): {}", lat, lon, e);
            actix_web::error::ErrorInternalServerError("Weather service temporarily unavailable")
        })
}