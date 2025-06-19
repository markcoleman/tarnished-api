//! Metrics endpoint handler.

use crate::{
    config::MetricsConfig,
    services::AppMetrics,
};
use actix_web::{web, Error, HttpRequest, HttpResponse, Result};
use paperclip::actix::api_v2_operation;

/// Prometheus metrics endpoint
/// 
/// Returns Prometheus-formatted metrics for monitoring API performance
/// and usage patterns. This endpoint is typically scraped by monitoring systems.
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
        // Use the metrics service's render method
        match metrics.render() {
            Ok(metrics_output) => Ok(HttpResponse::Ok()
                .content_type("text/plain; version=0.0.4; charset=utf-8")
                .body(metrics_output)),
            Err(e) => Err(actix_web::error::ErrorInternalServerError(format!(
                "Failed to render metrics: {}",
                e
            ))),
        }
    } else {
        Err(actix_web::error::ErrorServiceUnavailable(
            "Metrics not available",
        ))
    }
}