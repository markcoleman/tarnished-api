//! Log summarization endpoint handlers.

use crate::models::logs::{AiSummarizerConfig, LogSummaryResponse};
use crate::services::{AiSummarizer, LogAnalyzer};
use crate::utils::http::extract_client_ip;
use actix_web::{Error, HttpRequest, Result, web};
use paperclip::actix::{Apiv2Schema, api_v2_operation};
use serde::Deserialize;
use tracing::{error, info, warn};

/// Query parameters for log summary endpoint
#[derive(Debug, Deserialize, Apiv2Schema)]
pub struct LogSummaryQuery {
    /// Processing mode: "real-time" or "batch"
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Number of hours to analyze (default: 24)
    #[serde(default = "default_hours")]
    pub hours: u64,
}

fn default_mode() -> String {
    "real-time".to_string()
}

fn default_hours() -> u64 {
    24
}

/// AI-powered log summarization endpoint
///
/// This internal endpoint provides AI-generated summaries of API request logs
/// from the specified time period. It analyzes traffic patterns, error rates,
/// and provides insights into API usage trends.
#[api_v2_operation(
    summary = "AI Log Summarization",
    description = "Generate AI-powered summary of request logs and usage patterns",
    tags("Logs"),
    responses(
        (status = 200, description = "Log summary generated successfully", body = LogSummaryResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Access forbidden - internal use only"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn logs_summary(
    req: HttpRequest,
    query: web::Query<LogSummaryQuery>,
) -> Result<web::Json<LogSummaryResponse>, Error> {
    let ip_address = extract_client_ip(&req);

    info!(
        mode = %query.mode,
        hours = query.hours,
        ip = %ip_address,
        "Log summary request received"
    );

    // Basic internal access control - in production this would use proper authentication
    if !is_internal_request(&req) {
        warn!(
            ip = %ip_address,
            "Unauthorized access attempt to logs summary endpoint"
        );
        return Err(actix_web::error::ErrorForbidden(
            "This endpoint is for internal use only",
        ));
    }

    // Validate parameters
    if query.hours == 0 || query.hours > 168 {
        // Max 1 week
        return Err(actix_web::error::ErrorBadRequest(
            "Hours parameter must be between 1 and 168 (1 week)",
        ));
    }

    if query.mode != "real-time" && query.mode != "batch" {
        return Err(actix_web::error::ErrorBadRequest(
            "Mode must be 'real-time' or 'batch'",
        ));
    }

    // Initialize services
    let log_analyzer = LogAnalyzer::new();
    let ai_config = AiSummarizerConfig::from_env();
    let ai_summarizer = match AiSummarizer::new(ai_config) {
        Ok(summarizer) => summarizer,
        Err(e) => {
            error!(error = %e, "Failed to initialize AI summarizer");
            return Err(actix_web::error::ErrorInternalServerError(
                "AI summarization service unavailable",
            ));
        }
    };

    // Analyze logs
    let log_statistics = if query.hours == 24 {
        log_analyzer.analyze_last_24_hours().await
    } else {
        let end_time = chrono::Utc::now();
        let start_time = end_time - chrono::Duration::hours(query.hours as i64);
        log_analyzer.analyze_time_range(start_time, end_time).await
    };

    let statistics = match log_statistics {
        Ok(stats) => stats,
        Err(e) => {
            error!(error = %e, "Failed to analyze logs");
            return Err(actix_web::error::ErrorInternalServerError(
                "Log analysis failed",
            ));
        }
    };

    // Generate AI summary
    let summary = match ai_summarizer.summarize_logs(&statistics, &query.mode).await {
        Ok(summary) => summary,
        Err(e) => {
            error!(error = %e, "Failed to generate AI summary");
            return Err(actix_web::error::ErrorInternalServerError(
                "AI summarization failed",
            ));
        }
    };

    info!(
        total_requests = summary.traffic.total_requests,
        error_rate = summary.errors.error_rate,
        top_endpoint = summary
            .top_endpoints
            .first()
            .map(|e| e.endpoint.as_str())
            .unwrap_or("none"),
        "Log summary generated successfully"
    );

    Ok(web::Json(summary))
}

/// Check if the request is from an internal source
/// In production, this would implement proper authentication/authorization
fn is_internal_request(req: &HttpRequest) -> bool {
    // Check for internal API key header
    if let Some(api_key) = req.headers().get("X-Internal-API-Key")
        && let Ok(key_str) = api_key.to_str()
    {
        let expected_key =
            std::env::var("INTERNAL_API_KEY").unwrap_or_else(|_| "dev-internal-key".to_string());
        return key_str == expected_key;
    }

    // Check if request is from localhost/internal networks
    let ip = extract_client_ip(req);
    ip.starts_with("127.")
        || ip.starts_with("::1")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test};

    #[actix_web::test]
    async fn test_logs_summary_unauthorized() {
        let app =
            test::init_service(App::new().route("/api/logs/summary", web::get().to(logs_summary)))
                .await;

        // Request from external IP without API key
        let req = test::TestRequest::get()
            .uri("/api/logs/summary")
            .insert_header(("X-Forwarded-For", "203.0.113.1")) // External IP
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[actix_web::test]
    async fn test_logs_summary_with_api_key() {
        unsafe {
            std::env::set_var("INTERNAL_API_KEY", "test-key");
        }

        let app =
            test::init_service(App::new().route("/api/logs/summary", web::get().to(logs_summary)))
                .await;

        let req = test::TestRequest::get()
            .uri("/api/logs/summary")
            .insert_header(("X-Internal-API-Key", "test-key"))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn test_logs_summary_invalid_hours() {
        unsafe {
            std::env::set_var("INTERNAL_API_KEY", "test-key");
        }

        let app =
            test::init_service(App::new().route("/api/logs/summary", web::get().to(logs_summary)))
                .await;

        let req = test::TestRequest::get()
            .uri("/api/logs/summary?hours=0")
            .insert_header(("X-Internal-API-Key", "test-key"))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn test_logs_summary_invalid_mode() {
        unsafe {
            std::env::set_var("INTERNAL_API_KEY", "test-key");
        }

        let app =
            test::init_service(App::new().route("/api/logs/summary", web::get().to(logs_summary)))
                .await;

        let req = test::TestRequest::get()
            .uri("/api/logs/summary?mode=invalid")
            .insert_header(("X-Internal-API-Key", "test-key"))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }
}
