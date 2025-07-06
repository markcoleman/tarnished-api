//! Log analysis and summarization data models.

use chrono::{DateTime, Utc};
use paperclip::actix::Apiv2Schema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for AI summarization service
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct AiSummarizerConfig {
    /// AI service provider (openai, mock)
    pub provider: String,
    /// API key for external AI service
    pub api_key: Option<String>,
    /// Base URL for API service
    pub base_url: Option<String>,
    /// Enable/disable AI summarization
    pub enabled: bool,
    /// Timeout for AI requests in seconds
    pub timeout_seconds: u64,
}

impl Default for AiSummarizerConfig {
    fn default() -> Self {
        Self {
            provider: "mock".to_string(),
            api_key: None,
            base_url: None,
            enabled: true,
            timeout_seconds: 30,
        }
    }
}

impl AiSummarizerConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            provider: std::env::var("AI_SUMMARIZER_PROVIDER")
                .unwrap_or_else(|_| "mock".to_string()),
            api_key: std::env::var("AI_SUMMARIZER_API_KEY").ok(),
            base_url: std::env::var("AI_SUMMARIZER_BASE_URL").ok(),
            enabled: std::env::var("AI_SUMMARIZER_ENABLED")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            timeout_seconds: std::env::var("AI_SUMMARIZER_TIMEOUT")
                .and_then(|v| v.parse().map_err(|_| std::env::VarError::NotPresent))
                .unwrap_or(30),
        }
    }
}

/// Aggregated log statistics for a time period (internal use)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStatistics {
    /// Total number of requests
    pub total_requests: u64,
    /// Number of successful requests (2xx status codes)
    pub successful_requests: u64,
    /// Number of error requests (4xx/5xx status codes)
    pub error_requests: u64,
    /// Top endpoints by request count
    pub top_endpoints: HashMap<String, u64>,
    /// Error breakdown by status code
    pub error_breakdown: HashMap<u16, u64>,
    /// Top user agents
    pub top_user_agents: HashMap<String, u64>,
    /// Unique IP addresses
    pub unique_ips: u64,
    /// Time range analyzed (internal use with DateTime)
    pub time_range: TimeRangeInternal,
}

/// Internal time range using DateTime 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRangeInternal {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl From<TimeRangeInternal> for TimeRange {
    fn from(internal: TimeRangeInternal) -> Self {
        TimeRange {
            start: internal.start.to_rfc3339(),
            end: internal.end.to_rfc3339(),
        }
    }
}

/// Time range for log analysis
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct TimeRange {
    /// Start time in ISO 8601 format
    pub start: String,
    /// End time in ISO 8601 format  
    pub end: String,
}

/// AI-generated summary response
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct LogSummaryResponse {
    /// AI-generated summary paragraph
    pub summary: String,
    /// Top endpoints hit
    pub top_endpoints: Vec<EndpointStat>,
    /// Error analysis
    pub errors: ErrorAnalysis,
    /// Traffic analysis
    pub traffic: TrafficAnalysis,
    /// Metadata about the analysis
    pub metadata: SummaryMetadata,
}

/// Statistics for a specific endpoint
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct EndpointStat {
    pub endpoint: String,
    pub count: u64,
    pub percentage: f64,
}

/// Error analysis breakdown
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct ErrorAnalysis {
    pub total_errors: u64,
    pub error_rate: f64,
    pub top_errors: Vec<ErrorStat>,
    pub anomalies_detected: Vec<String>,
}

/// Statistics for specific error types
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct ErrorStat {
    pub status_code: u16,
    pub count: u64,
    pub description: String,
}

/// Traffic analysis data
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct TrafficAnalysis {
    pub total_requests: u64,
    pub requests_per_hour: f64,
    pub peak_hour: Option<String>,
    pub unique_clients: u64,
    pub top_user_agents: Vec<UserAgentStat>,
}

/// User agent statistics
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct UserAgentStat {
    pub user_agent: String,
    pub count: u64,
}

/// Metadata about the summary generation
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct SummaryMetadata {
    /// When the summary was generated (ISO 8601 format)
    pub generated_at: String,
    pub time_range: TimeRange,
    pub ai_provider: String,
    pub processing_mode: String, // "real-time" or "batch"
    pub data_sources: Vec<String>,
}

/// Raw log entry for parsing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub target: Option<String>,
    pub message: String,
    pub fields: Option<HashMap<String, serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_ai_summarizer_config_defaults() {
        let config = AiSummarizerConfig::default();
        assert_eq!(config.provider, "mock");
        assert!(config.enabled);
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_log_summary_response_serialization() {
        let summary = LogSummaryResponse {
            summary: "Test summary".to_string(),
            top_endpoints: vec![EndpointStat {
                endpoint: "/api/health".to_string(),
                count: 100,
                percentage: 50.0,
            }],
            errors: ErrorAnalysis {
                total_errors: 10,
                error_rate: 5.0,
                top_errors: vec![],
                anomalies_detected: vec![],
            },
            traffic: TrafficAnalysis {
                total_requests: 200,
                requests_per_hour: 8.3,
                peak_hour: Some("14:00".to_string()),
                unique_clients: 25,
                top_user_agents: vec![],
            },
            metadata: SummaryMetadata {
                generated_at: Utc::now().to_rfc3339(),
                time_range: TimeRange {
                    start: Utc::now().to_rfc3339(),
                    end: Utc::now().to_rfc3339(),
                },
                ai_provider: "mock".to_string(),
                processing_mode: "real-time".to_string(),
                data_sources: vec!["structured_logs".to_string()],
            },
        };

        let json = serde_json::to_string(&summary).unwrap();
        let _deserialized: LogSummaryResponse = serde_json::from_str(&json).unwrap();
    }
}