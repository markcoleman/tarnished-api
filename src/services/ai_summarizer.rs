//! AI-powered log summarization service.

use crate::models::logs::{
    AiSummarizerConfig, ErrorAnalysis, ErrorStat, EndpointStat, LogStatistics, LogSummaryResponse,
    SummaryMetadata, TrafficAnalysis, UserAgentStat,
};
use crate::services::resilient_client::{ResilientClient, ResilientClientConfig};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// AI-powered log summarization service
pub struct AiSummarizer {
    config: AiSummarizerConfig,
    client: Option<ResilientClient>,
}

impl AiSummarizer {
    /// Create a new AI summarizer instance
    pub fn new(config: AiSummarizerConfig) -> Result<Self, String> {
        let client = if config.enabled && config.provider != "mock" {
            let client_config = ResilientClientConfig::default();
            Some(
                ResilientClient::new(client_config, None)
                    .map_err(|e| format!("Failed to create HTTP client: {e}"))?,
            )
        } else {
            None
        };

        Ok(Self { config, client })
    }

    /// Generate a comprehensive summary of log statistics
    pub async fn summarize_logs(
        &self,
        statistics: &LogStatistics,
        processing_mode: &str,
    ) -> Result<LogSummaryResponse, String> {
        info!(
            provider = %self.config.provider,
            enabled = self.config.enabled,
            total_requests = statistics.total_requests,
            "Generating AI summary"
        );

        // Generate AI summary text
        let summary_text = if self.config.enabled {
            match self.config.provider.as_str() {
                "openai" => self.generate_openai_summary(statistics).await?,
                "mock" => self.generate_mock_summary(statistics),
                _ => {
                    warn!(provider = %self.config.provider, "Unknown AI provider, using mock");
                    self.generate_mock_summary(statistics)
                }
            }
        } else {
            "AI summarization is disabled. Raw statistics available in response data.".to_string()
        };

        // Build comprehensive response
        let response = LogSummaryResponse {
            summary: summary_text,
            top_endpoints: self.build_endpoint_stats(statistics),
            errors: self.build_error_analysis(statistics),
            traffic: self.build_traffic_analysis(statistics),
            metadata: SummaryMetadata {
                generated_at: Utc::now().to_rfc3339(),
                time_range: statistics.time_range.clone().into(),
                ai_provider: self.config.provider.clone(),
                processing_mode: processing_mode.to_string(),
                data_sources: vec!["structured_logs".to_string(), "audit_events".to_string()],
            },
        };

        debug!("AI summary generation completed");
        Ok(response)
    }

    /// Generate summary using OpenAI API
    async fn generate_openai_summary(&self, statistics: &LogStatistics) -> Result<String, String> {
        let _client = self.client.as_ref()
            .ok_or("HTTP client not initialized for OpenAI")?;

        let api_key = self.config.api_key.as_ref()
            .ok_or("OpenAI API key not configured")?;

        let base_url = self.config.base_url.as_deref()
            .unwrap_or("https://api.openai.com/v1");

        // Build prompt with log statistics
        let prompt = self.build_ai_prompt(statistics);

        let request_body = json!({
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a technical analyst specializing in API traffic analysis. Provide concise, professional summaries of API usage patterns."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 200,
            "temperature": 0.3
        });

        let url = format!("{base_url}/chat/completions");
        
        // Use reqwest directly for OpenAI API call since ResilientClient doesn't support headers
        let http_client = reqwest::Client::new();
        let response = http_client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| format!("OpenAI API request failed: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(format!("OpenAI API error {status}: {text}"));
        }

        let response_data: Value = response.json().await
            .map_err(|e| format!("Failed to parse OpenAI response: {e}"))?;

        let summary = response_data
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or("Invalid OpenAI response format")?;

        Ok(summary.trim().to_string())
    }

    /// Generate mock summary for testing and fallback
    fn generate_mock_summary(&self, statistics: &LogStatistics) -> String {
        let hours = (statistics.time_range.end - statistics.time_range.start).num_hours();
        let avg_requests_per_hour = if hours > 0 {
            statistics.total_requests as f64 / hours as f64
        } else {
            0.0
        };

        let error_rate = if statistics.total_requests > 0 {
            (statistics.error_requests as f64 / statistics.total_requests as f64) * 100.0
        } else {
            0.0
        };

        let top_endpoint = statistics
            .top_endpoints
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(endpoint, _)| endpoint.as_str())
            .unwrap_or("unknown");

        let peak_analysis = if avg_requests_per_hour > 100.0 {
            "with high traffic volume"
        } else if avg_requests_per_hour > 50.0 {
            "with moderate traffic"
        } else {
            "with light traffic"
        };

        let error_analysis = if error_rate > 10.0 {
            format!(" High error rate detected ({error_rate:.1}%) requiring attention.")
        } else if error_rate > 5.0 {
            format!(" Moderate error rate ({error_rate:.1}%) observed.")
        } else {
            format!(" Low error rate ({error_rate:.1}%), system operating normally.")
        };

        format!(
            "API traffic analysis for the last {hours} hours shows {total_requests} total requests {peak_analysis} \
            averaging {avg_requests_per_hour:.1} requests per hour. Most requests targeted '{top_endpoint}' endpoint. \
            {unique_ips} unique clients accessed the API.{error_analysis}",
            total_requests = statistics.total_requests,
            unique_ips = statistics.unique_ips,
        )
    }

    /// Build AI prompt from log statistics
    fn build_ai_prompt(&self, statistics: &LogStatistics) -> String {
        let hours = (statistics.time_range.end - statistics.time_range.start).num_hours();
        
        format!(
            "Analyze the following API traffic data for the last {hours} hours and provide a concise summary:\n\n\
            Total Requests: {total_requests}\n\
            Successful: {successful_requests}\n\
            Errors: {error_requests}\n\
            Unique IPs: {unique_ips}\n\
            Top Endpoints: {top_endpoints:?}\n\
            Error Breakdown: {error_breakdown:?}\n\n\
            Please provide a 2-3 sentence summary highlighting key patterns, traffic volume, \
            main endpoints used, and any notable error rates or anomalies.",
            total_requests = statistics.total_requests,
            successful_requests = statistics.successful_requests,
            error_requests = statistics.error_requests,
            unique_ips = statistics.unique_ips,
            top_endpoints = statistics.top_endpoints.iter().take(3).collect::<HashMap<_, _>>(),
            error_breakdown = statistics.error_breakdown
        )
    }

    /// Build endpoint statistics for response
    fn build_endpoint_stats(&self, statistics: &LogStatistics) -> Vec<EndpointStat> {
        let mut endpoint_stats: Vec<_> = statistics
            .top_endpoints
            .iter()
            .map(|(endpoint, count)| {
                let percentage = if statistics.total_requests > 0 {
                    (*count as f64 / statistics.total_requests as f64) * 100.0
                } else {
                    0.0
                };
                EndpointStat {
                    endpoint: endpoint.clone(),
                    count: *count,
                    percentage,
                }
            })
            .collect();

        endpoint_stats.sort_by(|a, b| b.count.cmp(&a.count));
        endpoint_stats.into_iter().take(10).collect()
    }

    /// Build error analysis for response
    fn build_error_analysis(&self, statistics: &LogStatistics) -> ErrorAnalysis {
        let error_rate = if statistics.total_requests > 0 {
            (statistics.error_requests as f64 / statistics.total_requests as f64) * 100.0
        } else {
            0.0
        };

        let top_errors: Vec<_> = statistics
            .error_breakdown
            .iter()
            .map(|(status_code, count)| ErrorStat {
                status_code: *status_code,
                count: *count,
                description: self.get_status_description(*status_code),
            })
            .collect();

        let mut anomalies = Vec::new();
        if error_rate > 10.0 {
            anomalies.push("High error rate detected".to_string());
        }
        if statistics.error_breakdown.get(&500).unwrap_or(&0) > &0 {
            anomalies.push("Server errors (5xx) detected".to_string());
        }

        ErrorAnalysis {
            total_errors: statistics.error_requests,
            error_rate,
            top_errors,
            anomalies_detected: anomalies,
        }
    }

    /// Build traffic analysis for response
    fn build_traffic_analysis(&self, statistics: &LogStatistics) -> TrafficAnalysis {
        let hours = (statistics.time_range.end - statistics.time_range.start).num_hours();
        let requests_per_hour = if hours > 0 {
            statistics.total_requests as f64 / hours as f64
        } else {
            0.0
        };

        let top_user_agents: Vec<_> = statistics
            .top_user_agents
            .iter()
            .map(|(user_agent, count)| UserAgentStat {
                user_agent: user_agent.clone(),
                count: *count,
            })
            .collect();

        TrafficAnalysis {
            total_requests: statistics.total_requests,
            requests_per_hour,
            peak_hour: Some("14:00".to_string()), // Mock data - would calculate from real logs
            unique_clients: statistics.unique_ips,
            top_user_agents,
        }
    }

    /// Get human-readable description for HTTP status codes
    fn get_status_description(&self, status_code: u16) -> String {
        match status_code {
            400 => "Bad Request".to_string(),
            401 => "Unauthorized".to_string(),
            403 => "Forbidden".to_string(),
            404 => "Not Found".to_string(),
            429 => "Too Many Requests".to_string(),
            500 => "Internal Server Error".to_string(),
            502 => "Bad Gateway".to_string(),
            503 => "Service Unavailable".to_string(),
            _ => format!("HTTP {status_code}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::logs::TimeRangeInternal;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    fn create_test_statistics() -> LogStatistics {
        let mut top_endpoints = HashMap::new();
        top_endpoints.insert("/api/health".to_string(), 100);
        top_endpoints.insert("/api/weather".to_string(), 50);
        top_endpoints.insert("/auth/login".to_string(), 25);

        let mut error_breakdown = HashMap::new();
        error_breakdown.insert(400, 5);
        error_breakdown.insert(401, 3);
        error_breakdown.insert(500, 1);

        let mut top_user_agents = HashMap::new();
        top_user_agents.insert("curl/7.68.0".to_string(), 80);
        top_user_agents.insert("Mozilla/5.0".to_string(), 60);

        let end_time = Utc::now();
        let start_time = end_time - Duration::hours(24);

        LogStatistics {
            total_requests: 200,
            successful_requests: 191,
            error_requests: 9,
            top_endpoints,
            error_breakdown,
            top_user_agents,
            unique_ips: 25,
            time_range: TimeRangeInternal {
                start: start_time,
                end: end_time,
            },
        }
    }

    #[test]
    fn test_ai_summarizer_creation() {
        let config = AiSummarizerConfig::default();
        let summarizer = AiSummarizer::new(config);
        assert!(summarizer.is_ok());
    }

    #[tokio::test]
    async fn test_mock_summary_generation() {
        let config = AiSummarizerConfig {
            provider: "mock".to_string(),
            enabled: true,
            ..Default::default()
        };
        let summarizer = AiSummarizer::new(config).unwrap();
        let statistics = create_test_statistics();

        let result = summarizer.summarize_logs(&statistics, "real-time").await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert!(!summary.summary.is_empty());
        assert!(!summary.top_endpoints.is_empty());
        assert_eq!(summary.errors.total_errors, 9);
        assert_eq!(summary.traffic.total_requests, 200);
        assert_eq!(summary.metadata.processing_mode, "real-time");
    }

    #[test]
    fn test_build_endpoint_stats() {
        let config = AiSummarizerConfig::default();
        let summarizer = AiSummarizer::new(config).unwrap();
        let statistics = create_test_statistics();

        let endpoint_stats = summarizer.build_endpoint_stats(&statistics);
        assert!(!endpoint_stats.is_empty());
        
        // Should be sorted by count (descending)
        assert_eq!(endpoint_stats[0].endpoint, "/api/health");
        assert_eq!(endpoint_stats[0].count, 100);
        assert_eq!(endpoint_stats[0].percentage, 50.0);
    }

    #[test]
    fn test_build_error_analysis() {
        let config = AiSummarizerConfig::default();
        let summarizer = AiSummarizer::new(config).unwrap();
        let statistics = create_test_statistics();

        let error_analysis = summarizer.build_error_analysis(&statistics);
        assert_eq!(error_analysis.total_errors, 9);
        assert_eq!(error_analysis.error_rate, 4.5);
        assert!(!error_analysis.top_errors.is_empty());
    }

    #[test]
    fn test_status_description() {
        let config = AiSummarizerConfig::default();
        let summarizer = AiSummarizer::new(config).unwrap();

        assert_eq!(summarizer.get_status_description(400), "Bad Request");
        assert_eq!(summarizer.get_status_description(401), "Unauthorized");
        assert_eq!(summarizer.get_status_description(500), "Internal Server Error");
        assert_eq!(summarizer.get_status_description(999), "HTTP 999");
    }
}