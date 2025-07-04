//! Log analysis service for parsing and aggregating structured logs.

use crate::models::logs::{LogEntry, LogStatistics, TimeRangeInternal};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Service for analyzing and aggregating log data
pub struct LogAnalyzer {
    /// Whether to include detailed debugging information
    debug_mode: bool,
}

impl LogAnalyzer {
    /// Create a new log analyzer instance
    pub fn new() -> Self {
        let debug_mode = std::env::var("LOG_ANALYZER_DEBUG")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        Self { debug_mode }
    }

    /// Analyze logs from the last 24 hours
    pub async fn analyze_last_24_hours(&self) -> Result<LogStatistics, String> {
        let end_time = Utc::now();
        let start_time = end_time - Duration::hours(24);
        
        self.analyze_time_range(start_time, end_time).await
    }

    /// Analyze logs for a specific time range
    pub async fn analyze_time_range(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<LogStatistics, String> {
        info!(
            start = %start_time,
            end = %end_time,
            "Analyzing logs for time range"
        );

        // In a real implementation, this would read from actual log files or a logging service
        // For now, we'll simulate log analysis based on audit events and structured logs
        let log_entries = self.collect_log_entries(start_time, end_time).await?;
        
        let statistics = self.aggregate_statistics(&log_entries, start_time, end_time);
        
        info!(
            total_requests = statistics.total_requests,
            successful_requests = statistics.successful_requests,
            error_requests = statistics.error_requests,
            unique_ips = statistics.unique_ips,
            "Log analysis completed"
        );

        Ok(statistics)
    }

    /// Collect log entries from various sources
    async fn collect_log_entries(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<LogEntry>, String> {
        // In a real implementation, this would:
        // 1. Read from structured log files (JSON format)
        // 2. Query a logging service like New Relic, Loki, or Elasticsearch
        // 3. Parse application-specific log formats
        
        // For now, we'll generate some mock data for demonstration
        let mock_entries = self.generate_mock_log_entries(start_time, end_time);
        
        debug!(
            count = mock_entries.len(),
            "Collected log entries"
        );

        Ok(mock_entries)
    }

    /// Generate mock log entries for testing and demonstration
    fn generate_mock_log_entries(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Vec<LogEntry> {
        let mut entries = Vec::new();
        let duration = end_time - start_time;
        let num_entries = (duration.num_hours() * 50) as usize; // ~50 requests per hour

        for i in 0..num_entries {
            let timestamp = start_time + Duration::seconds(
                (duration.num_seconds() * i as i64) / num_entries as i64
            );

            // Simulate different types of requests
            let (endpoint, status_code, method) = match i % 20 {
                0..=10 => ("/api/health", 200, "GET"),
                11..=15 => ("/api/weather", 200, "GET"),
                16 => ("/api/weather", 400, "GET"), // Bad request
                17 => ("/auth/login", 200, "POST"),
                18 => ("/auth/login", 401, "POST"), // Failed login
                _ => ("/api/version", 200, "GET"),
            };

            let user_agent = match i % 4 {
                0 => "curl/7.68.0",
                1 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                2 => "PostmanRuntime/7.28.4",
                _ => "weather-bot/1.0",
            };

            let ip_address = format!("192.168.1.{}", (i % 254) + 1);

            let mut fields = HashMap::new();
            fields.insert("method".to_string(), Value::String(method.to_string()));
            fields.insert("endpoint".to_string(), Value::String(endpoint.to_string()));
            fields.insert("status".to_string(), Value::Number(status_code.into()));
            fields.insert("ip_address".to_string(), Value::String(ip_address));
            fields.insert("user_agent".to_string(), Value::String(user_agent.to_string()));
            fields.insert("duration_ms".to_string(), Value::Number((i % 500 + 10).into()));

            entries.push(LogEntry {
                timestamp,
                level: if status_code >= 400 { "WARN".to_string() } else { "INFO".to_string() },
                target: Some("http_request".to_string()),
                message: format!("{} {} -> {}", method, endpoint, status_code),
                fields: Some(fields),
            });
        }

        entries
    }

    /// Aggregate log entries into statistics
    fn aggregate_statistics(
        &self,
        entries: &[LogEntry],
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> LogStatistics {
        let mut total_requests = 0;
        let mut successful_requests = 0;
        let mut error_requests = 0;
        let mut top_endpoints = HashMap::new();
        let mut error_breakdown = HashMap::new();
        let mut top_user_agents = HashMap::new();
        let mut unique_ips = std::collections::HashSet::new();

        for entry in entries {
            if let Some(fields) = &entry.fields {
                total_requests += 1;

                // Extract status code
                if let Some(status) = fields.get("status").and_then(|v| v.as_u64()) {
                    let status_code = status as u16;
                    if status_code >= 200 && status_code < 400 {
                        successful_requests += 1;
                    } else if status_code >= 400 {
                        error_requests += 1;
                        *error_breakdown.entry(status_code).or_insert(0) += 1;
                    }
                }

                // Extract endpoint
                if let Some(endpoint) = fields.get("endpoint").and_then(|v| v.as_str()) {
                    *top_endpoints.entry(endpoint.to_string()).or_insert(0) += 1;
                }

                // Extract user agent
                if let Some(user_agent) = fields.get("user_agent").and_then(|v| v.as_str()) {
                    *top_user_agents.entry(user_agent.to_string()).or_insert(0) += 1;
                }

                // Extract IP address
                if let Some(ip) = fields.get("ip_address").and_then(|v| v.as_str()) {
                    unique_ips.insert(ip.to_string());
                }
            }
        }

        LogStatistics {
            total_requests,
            successful_requests,
            error_requests,
            top_endpoints,
            error_breakdown,
            top_user_agents,
            unique_ips: unique_ips.len() as u64,
            time_range: TimeRangeInternal {
                start: start_time,
                end: end_time,
            },
        }
    }
}

impl Default for LogAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_analyzer_creation() {
        let analyzer = LogAnalyzer::new();
        assert!(!analyzer.debug_mode); // Default should be false
    }

    #[tokio::test]
    async fn test_analyze_time_range() {
        let analyzer = LogAnalyzer::new();
        let end_time = Utc::now();
        let start_time = end_time - Duration::hours(1);

        let result = analyzer.analyze_time_range(start_time, end_time).await;
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert!(stats.total_requests > 0);
        assert!(stats.top_endpoints.len() > 0);
        assert_eq!(stats.time_range.start, start_time);
        assert_eq!(stats.time_range.end, end_time);
    }

    #[tokio::test]
    async fn test_analyze_last_24_hours() {
        let analyzer = LogAnalyzer::new();
        let result = analyzer.analyze_last_24_hours().await;
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert!(stats.total_requests > 0);
        assert!(stats.successful_requests > 0);
        assert!(stats.unique_ips > 0);
        
        // Should have some common endpoints
        assert!(stats.top_endpoints.contains_key("/api/health"));
    }

    #[test]
    fn test_generate_mock_log_entries() {
        let analyzer = LogAnalyzer::new();
        let end_time = Utc::now();
        let start_time = end_time - Duration::hours(2);
        
        let entries = analyzer.generate_mock_log_entries(start_time, end_time);
        assert!(!entries.is_empty());
        
        // Check that entries are within the time range
        for entry in &entries {
            assert!(entry.timestamp >= start_time);
            assert!(entry.timestamp <= end_time);
        }

        // Check that we have fields
        if let Some(first_entry) = entries.first() {
            assert!(first_entry.fields.is_some());
            let fields = first_entry.fields.as_ref().unwrap();
            assert!(fields.contains_key("method"));
            assert!(fields.contains_key("endpoint"));
            assert!(fields.contains_key("status"));
        }
    }
}