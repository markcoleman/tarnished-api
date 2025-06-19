//! Suspicious activity tracking and monitoring service.

use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Tracks suspicious authentication activity by IP address
/// 
/// This service monitors failed authentication attempts and can identify
/// potentially malicious activity patterns.
pub struct SuspiciousActivityTracker {
    failed_attempts: Arc<Mutex<HashMap<String, (usize, Instant)>>>,
    max_failures: usize,
    window_seconds: u64,
}

impl Default for SuspiciousActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SuspiciousActivityTracker {
    /// Create a new suspicious activity tracker with environment-based configuration
    pub fn new() -> Self {
        let max_failures = env::var("AUTH_MAX_FAILURES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let window_seconds = env::var("AUTH_FAILURE_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300); // 5 minutes

        Self {
            failed_attempts: Arc::new(Mutex::new(HashMap::new())),
            max_failures,
            window_seconds,
        }
    }

    /// Record a failed authentication attempt for the given IP
    /// 
    /// Returns `true` if this IP has reached the suspicious threshold,
    /// `false` if it's still within acceptable limits.
    pub fn record_failure(&self, ip: &str) -> bool {
        let mut attempts = self.failed_attempts.lock().unwrap();
        let now = Instant::now();

        // Clean up old entries
        attempts.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < Duration::from_secs(self.window_seconds)
        });

        match attempts.get_mut(ip) {
            Some((count, timestamp)) => {
                if now.duration_since(*timestamp) < Duration::from_secs(self.window_seconds) {
                    *count += 1;
                    *count >= self.max_failures
                } else {
                    *count = 1;
                    *timestamp = now;
                    false
                }
            }
            None => {
                attempts.insert(ip.to_string(), (1, now));
                false
            }
        }
    }

    /// Check if the given IP address has suspicious activity patterns
    /// 
    /// Returns `true` if the IP has exceeded the failure threshold
    /// within the configured time window.
    pub fn is_suspicious(&self, ip: &str) -> bool {
        let attempts = self.failed_attempts.lock().unwrap();
        if let Some((count, timestamp)) = attempts.get(ip) {
            let now = Instant::now();
            if now.duration_since(*timestamp) < Duration::from_secs(self.window_seconds) {
                return *count >= self.max_failures;
            }
        }
        false
    }
}