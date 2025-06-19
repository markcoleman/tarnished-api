//! Audit logging data structures and types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Types of authentication events for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEventType {
    LoginSuccess,
    LoginFailure,
    TokenValidationSuccess,
    TokenValidationFailure,
    SuspiciousActivity,
    RateLimitExceeded,
}

/// Outcomes of authentication events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEventOutcome {
    Success,
    Failure,
}

/// Structured audit log entry for authentication events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAuditEvent {
    pub event_type: AuthEventType,
    pub outcome: AuthEventOutcome,
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub user_id: Option<String>,
    pub method: String,
    pub endpoint: String,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub additional_context: Option<String>,
}

impl AuthAuditEvent {
    /// Create a new audit event with basic information
    pub fn new(
        event_type: AuthEventType,
        outcome: AuthEventOutcome,
        ip_address: String,
        method: String,
        endpoint: String,
    ) -> Self {
        Self {
            event_type,
            outcome,
            timestamp: Utc::now(),
            ip_address,
            user_agent: None,
            user_id: None,
            method,
            endpoint,
            session_id: None,
            request_id: None,
            additional_context: None,
        }
    }

    /// Add user agent information
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Add user ID information
    pub fn with_user_id(mut self, user_id: Option<String>) -> Self {
        self.user_id = user_id;
        self
    }

    /// Add session ID information
    pub fn with_session_id(mut self, session_id: Option<String>) -> Self {
        self.session_id = session_id;
        self
    }

    /// Add request ID information
    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }

    /// Add additional context information
    pub fn with_context(mut self, context: Option<String>) -> Self {
        self.additional_context = context;
        self
    }

    /// Add additional details information (alias for with_context for compatibility)
    pub fn with_details(mut self, details: Option<String>) -> Self {
        self.additional_context = details;
        self
    }

    /// Log the audit event using structured logging
    pub fn log(&self) {
        info!(
            target: "auth_audit",
            event_type = ?self.event_type,
            outcome = ?self.outcome,
            timestamp = %self.timestamp,
            ip_address = %self.ip_address,
            user_agent = ?self.user_agent,
            user_id = ?self.user_id,
            method = %self.method,
            endpoint = %self.endpoint,
            session_id = ?self.session_id,
            request_id = ?self.request_id,
            additional_context = ?self.additional_context,
            "Authentication audit event"
        );
    }
}