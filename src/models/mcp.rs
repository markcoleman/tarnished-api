//! Model Context Protocol (MCP) data structures and response wrappers.
//!
//! This module provides support for optional MCP metadata that can be included
//! in API responses for context-aware clients while maintaining backward compatibility
//! with standard REST clients.

use chrono::Utc;
use paperclip::actix::Apiv2Schema;
use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

/// Context metadata for MCP-aware requests and responses
///
/// This structure contains trace information, model versioning, and timing data
/// that enables context-aware interactions between clients and the API.
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct ContextMetadata {
    /// Unique trace identifier for request tracking
    pub trace_id: String,
    /// API/model version information
    pub model_version: String,
    /// Timestamp when the context was created (ISO 8601 format)
    pub timestamp: String,
    /// Optional correlation ID for linking related requests
    pub correlation_id: Option<String>,
    /// Optional client identifier
    pub client_id: Option<String>,
}

impl ContextMetadata {
    /// Create new context metadata with generated trace ID
    pub fn new() -> Self {
        Self {
            trace_id: Uuid::new_v4().to_string(),
            model_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now().to_rfc3339(),
            correlation_id: None,
            client_id: None,
        }
    }

    /// Create context metadata from request headers
    pub fn from_headers(
        trace_id: Option<String>,
        client_id: Option<String>,
        correlation_id: Option<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            model_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now().to_rfc3339(),
            correlation_id,
            client_id,
        }
    }
}

impl Default for ContextMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// MCP-enhanced response wrapper
///
/// This structure wraps standard API responses with optional MCP context metadata.
/// When MCP context is not present, only the data is serialized directly, maintaining
/// backward compatibility with REST clients.
#[derive(Debug, Clone, Deserialize, Apiv2Schema)]
pub struct McpResponse<T> {
    /// The actual response data
    pub data: T,
    /// Optional MCP context metadata (included only for MCP-aware clients)
    pub context: Option<ContextMetadata>,
}

impl<T> McpResponse<T> {
    /// Create a new MCP response with data only (for REST clients)
    pub fn new(data: T) -> Self {
        Self {
            data,
            context: None,
        }
    }

    /// Create a new MCP response with context metadata (for MCP clients)
    pub fn with_context(data: T, context: ContextMetadata) -> Self {
        Self {
            data,
            context: Some(context),
        }
    }

    /// Convert into the inner data, discarding context
    pub fn into_data(self) -> T {
        self.data
    }

    /// Get a reference to the inner data
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Check if this response has MCP context
    pub fn has_context(&self) -> bool {
        self.context.is_some()
    }
}

impl<T> Serialize for McpResponse<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(ref context) = self.context {
            // MCP mode: serialize with wrapper
            use serde::ser::SerializeStruct;
            let mut state = serializer.serialize_struct("McpResponse", 2)?;
            state.serialize_field("data", &self.data)?;
            state.serialize_field("context", context)?;
            state.end()
        } else {
            // REST mode: serialize data directly for backward compatibility
            self.data.serialize(serializer)
        }
    }
}

impl<T> From<T> for McpResponse<T> {
    fn from(data: T) -> Self {
        Self::new(data)
    }
}

/// Trait for converting regular responses to MCP-enhanced responses
pub trait ToMcpResponse<T> {
    /// Convert to MCP response without context (REST mode)
    fn to_mcp_response(self) -> McpResponse<T>;

    /// Convert to MCP response with context (MCP mode)
    fn to_mcp_response_with_context(self, context: ContextMetadata) -> McpResponse<T>;
}

impl<T> ToMcpResponse<T> for T {
    fn to_mcp_response(self) -> McpResponse<T> {
        McpResponse::new(self)
    }

    fn to_mcp_response_with_context(self, context: ContextMetadata) -> McpResponse<T> {
        McpResponse::with_context(self, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::HealthResponse;

    #[test]
    fn test_context_metadata_creation() {
        let context = ContextMetadata::new();
        assert!(!context.trace_id.is_empty());
        assert_eq!(context.model_version, env!("CARGO_PKG_VERSION"));
        assert!(context.correlation_id.is_none());
        assert!(context.client_id.is_none());
    }

    #[test]
    fn test_context_metadata_from_headers() {
        let trace_id = Some("test-trace-123".to_string());
        let client_id = Some("test-client".to_string());
        let correlation_id = Some("corr-456".to_string());

        let context = ContextMetadata::from_headers(
            trace_id.clone(),
            client_id.clone(),
            correlation_id.clone(),
        );

        assert_eq!(context.trace_id, "test-trace-123");
        assert_eq!(context.client_id, Some("test-client".to_string()));
        assert_eq!(context.correlation_id, Some("corr-456".to_string()));
    }

    #[test]
    fn test_mcp_response_rest_serialization() {
        let health = HealthResponse {
            status: "healthy".to_string(),
        };
        let response = McpResponse::new(health);

        assert!(!response.has_context());
        assert_eq!(response.data().status, "healthy");

        // Test serialization - should serialize data directly for REST compatibility
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Should be direct field access, not wrapped in "data"
        assert_eq!(parsed["status"], "healthy");
        assert!(parsed.get("data").is_none());
        assert!(parsed.get("context").is_none());
    }

    #[test]
    fn test_mcp_response_mcp_serialization() {
        let health = HealthResponse {
            status: "healthy".to_string(),
        };
        let context = ContextMetadata::new();
        let response = McpResponse::with_context(health, context.clone());

        assert!(response.has_context());
        assert_eq!(response.data().status, "healthy");

        // Test serialization - should include context wrapper for MCP clients
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Should be wrapped format
        assert_eq!(parsed["data"]["status"], "healthy");
        assert!(parsed["context"].is_object());
        assert_eq!(parsed["context"]["trace_id"], context.trace_id);
    }

    #[test]
    fn test_to_mcp_response_trait() {
        let health = HealthResponse {
            status: "healthy".to_string(),
        };

        // Test without context
        let response = health.clone().to_mcp_response();
        assert!(!response.has_context());

        // Test with context
        let context = ContextMetadata::new();
        let response_with_context = health.to_mcp_response_with_context(context);
        assert!(response_with_context.has_context());
    }

    #[test]
    fn test_from_conversion() {
        let health = HealthResponse {
            status: "healthy".to_string(),
        };
        let response: McpResponse<HealthResponse> = health.into();

        assert!(!response.has_context());
        assert_eq!(response.data().status, "healthy");
    }
}
