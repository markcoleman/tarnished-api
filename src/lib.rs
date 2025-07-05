//! Tarnished API - A Rust web API with security, metrics, and authentication
//!
//! This is a sample API built with Actix Web and Paperclip that demonstrates:
//! - RESTful endpoint design
//! - HMAC signature authentication
//! - Prometheus metrics integration
//! - Rate limiting and security headers
//! - Structured audit logging
//! - OpenAPI documentation
//!
//! ## Architecture
//!
//! The codebase is organized into focused modules:
//! - `models/` - Data structures and request/response models
//! - `handlers/` - HTTP request handlers for each endpoint
//! - `middleware/` - Custom middleware for cross-cutting concerns
//! - `services/` - Business logic and core services
//! - `utils/` - Utility functions and helpers
//! - `config/` - Configuration structures and environment loading
//! - `newrelic/` - New Relic integration and observability
//!
//! ## Quick Start
//!
//! ```no_run
//! use tarnished_api::create_base_app;
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let app = create_base_app();
//!     // Configure and run the server
//!     Ok(())
//! }
//! ```

// Core modules
pub mod config;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod services;
pub mod utils;
pub mod newrelic;

// Re-export commonly used types and functions for convenience
pub use config::{MetricsConfig, RateLimitConfig, HmacConfig, SecurityHeadersConfig};
pub use handlers::{health, version, get_metrics, login, validate_token, weather, logs_summary, create_openapi_spec, create_base_app};
pub use middleware::{SecurityHeaders, RequestIdMiddleware, MetricsMiddleware, metrics_middleware, McpMiddleware, extract_mcp_context};
pub use models::{HealthResponse, VersionResponse, WeatherQuery, WeatherResponse, LoginRequest, LoginResponse, TokenValidationRequest, TokenValidationResponse, AuthAuditEvent, AuthEventType, AuthEventOutcome, ContextMetadata, McpResponse, ToMcpResponse, LogSummaryResponse, AiSummarizerConfig};
pub use services::{AppMetrics, SimpleRateLimiter, SuspiciousActivityTracker, WeatherService, rate_limit_middleware, hmac_signature_middleware, add_response_signature, ResilientClient, ResilientClientConfig, ResilientClientMetrics, ResilientClientError, LogAnalyzer, AiSummarizer};
pub use utils::{extract_client_ip, extract_user_agent, extract_route_pattern};

// Additional re-exports for backward compatibility with tests
pub use middleware::{SecurityHeadersMiddleware, RequestIdService, MetricsService};
pub use utils::hmac as hmac_utils;