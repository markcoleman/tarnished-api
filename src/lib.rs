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
pub mod newrelic;
pub mod services;
pub mod utils;

// Re-export commonly used types and functions for convenience
pub use config::{HmacConfig, MetricsConfig, RateLimitConfig, SecurityHeadersConfig};
pub use handlers::{
    create_base_app, create_openapi_spec, get_metrics, health, login, logs_summary, validate_token,
    version, weather,
};
pub use middleware::{
    extract_mcp_context, metrics_middleware, McpMiddleware, MetricsMiddleware, RequestIdMiddleware,
    SecurityHeaders,
};
pub use models::{
    AiSummarizerConfig, AuthAuditEvent, AuthEventOutcome, AuthEventType, ContextMetadata,
    HealthResponse, LogSummaryResponse, LoginRequest, LoginResponse, McpResponse, ToMcpResponse,
    TokenValidationRequest, TokenValidationResponse, VersionResponse, WeatherQuery,
    WeatherResponse,
};
pub use services::{
    add_response_signature, hmac_signature_middleware, rate_limit_middleware, AiSummarizer,
    AppMetrics, LogAnalyzer, ResilientClient, ResilientClientConfig, ResilientClientError,
    ResilientClientMetrics, SimpleRateLimiter, SuspiciousActivityTracker, WeatherService,
};
pub use utils::{extract_client_ip, extract_route_pattern, extract_user_agent};

// Additional re-exports for backward compatibility with tests
pub use middleware::{MetricsService, RequestIdService, SecurityHeadersMiddleware};
pub use utils::hmac as hmac_utils;
