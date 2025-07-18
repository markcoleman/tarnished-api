//! Business logic and service layer modules.
//!
//! This module contains the core business logic of the application,
//! including authentication services, metrics collection, rate limiting,
//! and resilient HTTP client capabilities.

pub mod ai_summarizer;
pub mod auth;
pub mod log_analyzer;
pub mod metrics;
pub mod rate_limit;
pub mod resilient_client;
pub mod suspicious_activity;
pub mod weather;

pub use ai_summarizer::*;
pub use auth::*;
pub use log_analyzer::*;
pub use metrics::*;
pub use rate_limit::*;
pub use resilient_client::*;
pub use suspicious_activity::*;
pub use weather::*;