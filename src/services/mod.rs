//! Business logic and service layer modules.
//!
//! This module contains the core business logic of the application,
//! including authentication services, metrics collection, rate limiting,
//! and resilient HTTP client capabilities.

pub mod auth;
pub mod metrics;
pub mod rate_limit;
pub mod resilient_client;
pub mod suspicious_activity;

pub use auth::*;
pub use metrics::*;
pub use rate_limit::*;
pub use resilient_client::*;
pub use suspicious_activity::*;