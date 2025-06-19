//! HTTP request handlers for API endpoints.
//!
//! This module contains all the HTTP request handlers that process
//! incoming requests and generate responses.

pub mod health;
pub mod version;
pub mod metrics;
pub mod auth;
pub mod openapi;

pub use health::*;
pub use version::*;
pub use metrics::*;
pub use auth::*;
pub use openapi::*;