//! HTTP request handlers for API endpoints.
//!
//! This module contains all the HTTP request handlers that process
//! incoming requests and generate responses.

pub mod auth;
pub mod health;
pub mod logs;
pub mod metrics;
pub mod openapi;
pub mod version;
pub mod weather;

pub use auth::*;
pub use health::*;
pub use logs::*;
pub use metrics::*;
pub use openapi::*;
pub use version::*;
pub use weather::*;