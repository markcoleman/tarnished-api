#!/usr/bin/env cargo
//! Development Server Demo
//!
//! This example demonstrates how to start a development server with
//! custom configuration for testing and development. Run with:
//!
//! ```
//! cargo run --example dev_server
//! ```

use actix_web::{web, App, HttpServer};
use tarnished_api::{health, version, weather};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Tarnished API Development Server");
    println!("==================================\n");

    // Initialize logging for development
    env_logger::init();

    println!("🔧 Development Configuration:");
    println!("  - Logging: DEBUG level enabled");
    println!("  - HMAC: Disabled for development");
    println!("  - Rate limiting: Disabled for development");
    println!("  - CORS: Permissive for local development\n");

    println!("📋 Available endpoints:");
    println!("  GET  /api/health   - Health check");
    println!("  GET  /api/version  - Version information");
    println!("  GET  /api/weather  - Weather data (mock)\n");

    println!("🌐 Starting server at http://localhost:8080");
    println!("   Press Ctrl+C to stop\n");

    HttpServer::new(|| {
        App::new()
            .route("/api/health", web::get().to(health))
            .route("/api/version", web::get().to(version))
            .route("/api/weather", web::get().to(weather))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}