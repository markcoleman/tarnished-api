#!/usr/bin/env cargo
//! API Client Demo
//!
//! This example demonstrates how to interact with the Tarnished API
//! from a Rust client application. Run with:
//!
//! ```
//! cargo run --example api_client
//! ```

use reqwest::Client;
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📡 Tarnished API Client Demo");
    println!("============================\n");

    let client = Client::new();
    let base_url = "http://localhost:8080";

    // Test health endpoint
    println!("🏥 Testing health endpoint...");
    match test_endpoint(&client, &format!("{}/api/health", base_url)).await {
        Ok(response) => println!("✅ Health check: {}\n", response),
        Err(e) => {
            println!("❌ Health check failed: {}", e);
            println!("💡 Make sure the server is running: just dev\n");
            return Err(e);
        }
    }

    // Test version endpoint
    println!("📋 Testing version endpoint...");
    match test_endpoint(&client, &format!("{}/api/version", base_url)).await {
        Ok(response) => {
            println!("✅ Version info received:");
            if let Ok(json) = serde_json::from_str::<Value>(&response) {
                if let Some(obj) = json.as_object() {
                    for (key, value) in obj {
                        println!("   {}: {}", key, value);
                    }
                }
            }
            println!();
        }
        Err(e) => println!("❌ Version check failed: {}\n", e),
    }

    // Test weather endpoint with different parameters
    println!("🌤️  Testing weather endpoint...");

    let weather_tests = vec![
        ("lat=34.05&lon=-118.25", "Los Angeles coordinates"),
        ("zip=90210", "Beverly Hills ZIP code"),
        ("lat=40.71&lon=-74.01", "New York coordinates"),
    ];

    for (params, description) in weather_tests {
        println!("   Testing: {} ({})", description, params);
        let url = format!("{}/api/weather?{}", base_url, params);
        match test_endpoint(&client, &url).await {
            Ok(response) => {
                if let Ok(json) = serde_json::from_str::<Value>(&response) {
                    if let Some(location) = json.get("location") {
                        if let Some(weather) = json.get("weather") {
                            if let Some(emoji) = json.get("emoji") {
                                println!("     ✅ {}: {} {}", location, weather, emoji);
                            }
                        }
                    }
                }
            }
            Err(e) => println!("     ❌ Failed: {}", e),
        }
    }

    println!("\n🎯 Demo complete!");
    println!("💡 Try making requests with different parameters:");
    println!("   curl http://localhost:8080/api/weather?lat=51.5&lon=-0.1");
    println!("   curl http://localhost:8080/api/weather?zip=10001");

    Ok(())
}

async fn test_endpoint(client: &Client, url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(format!(
            "HTTP {}: {}",
            response.status(),
            response.status().canonical_reason().unwrap_or("Unknown")
        )
        .into());
    }

    let text = response.text().await?;
    Ok(text)
}
