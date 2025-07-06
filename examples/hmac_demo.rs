#!/usr/bin/env cargo
//! HMAC Signature Demo
//!
//! This example demonstrates how to generate and validate HMAC signatures
//! for the Tarnished API. Run with:
//!
//! ```
//! cargo run --example hmac_demo
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Generate HMAC-SHA256 signature for the given payload and timestamp
fn generate_signature(secret: &str, payload: &str, timestamp: u64) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Invalid secret key: {e}"))?;

    let message = format!("{timestamp}.{payload}");
    mac.update(message.as_bytes());

    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

fn main() {
    println!("🔐 Tarnished API HMAC Signature Demo");
    println!("=====================================\n");

    // Demo configuration
    let secret = "my-secret-key";
    let payload = ""; // Empty payload for GET requests
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    println!("Configuration:");
    println!("  Secret: {secret}");
    println!("  Payload: '{payload}' (empty for GET requests)");
    println!("  Timestamp: {timestamp}");

    // Generate signature
    match generate_signature(secret, payload, timestamp) {
        Ok(signature) => {
            println!("\n✅ Generated Signature:");
            println!("  X-Signature: {signature}");
            println!("  X-Timestamp: {timestamp}");

            println!("\n📋 Example curl command:");
            println!("curl -H 'X-Signature: {signature}' \\");
            println!("     -H 'X-Timestamp: {timestamp}' \\");
            println!("     http://localhost:8080/api/health");

            println!("\n🔍 Message for signature (format: timestamp.payload):");
            println!("  '{timestamp}.{payload}'");

            println!("\n⚙️  To enable HMAC validation, set environment variables:");
            println!("  export HMAC_REQUIRE_SIGNATURE=true");
            println!("  export HMAC_SECRET={secret}");

            println!("\n📚 Additional configuration options:");
            println!("  export HMAC_TIMESTAMP_TOLERANCE=300  # 5 minutes tolerance");
        }
        Err(e) => {
            println!("❌ Error generating signature: {e}");
        }
    }
}
