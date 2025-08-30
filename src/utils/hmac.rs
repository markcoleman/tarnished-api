//! HMAC signature generation and validation utilities.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Generate HMAC-SHA256 signature for the given payload and timestamp
pub fn generate_signature(secret: &str, payload: &str, timestamp: u64) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Invalid secret key: {e}"))?;

    let message = format!("{timestamp}.{payload}");
    mac.update(message.as_bytes());

    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Validate HMAC-SHA256 signature
pub fn validate_signature(
    secret: &str,
    payload: &str,
    timestamp: u64,
    signature: &str,
    tolerance_seconds: u64,
) -> Result<bool, String> {
    // Check timestamp validity first
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {e}"))?
        .as_secs();

    let time_diff = current_time.abs_diff(timestamp);

    if time_diff > tolerance_seconds {
        return Ok(false);
    }

    // Generate expected signature
    let expected_signature = generate_signature(secret, payload, timestamp)?;

    // Compare signatures using constant-time comparison
    let signature_bytes =
        hex::decode(signature).map_err(|_| "Invalid signature format".to_string())?;
    let expected_bytes = hex::decode(expected_signature)
        .map_err(|_| "Invalid expected signature format".to_string())?;

    if signature_bytes.len() != expected_bytes.len() {
        return Ok(false);
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Invalid secret key: {e}"))?;

    mac.update(format!("{timestamp}.{payload}").as_bytes());

    mac.verify_slice(&signature_bytes)
        .map(|_| true)
        .or(Ok(false))
}
