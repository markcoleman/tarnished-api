//! HTTP utility functions for extracting request information.

use actix_web::HttpRequest;

/// Extract client IP address from request headers
///
/// Attempts to extract the real client IP from various proxy headers,
/// falling back to the connection remote address.
pub fn extract_client_ip(req: &HttpRequest) -> String {
    // Check for common proxy headers in order of preference
    let ip_headers = [
        "X-Forwarded-For",
        "X-Real-IP",
        "CF-Connecting-IP", // Cloudflare
        "X-Cluster-Client-IP",
        "X-Forwarded",
        "Forwarded-For",
        "Forwarded",
    ];

    for header_name in &ip_headers {
        if let Some(header_value) = req.headers().get(*header_name) {
            if let Ok(header_str) = header_value.to_str() {
                // X-Forwarded-For can contain multiple IPs, take the first one
                let ip = header_str.split(',').next().unwrap_or(header_str).trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    // Fall back to connection remote address
    req.connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string()
}

/// Extract user agent from request headers
pub fn extract_user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}
