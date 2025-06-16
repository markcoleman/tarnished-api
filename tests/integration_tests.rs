use actix_web::{test, http::StatusCode};
use tarnished_api::{create_base_app, RateLimitConfig, SimpleRateLimiter, hmac_utils};
use actix_web::{test, http::StatusCode, App};
use paperclip::actix::{OpenApiExt, web};
use tarnished_api::{create_base_app, create_openapi_spec, health, version, get_metrics, RateLimitConfig, SimpleRateLimiter, MetricsConfig, AppMetrics};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

/// Integration test for the health check endpoint
/// 
/// This test differs from the unit test in that it:
/// - Tests the complete application configuration (OpenAPI spec, middleware stack, etc.)
/// - Uses the full app setup that mirrors the production environment
/// - Provides more comprehensive validation of the HTTP response
/// - Verifies the integration between all application components
/// 
/// This ensures the /api/health endpoint works correctly after any changes or deployments.
#[actix_web::test]
async fn test_health_endpoint_integration() {
    // Ensure HMAC is not required for backward compatibility
    unsafe {
        env::remove_var("HMAC_REQUIRE_SIGNATURE"); // Explicitly remove first
        env::set_var("HMAC_REQUIRE_SIGNATURE", "false");
    }
    
    // Create a test service with the same configuration as the main app
    let app = test::init_service(create_base_app()).await;
    
    // Create a test request to GET /api/health
    let req = test::TestRequest::get().uri("/api/health").to_request();
    let resp = test::call_service(&app, req).await;
    
    // Verify response status is 200 OK
    assert_eq!(resp.status(), StatusCode::OK, "Expected 200 OK status");
    
    // Verify response content type is JSON
    let content_type = resp.headers().get("content-type");
    assert!(content_type.is_some(), "Content-Type header should be present");
    let content_type_str = content_type.unwrap().to_str().unwrap();
    assert!(content_type_str.contains("application/json"), 
            "Expected JSON content type, got: {}", content_type_str);
    
    // Read and parse response body
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    
    // Parse JSON response
    let json: serde_json::Value = serde_json::from_str(body_str)
        .expect("Failed to parse response as JSON");
    
    // Check that the response contains the status field
    assert!(json.is_object(), "Response should be a JSON object");
    let status = json.get("status");
    assert!(status.is_some(), "Response should contain 'status' field");
    
    // Verify the status value is "healthy" (matches what the endpoint returns)
    let status_value = status.unwrap().as_str();
    assert!(status_value.is_some(), "Status should be a string");
    assert_eq!(status_value.unwrap(), "healthy", "Expected status to be 'healthy'");
    
    // Additional check: verify the entire JSON structure matches expectation
    let expected_json: serde_json::Value = serde_json::json!({
        "status": "healthy"
    });
    assert_eq!(json, expected_json, "Response JSON should match expected structure");
    
    // Clean up
    unsafe {
        env::remove_var("HMAC_REQUIRE_SIGNATURE");
    }
}

/// Integration test for the version endpoint
/// 
/// This test verifies that the /api/version endpoint:
/// - Returns a 200 OK status
/// - Returns a JSON response with version, commit, and build_time fields
/// - Integrates properly with the complete application configuration
/// 
/// This ensures the /api/version endpoint works correctly after any changes or deployments.
#[actix_web::test]
async fn test_version_endpoint_integration() {
    // Ensure HMAC is not required for backward compatibility
    unsafe {
        env::set_var("HMAC_REQUIRE_SIGNATURE", "false");
    }
    
    // Create a test service with the same configuration as the main app
    let app = test::init_service(create_base_app()).await;
    
    // Create a test request to GET /api/version
    let req = test::TestRequest::get().uri("/api/version").to_request();
    let resp = test::call_service(&app, req).await;
    
    // Verify response status is 200 OK
    assert_eq!(resp.status(), StatusCode::OK, "Expected 200 OK status");
    
    // Verify response content type is JSON
    let content_type = resp.headers().get("content-type");
    assert!(content_type.is_some(), "Content-Type header should be present");
    let content_type_str = content_type.unwrap().to_str().unwrap();
    assert!(content_type_str.contains("application/json"), 
            "Expected JSON content type, got: {}", content_type_str);
    
    // Read and parse response body
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    
    // Parse JSON response
    let json: serde_json::Value = serde_json::from_str(body_str)
        .expect("Failed to parse response as JSON");
    
    // Check that the response contains the required fields
    assert!(json.is_object(), "Response should be a JSON object");
    
    let version = json.get("version");
    assert!(version.is_some(), "Response should contain 'version' field");
    assert!(version.unwrap().is_string(), "Version should be a string");
    
    let commit = json.get("commit");
    assert!(commit.is_some(), "Response should contain 'commit' field");
    assert!(commit.unwrap().is_string(), "Commit should be a string");
    
    let build_time = json.get("build_time");
    assert!(build_time.is_some(), "Response should contain 'build_time' field");
    assert!(build_time.unwrap().is_string(), "Build time should be a string");
    
    // Verify that the version matches the package version
    let version_value = version.unwrap().as_str().unwrap();
    assert_eq!(version_value, "0.1.0", "Expected version to match package version");
    
    // Clean up
    unsafe {
        env::remove_var("HMAC_REQUIRE_SIGNATURE");
    }
}

/// Integration test for rate limiting functionality
/// 
/// This test verifies that:
/// - Version endpoint is subject to rate limiting
/// - Health endpoint is exempt from rate limiting
/// - Proper 429 Too Many Requests response is returned when limit is exceeded
#[actix_web::test]
async fn test_rate_limiting_integration() {
    // Set a very low rate limit for testing
    unsafe {
        env::set_var("RATE_LIMIT_RPM", "2");
        env::set_var("RATE_LIMIT_PERIOD", "60");
        env::set_var("HMAC_REQUIRE_SIGNATURE", "false"); // Disable HMAC for this test
    }
    
    // Create a test service with rate limiting enabled
    let app = test::init_service(create_base_app()).await;
    
    // Test version endpoint - should work for first few requests
    let req1 = test::TestRequest::get().uri("/api/version").to_request();
    let resp1 = test::call_service(&app, req1).await;
    assert_eq!(resp1.status(), StatusCode::OK, "First request should succeed");
    
    let req2 = test::TestRequest::get().uri("/api/version").to_request();
    let resp2 = test::call_service(&app, req2).await;
    assert_eq!(resp2.status(), StatusCode::OK, "Second request should succeed");
    
    // Third request should be rate limited
    let req3 = test::TestRequest::get().uri("/api/version").to_request();
    let resp3 = test::call_service(&app, req3).await;
    assert_eq!(resp3.status(), StatusCode::TOO_MANY_REQUESTS, "Third request should be rate limited");
    
    // Verify the error response
    let body = test::read_body(resp3).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.contains("Too Many Requests") || body_str.contains("Rate limit exceeded"), 
            "Response should contain rate limit error message: {}", body_str);
    
    // Health endpoint should NOT be rate limited
    let health_req1 = test::TestRequest::get().uri("/api/health").to_request();
    let health_resp1 = test::call_service(&app, health_req1).await;
    assert_eq!(health_resp1.status(), StatusCode::OK, "Health endpoint should not be rate limited");
    
    let health_req2 = test::TestRequest::get().uri("/api/health").to_request();
    let health_resp2 = test::call_service(&app, health_req2).await;
    assert_eq!(health_resp2.status(), StatusCode::OK, "Health endpoint should still work");
    
    let health_req3 = test::TestRequest::get().uri("/api/health").to_request();
    let health_resp3 = test::call_service(&app, health_req3).await;
    assert_eq!(health_resp3.status(), StatusCode::OK, "Health endpoint should continue to work");
    
    // Clean up environment variables
    unsafe {
        env::remove_var("RATE_LIMIT_RPM");
        env::remove_var("RATE_LIMIT_PERIOD");
        env::remove_var("HMAC_REQUIRE_SIGNATURE");
    }
}

/// Unit test for rate limiter functionality
#[actix_web::test]
async fn test_rate_limiter_unit() {
    let config = RateLimitConfig {
        requests_per_minute: 2,
        period_seconds: 60,
    };
    let limiter = SimpleRateLimiter::new(config);
    
    // First two requests should succeed
    assert!(limiter.check_rate_limit("test_ip"), "First request should succeed");
    assert!(limiter.check_rate_limit("test_ip"), "Second request should succeed");
    
    // Third request should fail
    assert!(!limiter.check_rate_limit("test_ip"), "Third request should be rate limited");
    
    // Different IP should work fine
    assert!(limiter.check_rate_limit("different_ip"), "Different IP should not be rate limited");
}

/// Unit tests for HMAC signature functionality
#[actix_web::test]
async fn test_hmac_signature_generation() {
    let secret = "test-secret-key";
    let payload = "test payload";
    let timestamp = 1234567890u64;
    
    // Test signature generation
    let signature = hmac_utils::generate_signature(secret, payload, timestamp)
        .expect("Signature generation should succeed");
    
    assert!(!signature.is_empty(), "Signature should not be empty");
    assert_eq!(signature.len(), 64, "HMAC-SHA256 signature should be 64 hex characters");
    
    // Test that same inputs produce same signature
    let signature2 = hmac_utils::generate_signature(secret, payload, timestamp)
        .expect("Second signature generation should succeed");
    
    assert_eq!(signature, signature2, "Same inputs should produce same signature");
    
    // Test that different inputs produce different signatures
    let signature3 = hmac_utils::generate_signature(secret, "different payload", timestamp)
        .expect("Third signature generation should succeed");
    
    assert_ne!(signature, signature3, "Different payloads should produce different signatures");
}

/// Unit tests for HMAC signature validation
#[actix_web::test]
async fn test_hmac_signature_validation() {
    let secret = "test-secret-key";
    let payload = "test payload";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Generate a valid signature
    let signature = hmac_utils::generate_signature(secret, payload, timestamp)
        .expect("Should generate signature");
    
    // Test valid signature
    let result = hmac_utils::validate_signature(secret, payload, timestamp, &signature, 300)
        .expect("Validation should not error");
    assert!(result, "Valid signature should pass validation");
    
    // Test invalid signature
    let invalid_signature = "0000000000000000000000000000000000000000000000000000000000000000";
    let result = hmac_utils::validate_signature(secret, payload, timestamp, invalid_signature, 300)
        .expect("Validation should not error");
    assert!(!result, "Invalid signature should fail validation");
    
    // Test expired timestamp
    let old_timestamp = timestamp - 400; // 400 seconds ago, beyond 300 second tolerance
    let old_signature = hmac_utils::generate_signature(secret, payload, old_timestamp)
        .expect("Should generate signature");
    let result = hmac_utils::validate_signature(secret, payload, old_timestamp, &old_signature, 300)
        .expect("Validation should not error");
    assert!(!result, "Expired timestamp should fail validation");
    
    // Test future timestamp (within tolerance)
    let future_timestamp = timestamp + 100; // 100 seconds in future, within 300 second tolerance
    let future_signature = hmac_utils::generate_signature(secret, payload, future_timestamp)
        .expect("Should generate signature");
    let result = hmac_utils::validate_signature(secret, payload, future_timestamp, &future_signature, 300)
        .expect("Validation should not error");
    assert!(result, "Future timestamp within tolerance should pass validation");
}

/// Integration test for HMAC signature middleware when not required
#[actix_web::test]
async fn test_hmac_middleware_not_required() {
    // Ensure HMAC is not required for this test
    unsafe {
        env::remove_var("HMAC_REQUIRE_SIGNATURE"); // Explicitly remove first
        env::set_var("HMAC_REQUIRE_SIGNATURE", "false");
    }
    
    // Create app AFTER setting environment variables
    let app = test::init_service(create_base_app()).await;
    
    // Request without signature headers should succeed when HMAC not required
    let req = test::TestRequest::get().uri("/api/health").to_request();
    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK, "Request should succeed when HMAC not required");
    
    // Clean up
    unsafe {
        env::remove_var("HMAC_REQUIRE_SIGNATURE");
    }
}

/// Integration test for HMAC signature middleware when required but missing headers
#[actix_web::test]
async fn test_hmac_middleware_required_missing_headers() {
    // Configure HMAC to be required
    unsafe {
        env::set_var("HMAC_REQUIRE_SIGNATURE", "true");
        env::set_var("HMAC_SECRET", "test-secret-for-integration");
    }
    
    // Create app AFTER setting environment variables
    let app = test::init_service(create_base_app()).await;
    
    // Request without signature headers should fail when HMAC required
    let req = test::TestRequest::get().uri("/api/health").to_request();
    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Request should fail when HMAC required but missing headers");
    
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.contains("Invalid or missing HMAC signature"), 
            "Error message should mention invalid or missing HMAC signature, got: {}", body_str);
    
    // Clean up
    unsafe {
        env::remove_var("HMAC_REQUIRE_SIGNATURE");
        env::remove_var("HMAC_SECRET");
    }
}

/// Integration test for HMAC signature middleware with valid signature
#[actix_web::test]
async fn test_hmac_middleware_valid_signature() {
    let secret = "test-secret-for-integration";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Configure HMAC to be required
    unsafe {
        env::set_var("HMAC_REQUIRE_SIGNATURE", "true");
        env::set_var("HMAC_SECRET", secret);
    }
    
    // Create app AFTER setting environment variables
    let app = test::init_service(create_base_app()).await;
    
    // For GET requests, the body is typically empty
    let payload = "";
    let signature = hmac_utils::generate_signature(secret, payload, timestamp)
        .expect("Should generate signature");
    
    // Request with valid signature headers should succeed
    let req = test::TestRequest::get()
        .uri("/api/health")
        .insert_header(("X-Signature", signature.as_str()))
        .insert_header(("X-Timestamp", timestamp.to_string()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK, "Request should succeed with valid signature");
    
    // Clean up
    unsafe {
        env::remove_var("HMAC_REQUIRE_SIGNATURE");
        env::remove_var("HMAC_SECRET");
    }
}

/// Integration test for HMAC signature middleware with invalid signature
#[actix_web::test]
async fn test_hmac_middleware_invalid_signature() {
    let secret = "test-secret-for-integration";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Configure HMAC to be required
    unsafe {
        env::set_var("HMAC_REQUIRE_SIGNATURE", "true");
        env::set_var("HMAC_SECRET", secret);
    }
    
    // Create app AFTER setting environment variables
    let app = test::init_service(create_base_app()).await;
    
    // Use invalid signature
    let invalid_signature = "0000000000000000000000000000000000000000000000000000000000000000";
    
    // Request with invalid signature should fail
    let req = test::TestRequest::get()
        .uri("/api/health")
        .insert_header(("X-Signature", invalid_signature))
        .insert_header(("X-Timestamp", timestamp.to_string()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Request should fail with invalid signature");
    
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.contains("Invalid or missing HMAC signature"), 
            "Error message should mention invalid or missing HMAC signature, got: {}", body_str);
    
    // Clean up
    unsafe {
        env::remove_var("HMAC_REQUIRE_SIGNATURE");
        env::remove_var("HMAC_SECRET");
    }
}
/// Unit test for response signature functionality
#[actix_web::test]
async fn test_response_signature_functionality() {
    use tarnished_api::{HmacConfig, add_response_signature, hmac_utils};
    use actix_web::HttpResponse;
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let config = HmacConfig {
        secret: "test-secret".to_string(),
        timestamp_tolerance_seconds: 300,
        require_signature: false,
    };
    
    let response_body = r#"{"status":"healthy"}"#;
    let mut response = HttpResponse::Ok().json(serde_json::json!({"status":"healthy"}));
    
    // Add signature to response
    let result = add_response_signature(&mut response, response_body, &config);
    assert!(result.is_ok(), "Should be able to add response signature");
    
    // Check that signature headers were added
    let headers = response.headers();
    let signature_header = headers.get("x-signature");
    let timestamp_header = headers.get("x-timestamp");
    
    assert!(signature_header.is_some(), "Response should have X-Signature header");
    assert!(timestamp_header.is_some(), "Response should have X-Timestamp header");
    
    // Verify the signature is valid
    let signature = signature_header.unwrap().to_str().unwrap();
    let timestamp_str = timestamp_header.unwrap().to_str().unwrap();
    let timestamp: u64 = timestamp_str.parse().expect("Should parse timestamp");
    
    let is_valid = hmac_utils::validate_signature(
        &config.secret,
        response_body,
        timestamp,
        signature,
        300
    ).expect("Should validate signature");
    
    assert!(is_valid, "Generated response signature should be valid");
    
    // Check timestamp is recent (within last minute)
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let time_diff = if current_time > timestamp {
        current_time - timestamp
    } else {
        timestamp - current_time
    };
    assert!(time_diff < 60, "Timestamp should be recent (within 60 seconds)");
/// Integration test for security headers on health endpoint
/// 
/// This test verifies that:
/// - All required security headers are present in the response
/// - Headers have the correct values
/// - CSP header is present by default
#[actix_web::test]
async fn test_security_headers_health_endpoint() {
    // Ensure CSP is enabled for this test by explicitly setting the env var
    unsafe {
        env::set_var("SECURITY_CSP_ENABLED", "true");
    }
    
    // Create a test service with the same configuration as the main app
    let app = test::init_service(create_base_app()).await;
    
    // Create a test request to GET /api/health
    let req = test::TestRequest::get().uri("/api/health").to_request();
    let resp = test::call_service(&app, req).await;
    
    // Verify response status is 200 OK
    assert_eq!(resp.status(), StatusCode::OK);
    
    let headers = resp.headers();
    
    // Verify X-Content-Type-Options header
    let content_type_options = headers.get("x-content-type-options");
    assert!(content_type_options.is_some(), "X-Content-Type-Options header should be present");
    assert_eq!(content_type_options.unwrap().to_str().unwrap(), "nosniff");
    
    // Verify X-Frame-Options header
    let frame_options = headers.get("x-frame-options");
    assert!(frame_options.is_some(), "X-Frame-Options header should be present");
    assert_eq!(frame_options.unwrap().to_str().unwrap(), "DENY");
    
    // Verify X-XSS-Protection header
    let xss_protection = headers.get("x-xss-protection");
    assert!(xss_protection.is_some(), "X-XSS-Protection header should be present");
    assert_eq!(xss_protection.unwrap().to_str().unwrap(), "1; mode=block");
    
    // Verify Referrer-Policy header
    let referrer_policy = headers.get("referrer-policy");
    assert!(referrer_policy.is_some(), "Referrer-Policy header should be present");
    assert_eq!(referrer_policy.unwrap().to_str().unwrap(), "no-referrer");
    
    // Verify Content-Security-Policy header (should be present when enabled)
    let csp = headers.get("content-security-policy");
    
    // Debug: print all headers if CSP is missing
    if csp.is_none() {
        eprintln!("CSP header is missing. All headers:");
        for (name, value) in headers.iter() {
            eprintln!("  {}: {:?}", name, value);
        }
    }
    
    assert!(csp.is_some(), "Content-Security-Policy header should be present when enabled");
    assert_eq!(csp.unwrap().to_str().unwrap(), "default-src 'none'; frame-ancestors 'none'");
    
    // Clean up environment variable
    unsafe {
        env::remove_var("SECURITY_CSP_ENABLED");
    }
}

/// Integration test for security headers on version endpoint
/// 
/// This test verifies that security headers are also applied to API endpoints
#[actix_web::test]
async fn test_security_headers_version_endpoint() {
    // Ensure CSP is enabled for this test
    unsafe {
        env::set_var("SECURITY_CSP_ENABLED", "true");
    }
    
    // Create a test service with the same configuration as the main app
    let app = test::init_service(create_base_app()).await;
    
    // Create a test request to GET /api/version
    let req = test::TestRequest::get().uri("/api/version").to_request();
    let resp = test::call_service(&app, req).await;
    
    // Verify response status is 200 OK
    assert_eq!(resp.status(), StatusCode::OK);
    
    let headers = resp.headers();
    
    // Verify all security headers are present
    assert!(headers.get("x-content-type-options").is_some(), "X-Content-Type-Options header should be present");
    assert!(headers.get("x-frame-options").is_some(), "X-Frame-Options header should be present");
    assert!(headers.get("x-xss-protection").is_some(), "X-XSS-Protection header should be present");
    assert!(headers.get("referrer-policy").is_some(), "Referrer-Policy header should be present");
    assert!(headers.get("content-security-policy").is_some(), "Content-Security-Policy header should be present");
    
    // Clean up environment variable
    unsafe {
        env::remove_var("SECURITY_CSP_ENABLED");
    }
}

/// Integration test for CSP toggle functionality
/// 
/// This test verifies that CSP can be disabled via environment variable
#[actix_web::test]
async fn test_csp_disabled() {
    // Disable CSP for this test
    unsafe {
        env::set_var("SECURITY_CSP_ENABLED", "false");
    }
    
    // Create a test service with CSP disabled
    let app = test::init_service(create_base_app()).await;
    
    // Create a test request to GET /api/health
    let req = test::TestRequest::get().uri("/api/health").to_request();
    let resp = test::call_service(&app, req).await;
    
    // Verify response status is 200 OK
    assert_eq!(resp.status(), StatusCode::OK);
    
    let headers = resp.headers();
    
    // Verify other security headers are still present
    assert!(headers.get("x-content-type-options").is_some(), "X-Content-Type-Options header should be present");
    assert!(headers.get("x-frame-options").is_some(), "X-Frame-Options header should be present");
    assert!(headers.get("x-xss-protection").is_some(), "X-XSS-Protection header should be present");
    assert!(headers.get("referrer-policy").is_some(), "Referrer-Policy header should be present");
    
    // Verify CSP header is NOT present when disabled
    let csp = headers.get("content-security-policy");
    assert!(csp.is_none(), "Content-Security-Policy header should not be present when disabled");
    
    // Clean up environment variable
    unsafe {
        env::remove_var("SECURITY_CSP_ENABLED");
    }
}

/// Test that Request ID middleware adds X-Request-ID header to responses
#[actix_web::test]
async fn test_request_id_header_added() {
    // Create a test service with Request ID middleware
    let app = test::init_service(create_base_app()).await;
    
    // Test health endpoint
    let req = test::TestRequest::get().uri("/api/health").to_request();
    let resp = test::call_service(&app, req).await;
    
    // Verify response has X-Request-ID header
    let request_id_header = resp.headers().get("x-request-id");
    assert!(request_id_header.is_some(), "Response should contain X-Request-ID header");
    
    let request_id = request_id_header.unwrap().to_str().unwrap();
    assert!(!request_id.is_empty(), "Request ID should not be empty");
    
    // Verify it looks like a UUID (basic format check)
    assert_eq!(request_id.len(), 36, "Request ID should be 36 characters long (UUID format)");
    assert_eq!(request_id.chars().filter(|&c| c == '-').count(), 4, "Request ID should have 4 hyphens (UUID format)");
}

/// Test that existing Request ID is preserved when passed in X-Request-ID header
#[actix_web::test]
async fn test_request_id_header_preserved() {
    // Create a test service with Request ID middleware
    let app = test::init_service(create_base_app()).await;
    
    let existing_request_id = "custom-request-id-12345";
    
    // Test with custom X-Request-ID header
    let req = test::TestRequest::get()
        .uri("/api/health")
        .insert_header(("X-Request-ID", existing_request_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    
    // Verify response preserves the original Request ID
    let request_id_header = resp.headers().get("x-request-id");
    assert!(request_id_header.is_some(), "Response should contain X-Request-ID header");
    
    let returned_request_id = request_id_header.unwrap().to_str().unwrap();
    assert_eq!(returned_request_id, existing_request_id, "Response should preserve the original Request ID");
}

/// Test that Request ID middleware works on version endpoint
#[actix_web::test]
async fn test_request_id_on_version_endpoint() {
    // Create a test service with Request ID middleware
    let app = test::init_service(create_base_app()).await;
    
    // Test version endpoint
    let req = test::TestRequest::get().uri("/api/version").to_request();
    let resp = test::call_service(&app, req).await;
    
    // Verify response has X-Request-ID header
    let request_id_header = resp.headers().get("x-request-id");
    assert!(request_id_header.is_some(), "Version endpoint response should contain X-Request-ID header");
    
    let request_id = request_id_header.unwrap().to_str().unwrap();
    assert!(!request_id.is_empty(), "Request ID should not be empty");
}

/// Integration test for the metrics endpoint
/// 
/// This test verifies that:
/// - /api/metrics endpoint returns 200 OK
/// - Response is in Prometheus text format
/// - Contains expected metric types (counters, histograms, gauges)
/// - Contains application info metrics
/// - Uptime metric is present and valid
#[actix_web::test]
async fn test_metrics_endpoint_integration() {
    // Create a test service with the same configuration as the main app
    let app = test::init_service(create_base_app()).await;
    
    // Make some requests to generate metrics data
    let health_req = test::TestRequest::get().uri("/api/health").to_request();
    let _health_resp = test::call_service(&app, health_req).await;
    
    let version_req = test::TestRequest::get().uri("/api/version").to_request();
    let _version_resp = test::call_service(&app, version_req).await;
    
    // Now request metrics
    let metrics_req = test::TestRequest::get().uri("/api/metrics").to_request();
    let metrics_resp = test::call_service(&app, metrics_req).await;
    
    // Verify response status is 200 OK
    assert_eq!(metrics_resp.status(), StatusCode::OK, "Expected 200 OK status for metrics endpoint");
    
    // Verify response content type is Prometheus text format
    let content_type = metrics_resp.headers().get("content-type");
    assert!(content_type.is_some(), "Content-Type header should be present");
    let content_type_str = content_type.unwrap().to_str().unwrap();
    assert!(content_type_str.contains("text/plain"), 
            "Expected text/plain content type, got: {}", content_type_str);
    
    // Read response body
    let body = test::read_body(metrics_resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    
    // Verify the response contains expected Prometheus metrics
    assert!(!body_str.is_empty(), "Metrics response should not be empty");
    
    // Check for expected metric names
    assert!(body_str.contains("http_requests_total"), "Should contain http_requests_total metric");
    assert!(body_str.contains("http_request_duration_seconds"), "Should contain http_request_duration_seconds metric");
    assert!(body_str.contains("app_uptime_seconds"), "Should contain app_uptime_seconds metric");
    assert!(body_str.contains("app_info"), "Should contain app_info metric");
    
    // Check for application version info in metrics
    assert!(body_str.contains("version=\"0.1.0\""), "Should contain version information");
    
    // Verify metrics format follows Prometheus conventions
    assert!(body_str.contains("# HELP"), "Should contain metric help text");
    assert!(body_str.contains("# TYPE"), "Should contain metric type information");
    
    // Verify that we have some actual metric values
    assert!(body_str.matches(char::is_numeric).count() > 0, "Should contain numeric metric values");
}

/// Test metrics endpoint when metrics are disabled
#[actix_web::test]
async fn test_metrics_endpoint_disabled() {
    // Create a test app with metrics disabled
    let config = RateLimitConfig::from_env();
    let limiter = SimpleRateLimiter::new(config.clone());
    let metrics_config = MetricsConfig { enabled: false }; // Explicitly disable metrics
    let metrics = AppMetrics::new().expect("Failed to create metrics");
    
    let app = test::init_service(
        App::new()
            .wrap_api_with_spec(create_openapi_spec())
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(limiter))
            .app_data(web::Data::new(metrics_config))
            .app_data(web::Data::new(metrics))
            .service(
                web::resource("/api/health")
                    .route(web::get().to(health))
            )
            .service(
                web::resource("/api/version")
                    .route(web::get().to(version))
            )
            .service(
                web::resource("/api/metrics")
                    .route(web::get().to(get_metrics))
            )
            .with_json_spec_at("/api/spec/v2")
            .build()
    ).await;
    
    // Request metrics
    let metrics_req = test::TestRequest::get().uri("/api/metrics").to_request();
    let metrics_resp = test::call_service(&app, metrics_req).await;
    
    // Should return 503 Service Unavailable
    assert_eq!(metrics_resp.status(), StatusCode::SERVICE_UNAVAILABLE, 
               "Expected 503 when metrics are disabled");
    
    // Check response body contains appropriate message
    let body = test::read_body(metrics_resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.contains("disabled"), "Response should indicate metrics are disabled");
}