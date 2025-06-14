use actix_web::{test, http::StatusCode};
use tarnished_api::{create_base_app, RateLimitConfig, SimpleRateLimiter};
use std::env;

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