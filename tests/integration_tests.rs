use actix_web::{test, http::StatusCode, App};
use paperclip::actix::{OpenApiExt, web};
use tarnished_api::{create_base_app, create_openapi_spec, health, version, get_metrics, RateLimitConfig, SimpleRateLimiter, MetricsConfig, AppMetrics};
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

<<<<<<< HEAD
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
=======
>>>>>>> 4549c9fd422199c90de8fe7c4b3dc8be2f3ec524
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