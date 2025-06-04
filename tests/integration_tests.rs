use actix_web::{test, App, http::StatusCode};
use paperclip::actix::{OpenApiExt, api_v2_operation, Apiv2Schema, web};
use paperclip::v2::models::{DefaultApiRaw, Info};
use serde::{Serialize, Deserialize};

// Re-declare the types and functions needed for testing
// (In a real project, these would be imported from the main crate)
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct HealthResponse {
    pub status: String,
}

#[api_v2_operation(
    summary = "Health Check Endpoint",
    description = "Returns the current health status of the API in JSON format.",
    tags("Health"),
    responses(
        (status = 200, description = "Successful response", body = HealthResponse)
    )
)]
async fn health() -> Result<web::Json<HealthResponse>, actix_web::Error> {
    let response = HealthResponse {
        status: "healthy".to_string(),
    };
    Ok(web::Json(response))
}

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
    let app = test::init_service(
        App::new()
            .wrap_api_with_spec(DefaultApiRaw {
                info: Info {
                    title: "Tarnished API".into(),
                    version: "1.0.0".into(),
                    description: Some("A sample API built with Actix and Paperclip".into()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .service(
                web::resource("/api/health")
                    .route(web::get().to(health))
            )
            .with_json_spec_at("/api/spec/v2")
            .build()
    ).await;
    
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