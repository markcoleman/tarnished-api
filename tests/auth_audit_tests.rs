use actix_web::{http::StatusCode, test};
use tarnished_api::{
    AuthAuditEvent, AuthEventOutcome, AuthEventType, LoginRequest, LoginResponse,
    TokenValidationRequest, TokenValidationResponse, create_base_app,
};

#[actix_web::test]
async fn test_login_success_audit_logging() {
    // Create a test service with the auth endpoints
    let app = test::init_service(create_base_app()).await;

    let login_request = LoginRequest {
        username: "admin".to_string(),
        password: "password123".to_string(),
    };

    // Create a test request to POST /auth/login
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Verify response status is 200 OK
    assert_eq!(resp.status(), StatusCode::OK, "Login should succeed");

    // Verify response content type is JSON
    let content_type = resp.headers().get("content-type");
    assert!(
        content_type.is_some(),
        "Content-Type header should be present"
    );
    let content_type_str = content_type.unwrap().to_str().unwrap();
    assert!(
        content_type_str.contains("application/json"),
        "Expected JSON content type, got: {}",
        content_type_str
    );

    // Read and parse response body
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Parse JSON response
    let json: LoginResponse =
        serde_json::from_str(body_str).expect("Failed to parse response as JSON");

    // Check that login was successful
    assert!(json.success, "Login should be successful");
    assert!(json.token.is_some(), "Token should be present");
    assert!(
        json.token.unwrap().starts_with("token_"),
        "Token should have expected format"
    );
    assert_eq!(
        json.message, "Login successful",
        "Message should indicate success"
    );
}

#[actix_web::test]
async fn test_login_failure_audit_logging() {
    // Create a test service with the auth endpoints
    let app = test::init_service(create_base_app()).await;

    let login_request = LoginRequest {
        username: "admin".to_string(),
        password: "wrongpassword".to_string(),
    };

    // Create a test request to POST /auth/login
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Verify response status is 401 Unauthorized
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Login should fail");
}

#[actix_web::test]
async fn test_token_validation_success_audit_logging() {
    // Create a test service with the auth endpoints
    let app = test::init_service(create_base_app()).await;

    let validation_request = TokenValidationRequest {
        token: "token_12345".to_string(),
    };

    // Create a test request to POST /auth/validate
    let req = test::TestRequest::post()
        .uri("/auth/validate")
        .set_json(&validation_request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Verify response status is 200 OK
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Token validation should succeed"
    );

    // Read and parse response body
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Parse JSON response
    let json: TokenValidationResponse =
        serde_json::from_str(body_str).expect("Failed to parse response as JSON");

    // Check that validation was successful
    assert!(json.valid, "Token should be valid");
    assert!(json.user_id.is_some(), "User ID should be present");
    assert_eq!(
        json.message, "Token is valid",
        "Message should indicate success"
    );
}

#[actix_web::test]
async fn test_token_validation_failure_audit_logging() {
    // Create a test service with the auth endpoints
    let app = test::init_service(create_base_app()).await;

    let validation_request = TokenValidationRequest {
        token: "invalid_token".to_string(),
    };

    // Create a test request to POST /auth/validate
    let req = test::TestRequest::post()
        .uri("/auth/validate")
        .set_json(&validation_request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Verify response status is 200 OK (but token is invalid)
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Endpoint should respond normally"
    );

    // Read and parse response body
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Parse JSON response
    let json: TokenValidationResponse =
        serde_json::from_str(body_str).expect("Failed to parse response as JSON");

    // Check that validation failed
    assert!(!json.valid, "Token should be invalid");
    assert!(json.user_id.is_none(), "User ID should not be present");
    assert_eq!(
        json.message, "Invalid token",
        "Message should indicate failure"
    );
}

#[actix_web::test]
async fn test_audit_event_creation() {
    let event = AuthAuditEvent::new(
        AuthEventType::LoginSuccess,
        AuthEventOutcome::Success,
        "192.168.1.100".to_string(),
        "POST".to_string(),
        "/auth/login".to_string(),
    )
    .with_user_id(Some("test_user".to_string()))
    .with_user_agent(Some("Test Agent".to_string()))
    .with_details(Some("Test login event".to_string()));

    // Verify event properties
    assert_eq!(event.ip_address, "192.168.1.100");
    assert_eq!(event.method, "POST");
    assert_eq!(event.endpoint, "/auth/login");
    assert_eq!(event.user_id, Some("test_user".to_string()));
    assert_eq!(event.user_agent, Some("Test Agent".to_string()));
    assert_eq!(event.additional_context, Some("Test login event".to_string()));

    // Verify event can be serialized to JSON
    let json = serde_json::to_string(&event).expect("Should serialize to JSON");
    assert!(
        json.contains("login_success"),
        "JSON should contain event type"
    );
    assert!(json.contains("success"), "JSON should contain outcome");
    assert!(
        json.contains("192.168.1.100"),
        "JSON should contain IP address"
    );
    assert!(json.contains("test_user"), "JSON should contain user ID");

    // Verify event can be deserialized from JSON
    let deserialized: AuthAuditEvent =
        serde_json::from_str(&json).expect("Should deserialize from JSON");
    assert_eq!(deserialized.ip_address, event.ip_address);
    assert_eq!(deserialized.user_id, event.user_id);
    assert_eq!(deserialized.method, event.method);
}

#[actix_web::test]
async fn test_suspicious_activity_detection() {
    use tarnished_api::SuspiciousActivityTracker;

    let tracker = SuspiciousActivityTracker::new();
    let test_ip = "192.168.1.100";

    // Initially should not be suspicious
    assert!(
        !tracker.is_suspicious(test_ip),
        "IP should not be suspicious initially"
    );

    // Record multiple failures
    for i in 0..4 {
        let is_suspicious = tracker.record_failure(test_ip);
        assert!(
            !is_suspicious,
            "Should not be suspicious after {} failures",
            i + 1
        );
    }

    // 5th failure should trigger suspicious activity detection
    let is_suspicious = tracker.record_failure(test_ip);
    assert!(is_suspicious, "Should be suspicious after 5 failures");

    // Should now be flagged as suspicious
    assert!(
        tracker.is_suspicious(test_ip),
        "IP should be flagged as suspicious"
    );

    // Different IP should not be affected
    assert!(
        !tracker.is_suspicious("192.168.1.101"),
        "Different IP should not be suspicious"
    );
}
