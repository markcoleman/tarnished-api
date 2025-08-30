use actix_web::{App, test, web};
use tarnished_api::{RequestIdMiddleware, health, newrelic::*};

#[actix_web::test]
async fn test_newrelic_fields_extraction() {
    let app = test::init_service(
        App::new()
            .wrap(RequestIdMiddleware)
            .route("/health", web::get().to(health)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/health")
        .insert_header(("User-Agent", "TestAgent/1.0"))
        .insert_header(("X-Request-ID", "test-req-123"))
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Verify response includes the request ID header
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("x-request-id"));
}

#[actix_web::test]
async fn test_newrelic_config() {
    // Test with no license key (disabled)
    let config = NewRelicConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.service_name, "tarnished-api");
    assert_eq!(config.environment, "development");
}

#[tokio::test]
async fn test_newrelic_sensitive_data_redaction() {
    let test_cases = vec![
        (
            r#"{"password": "secret123", "username": "admin"}"#,
            "password should be redacted",
        ),
        (
            r#"{"token": "abc123xyz", "data": "safe"}"#,
            "token should be redacted",
        ),
        (
            r#"{"api_key": "key_12345", "public": "info"}"#,
            "api_key should be redacted",
        ),
        (
            "Contact us at user@example.com for support",
            "email should be redacted",
        ),
    ];

    for (input, description) in test_cases {
        let redacted = redact_sensitive_data(input);

        // Check that sensitive patterns were replaced
        if input.contains("password") || input.contains("token") || input.contains("api") {
            assert!(redacted.contains("[REDACTED]"), "Failed: {description}");
        }

        if input.contains("@") {
            assert!(
                !redacted.contains("user@example.com"),
                "Failed: {description}"
            );
        }

        println!("✅ {description}: {input} -> {redacted}");
    }
}

#[tokio::test]
async fn test_newrelic_field_creation() {
    use actix_web::test::TestRequest;

    let req = TestRequest::get()
        .uri("/test/path")
        .insert_header(("User-Agent", "TestBot/2.0"))
        .insert_header(("X-Request-ID", "req-456"))
        .to_http_request();

    let fields = NewRelicFields::from_request(&req);

    assert_eq!(fields.method, "GET");
    assert_eq!(fields.path, "/test/path");
    assert_eq!(fields.user_agent, Some("TestBot/2.0".to_string()));
    assert_eq!(fields.request_id, "req-456");
    assert_eq!(fields.status_code, None);

    let fields_with_status = fields.with_status_code(200);
    assert_eq!(fields_with_status.status_code, Some(200));
}
