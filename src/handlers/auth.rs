//! Authentication endpoint handlers.

use crate::{
    models::{
        audit::{AuthAuditEvent, AuthEventOutcome, AuthEventType},
        auth::{LoginRequest, LoginResponse, TokenValidationRequest, TokenValidationResponse},
    },
    utils::http::{extract_client_ip, extract_user_agent},
};
use actix_web::{Error, HttpRequest, Result, web};
use paperclip::actix::api_v2_operation;
use uuid::Uuid;

/// User login endpoint
///
/// Authenticates users with username/password and returns an access token.
/// This is a mock implementation - real applications should use proper
/// password hashing and database authentication.
#[api_v2_operation(
    summary = "User Login",
    description = "Authenticate user and return access token",
    tags("Authentication"),
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Login failed", body = LoginResponse),
        (status = 429, description = "Too many requests")
    )
)]
pub async fn login(
    req: HttpRequest,
    payload: web::Json<LoginRequest>,
) -> Result<web::Json<LoginResponse>, Error> {
    let ip_address = extract_client_ip(&req);
    let user_agent = extract_user_agent(&req);
    let method = req.method().to_string();
    let endpoint = req.uri().path().to_string();

    // Simple mock authentication - in real implementation, this would check against a database
    let success = payload.username == "admin" && payload.password == "password123";

    if success {
        let token = format!("token_{}", Uuid::new_v4());
        let response = LoginResponse {
            success: true,
            token: Some(token),
            message: "Login successful".to_string(),
        };

        // Log successful login
        AuthAuditEvent::new(
            AuthEventType::LoginSuccess,
            AuthEventOutcome::Success,
            ip_address,
            method,
            endpoint,
        )
        .with_user_id(Some(payload.username.clone()))
        .with_user_agent(user_agent)
        .log();

        Ok(web::Json(response))
    } else {
        let response = LoginResponse {
            success: false,
            token: None,
            message: "Invalid credentials".to_string(),
        };

        // Log failed login
        AuthAuditEvent::new(
            AuthEventType::LoginFailure,
            AuthEventOutcome::Failure,
            ip_address,
            method,
            endpoint,
        )
        .with_user_id(Some(payload.username.clone()))
        .with_user_agent(user_agent)
        .log();

        Err(actix_web::error::ErrorUnauthorized(
            serde_json::to_string(&response).unwrap(),
        ))
    }
}

/// Token validation endpoint
///
/// Validates access tokens and returns user information if valid.
/// This is a mock implementation - real applications should use
/// proper JWT validation or database token verification.
#[api_v2_operation(
    summary = "Token Validation",
    description = "Validate an access token",
    tags("Authentication"),
    responses(
        (status = 200, description = "Token validation response", body = TokenValidationResponse)
    )
)]
pub async fn validate_token(
    req: HttpRequest,
    payload: web::Json<TokenValidationRequest>,
) -> Result<web::Json<TokenValidationResponse>, Error> {
    let ip_address = extract_client_ip(&req);
    let user_agent = extract_user_agent(&req);
    let method = req.method().to_string();
    let endpoint = req.uri().path().to_string();

    // Simple mock token validation - in real implementation, this would verify JWT or check database
    let valid = payload.token.starts_with("token_");

    if valid {
        let response = TokenValidationResponse {
            valid: true,
            user_id: Some("admin".to_string()),
            message: "Token is valid".to_string(),
        };

        // Log successful token validation
        AuthAuditEvent::new(
            AuthEventType::TokenValidationSuccess,
            AuthEventOutcome::Success,
            ip_address,
            method,
            endpoint,
        )
        .with_user_id(Some("admin".to_string()))
        .with_user_agent(user_agent)
        .log();

        Ok(web::Json(response))
    } else {
        let response = TokenValidationResponse {
            valid: false,
            user_id: None,
            message: "Invalid token".to_string(),
        };

        // Log failed token validation
        AuthAuditEvent::new(
            AuthEventType::TokenValidationFailure,
            AuthEventOutcome::Failure,
            ip_address,
            method,
            endpoint,
        )
        .with_user_agent(user_agent)
        .log();

        Ok(web::Json(response))
    }
}
