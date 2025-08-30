//! Request ID middleware for tracing and logging.

use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue},
};
use std::{
    future::{Ready, ready},
    pin::Pin,
};
use uuid::Uuid;

/// Request ID middleware factory
///
/// This middleware ensures every request has a unique ID for tracing purposes.
/// It will use an existing X-Request-ID header if present, or generate a new UUID.
pub struct RequestIdMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RequestIdMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestIdService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestIdService { service }))
    }
}

/// The actual request ID middleware service
pub struct RequestIdService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestIdService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start_time = std::time::Instant::now();

        // Extract or generate Request ID
        let request_id = req
            .headers()
            .get("X-Request-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Create New Relic fields for enhanced logging
        let newrelic_fields = crate::newrelic::NewRelicFields::from_request(req.request());

        // Store Request ID in request extensions for potential use in handlers
        req.extensions_mut().insert(request_id.clone());

        // Log incoming request with New Relic fields
        tracing::info!(
            target: "request",
            request_id = %request_id,
            method = %newrelic_fields.method,
            path = %newrelic_fields.path,
            ip_address = %newrelic_fields.ip_address,
            user_agent = ?newrelic_fields.user_agent,
            commit_sha = %std::env::var("GITHUB_SHA").unwrap_or_else(|_| "unknown".to_string()),
            git_ref = %std::env::var("GITHUB_REF").unwrap_or_else(|_| "unknown".to_string()),
            environment = %std::env::var("NEW_RELIC_ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            "Incoming request"
        );

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            let duration = start_time.elapsed();

            // Add Request ID to response headers
            res.headers_mut().insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str(&request_id)
                    .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
            );

            // Log completed request with response details
            tracing::info!(
                target: "request",
                request_id = %request_id,
                status = %res.status().as_u16(),
                duration_ms = %duration.as_millis(),
                commit_sha = %std::env::var("GITHUB_SHA").unwrap_or_else(|_| "unknown".to_string()),
                git_ref = %std::env::var("GITHUB_REF").unwrap_or_else(|_| "unknown".to_string()),
                environment = %std::env::var("NEW_RELIC_ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
                "Request completed"
            );

            Ok(res)
        })
    }
}
