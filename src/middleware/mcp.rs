//! Model Context Protocol (MCP) middleware for request/response enrichment.
//!
//! This middleware detects MCP-aware requests via headers and conditionally
//! wraps responses with context metadata while maintaining backward compatibility
//! with standard REST clients.

use crate::models::mcp::ContextMetadata;
use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
};
use std::{
    future::{Ready, ready},
    pin::Pin,
    rc::Rc,
};

/// MCP context key for storing context in request extensions
pub const MCP_CONTEXT_KEY: &str = "mcp_context";

/// MCP middleware factory
///
/// This middleware detects MCP-aware requests by checking for specific headers
/// and stores context information in request extensions for use by handlers.
pub struct McpMiddleware;

impl<S, B> Transform<S, ServiceRequest> for McpMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = McpMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(McpMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

/// The actual MCP middleware service
pub struct McpMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for McpMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            // Check for MCP headers to detect MCP-aware requests
            let headers = req.headers();

            // Look for MCP-specific headers
            let has_mcp_context = headers.get("X-MCP-Context").is_some();
            let has_mcp_client = headers.get("X-Client").is_some();
            let has_trace_id = headers.get("X-Trace-ID").is_some();

            // Determine if this is an MCP-aware request
            let is_mcp_request = has_mcp_context || has_mcp_client || has_trace_id;

            if is_mcp_request {
                // Extract context information from headers
                let trace_id = headers
                    .get("X-Trace-ID")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());

                let client_id = headers
                    .get("X-Client")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());

                let correlation_id = headers
                    .get("X-Correlation-ID")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());

                // Create context metadata
                let context = ContextMetadata::from_headers(trace_id, client_id, correlation_id);

                // Store context in request extensions for handlers to use
                req.extensions_mut().insert(context);

                tracing::debug!(
                    trace_id = %req.extensions().get::<ContextMetadata>()
                        .map(|c| c.trace_id.as_str())
                        .unwrap_or("unknown"),
                    client_id = ?req.extensions().get::<ContextMetadata>()
                        .and_then(|c| c.client_id.as_deref()),
                    "MCP request detected"
                );
            } else {
                tracing::trace!("Standard REST request detected");
            }

            // Call the next service
            let res = service.call(req).await?;

            // Note: Response wrapping is handled by individual handlers
            // using the context stored in request extensions
            Ok(res)
        })
    }
}

/// Helper function to check if a request has MCP context
pub fn has_mcp_context(req: &ServiceRequest) -> bool {
    req.extensions().get::<ContextMetadata>().is_some()
}

/// Helper function to get MCP context from request
pub fn get_mcp_context(req: &ServiceRequest) -> Option<ContextMetadata> {
    req.extensions().get::<ContextMetadata>().cloned()
}

/// Helper function to extract MCP context from HttpRequest (for handlers)
pub fn extract_mcp_context(req: &actix_web::HttpRequest) -> Option<ContextMetadata> {
    req.extensions().get::<ContextMetadata>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpRequest, HttpResponse, test, web};

    async fn test_handler(req: HttpRequest) -> HttpResponse {
        let context = extract_mcp_context(&req);
        if context.is_some() {
            HttpResponse::Ok().json(serde_json::json!({"mcp": true}))
        } else {
            HttpResponse::Ok().json(serde_json::json!({"mcp": false}))
        }
    }

    #[actix_web::test]
    async fn test_mcp_middleware_without_headers() {
        let app = test::init_service(
            App::new()
                .wrap(McpMiddleware)
                .route("/test", web::get().to(test_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["mcp"], false);
    }

    #[actix_web::test]
    async fn test_mcp_middleware_with_mcp_context_header() {
        let app = test::init_service(
            App::new()
                .wrap(McpMiddleware)
                .route("/test", web::get().to(test_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header(("X-MCP-Context", "true"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["mcp"], true);
    }

    #[actix_web::test]
    async fn test_mcp_middleware_with_client_header() {
        let app = test::init_service(
            App::new()
                .wrap(McpMiddleware)
                .route("/test", web::get().to(test_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header(("X-Client", "test-client"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["mcp"], true);
    }

    #[actix_web::test]
    async fn test_mcp_middleware_with_trace_id_header() {
        let app = test::init_service(
            App::new()
                .wrap(McpMiddleware)
                .route("/test", web::get().to(test_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header(("X-Trace-ID", "test-trace-123"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["mcp"], true);
    }

    #[actix_web::test]
    async fn test_context_extraction() {
        let app = test::init_service(App::new().wrap(McpMiddleware).route(
            "/test",
            web::get().to(|req: HttpRequest| async move {
                let context = extract_mcp_context(&req);
                match context {
                    Some(ctx) => HttpResponse::Ok().json(serde_json::json!({
                        "trace_id": ctx.trace_id,
                        "client_id": ctx.client_id,
                        "correlation_id": ctx.correlation_id
                    })),
                    None => HttpResponse::Ok().json(serde_json::json!({"context": null})),
                }
            }),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header(("X-Trace-ID", "test-trace-123"))
            .insert_header(("X-Client", "test-client"))
            .insert_header(("X-Correlation-ID", "corr-456"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["trace_id"], "test-trace-123");
        assert_eq!(body["client_id"], "test-client");
        assert_eq!(body["correlation_id"], "corr-456");
    }
}
