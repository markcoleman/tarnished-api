//! Security headers middleware implementation.

use crate::config::SecurityHeadersConfig;
use actix_web::{
    Error,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue},
};
use std::{
    future::{Ready, ready},
    pin::Pin,
};

/// Security headers middleware factory
pub struct SecurityHeaders {
    config: SecurityHeadersConfig,
}

impl SecurityHeaders {
    /// Create a new security headers middleware with the given configuration
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware {
            service,
            config: self.config.clone(),
        }))
    }
}

/// The actual security headers middleware service
pub struct SecurityHeadersMiddleware<S> {
    service: S,
    config: SecurityHeadersConfig,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
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
        let fut = self.service.call(req);
        let config = self.config.clone();

        Box::pin(async move {
            let mut res = fut.await?;
            let headers = res.headers_mut();

            // X-Content-Type-Options
            if config.content_type_options {
                headers.insert(
                    HeaderName::from_static("x-content-type-options"),
                    HeaderValue::from_static("nosniff"),
                );
            }

            // X-Frame-Options
            if let Ok(value) = HeaderValue::from_str(&config.frame_options) {
                headers.insert(HeaderName::from_static("x-frame-options"), value);
            }

            // X-XSS-Protection
            if config.xss_protection {
                headers.insert(
                    HeaderName::from_static("x-xss-protection"),
                    HeaderValue::from_static("1; mode=block"),
                );
            }

            // Referrer-Policy
            if let Ok(value) = HeaderValue::from_str(&config.referrer_policy) {
                headers.insert(HeaderName::from_static("referrer-policy"), value);
            }

            // Content-Security-Policy
            if config.csp_enabled
                && let Ok(value) = HeaderValue::from_str(&config.csp_directives) {
                    headers.insert(HeaderName::from_static("content-security-policy"), value);
                }

            // Strict-Transport-Security (HSTS)
            if config.hsts_enabled {
                let hsts_value = format!("max-age={}", config.hsts_max_age);
                if let Ok(value) = HeaderValue::from_str(&hsts_value) {
                    headers.insert(HeaderName::from_static("strict-transport-security"), value);
                }
            }

            Ok(res)
        })
    }
}
