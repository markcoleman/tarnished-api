//! Metrics collection middleware.

use crate::{services::AppMetrics, utils::route::extract_route_pattern};
use actix_web::{
    Error,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    web,
};
use std::{
    future::{Ready, ready},
    pin::Pin,
    time::Instant,
};

/// Metrics middleware factory
///
/// This middleware automatically records request metrics including
/// response times, status codes, and request counts.
pub struct MetricsMiddleware;

impl<S, B> Transform<S, ServiceRequest> for MetricsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = MetricsService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(MetricsService { service }))
    }
}

/// The actual metrics middleware service
pub struct MetricsService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for MetricsService<S>
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
        let start_time = Instant::now();
        let method = req.method().to_string();
        let route = extract_route_pattern(req.request());

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            let status = res.status().as_u16();
            let duration = start_time.elapsed();

            // Record metrics if available
            if let Some(metrics) = res.request().app_data::<web::Data<AppMetrics>>() {
                metrics.record_request(&method, &route, status, duration);
                metrics.update_uptime();
            }

            Ok(res)
        })
    }
}

/// Function-based metrics middleware for manual use
///
/// This function can be called manually from handlers to record metrics
/// when the automatic middleware is not suitable.
pub fn metrics_middleware(
    req: &actix_web::HttpRequest,
    metrics: &AppMetrics,
    start_time: Instant,
    status: u16,
) {
    let duration = start_time.elapsed();
    let method = req.method().as_str();
    let route = extract_route_pattern(req);

    metrics.record_request(method, &route, status, duration);
    metrics.update_uptime();
}
