//! Metrics collection and Prometheus integration service.

use prometheus::{CounterVec, Gauge, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder};
use std::time::{Duration, Instant};

/// Application metrics collector for Prometheus integration
#[derive(Clone)]
pub struct AppMetrics {
    pub registry: Registry,
    pub http_requests_total: CounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub app_uptime_seconds: Gauge,
    pub app_info: CounterVec,
    pub start_time: Instant,
}

impl AppMetrics {
    /// Create a new metrics collector with default Prometheus metrics
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // HTTP request counter by method, status, and route
        let http_requests_total = CounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests"),
            &["method", "status", "route"],
        )?;

        // HTTP request duration histogram
        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "route"],
        )?;

        // Application uptime gauge
        let app_uptime_seconds = Gauge::new("app_uptime_seconds", "Application uptime in seconds")?;

        // Application info counter
        let app_info = CounterVec::new(
            Opts::new("app_info", "Application information"),
            &["version", "commit", "build_time"],
        )?;

        // Register all metrics
        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;
        registry.register(Box::new(app_uptime_seconds.clone()))?;
        registry.register(Box::new(app_info.clone()))?;

        let start_time = Instant::now();

        // Set application info
        app_info
            .with_label_values(&[
                env!("CARGO_PKG_VERSION"),
                env!("VERGEN_GIT_SHA"),
                env!("VERGEN_BUILD_TIMESTAMP"),
            ])
            .inc();

        Ok(Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            app_uptime_seconds,
            app_info,
            start_time,
        })
    }

    /// Record an HTTP request with method, route, status, and duration
    pub fn record_request(&self, method: &str, route: &str, status: u16, duration: Duration) {
        if route == "/api/metrics" {
            // Don't record metrics for the metrics endpoint itself to avoid noise
            return;
        }

        self.http_requests_total
            .with_label_values(&[method, &status.to_string(), route])
            .inc();

        self.http_request_duration_seconds
            .with_label_values(&[method, route])
            .observe(duration.as_secs_f64());
    }

    /// Update the application uptime gauge
    pub fn update_uptime(&self) {
        let uptime = self.start_time.elapsed().as_secs_f64();
        self.app_uptime_seconds.set(uptime);
    }

    /// Render metrics in Prometheus text format
    pub fn render(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families)
    }
}
