use actix_web::{App, HttpResponse, HttpServer, HttpRequest};
use paperclip::actix::{
    // extension trait for actix_web::App and proc-macro attributes
    OpenApiExt, api_v2_operation,
    // Import the paperclip web module
    web::{self},
};
use tarnished_api::{create_openapi_spec, health, version, get_metrics, RateLimitConfig, SimpleRateLimiter, SecurityHeaders, SecurityHeadersConfig, MetricsConfig, AppMetrics, RequestIdMiddleware};
use tarnished_api::{create_openapi_spec, health, version, login, validate_token, RateLimitConfig, SimpleRateLimiter, SuspiciousActivityTracker};

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Tarnished API - OpenAPI Spec</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 800px;
            margin: 40px auto;
            padding: 20px;
            background: #fff;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
        }
        h1 {
            text-align: center;
        }
        pre {
            background: #eee;
            padding: 20px;
            border-radius: 4px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Tarnished API OpenAPI Spec</h1>
        <pre id="openapi">Loading...</pre>
    </div>
    <script>
        fetch('/api/spec/v2')
            .then(response => response.json())
            .then(data => {
                document.getElementById('openapi').textContent = JSON.stringify(data, null, 2);
            })
            .catch(error => {
                document.getElementById('openapi').textContent = 'Error loading spec: ' + error;
            });
    </script>
</body>
</html>"#;


#[api_v2_operation (
    summary = "Hello World Endpoint",
    description = "Returns a simple hello world message.",
    tags("Hello"),
    responses(
        (status = 200, description = "Successful response")
    )
)]
async fn index(req: HttpRequest) -> HttpResponse {
    let start_time = std::time::Instant::now();
    
    let response = HttpResponse::Ok()
        .content_type("text/html")
        .body(INDEX_HTML);
    
    // Record metrics if available
    if let Some(metrics) = req.app_data::<web::Data<AppMetrics>>() {
        metrics.record_request("GET", "/", 200, start_time.elapsed());
    }
    
    response
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize structured logging
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,auth_audit=info".to_string());
    
    // Check if we should use JSON logging (for production/observability)
    let use_json_logging = std::env::var("LOG_FORMAT")
        .map(|v| v.to_lowercase() == "json")
        .unwrap_or(false);

    if use_json_logging {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .init();
    }

    // Print a startup message for convenience.
    println!("Server running at http://127.0.0.1:8080");
    println!("Authentication endpoints:");
    println!("  POST /auth/login - User login");
    println!("  POST /auth/validate - Token validation");
    println!("Set LOG_FORMAT=json for structured JSON logging");
    println!("Set RUST_LOG=debug,auth_audit=info for verbose logging");

    HttpServer::new(|| {
        let config = RateLimitConfig::from_env();
        let limiter = SimpleRateLimiter::new(config.clone());
        let security_config = SecurityHeadersConfig::from_env();
        let metrics_config = MetricsConfig::from_env();
        let metrics = AppMetrics::new().expect("Failed to create metrics");
        let activity_tracker = SuspiciousActivityTracker::new();
        
        App::new()
            .wrap(SecurityHeaders::new(security_config))
            .wrap(RequestIdMiddleware)
            .wrap_api_with_spec(create_openapi_spec())
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(limiter))
            .app_data(web::Data::new(metrics_config))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(activity_tracker))
            .service(
                web::resource("/")
                    .route(web::get().to(index))
            )
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
                web::resource("/auth/login")
                    .route(web::post().to(login))
            )
            .service(
                web::resource("/auth/validate")
                    .route(web::post().to(validate_token))
            )
            .with_json_spec_at("/api/spec/v2")
            .build()
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use actix_web::{test, web, App};
    use tarnished_api::{health, version};

    #[actix_web::test]
    async fn test_health() {
        // Create a test app with the /api/health route.
        let app = test::init_service(
            App::new().route("/api/health", web::get().to(health))
        ).await;
        
        // Create a test request to GET /api/health.
        let req = test::TestRequest::get().uri("/api/health").to_request();
        let resp = test::call_service(&app, req).await;
        
        // Ensure the response status is successful (200 OK).
        assert!(resp.status().is_success());
        
        // Check that the response body contains "healthy".
        let body = test::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("healthy"));
    }

    #[actix_web::test]
    async fn test_version() {
        // Create a test app with the /api/version route.
        let app = test::init_service(
            App::new().route("/api/version", web::get().to(version))
        ).await;
        
        // Create a test request to GET /api/version.
        let req = test::TestRequest::get().uri("/api/version").to_request();
        let resp = test::call_service(&app, req).await;
        
        // Ensure the response status is successful (200 OK).
        assert!(resp.status().is_success());
        
        // Check that the response body contains version, commit, and build_time fields.
        let body = test::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("version"));
        assert!(body_str.contains("commit"));
        assert!(body_str.contains("build_time"));
    }
}