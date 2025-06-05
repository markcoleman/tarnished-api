use actix_web::{App, HttpResponse, HttpServer};
use paperclip::actix::{
    // extension trait for actix_web::App and proc-macro attributes
    OpenApiExt, api_v2_operation,
    // Import the paperclip web module
    web::{self},
};
use tarnished_api::{create_openapi_spec, health, version, RateLimitConfig, SimpleRateLimiter};

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
async fn index() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(INDEX_HTML)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger (make sure to run with RUST_LOG=info, for example)
    env_logger::init();

    // Print a startup message for convenience.
    println!("Server running at http://127.0.0.1:8080");

    HttpServer::new(|| {
        let config = RateLimitConfig::from_env();
        let limiter = SimpleRateLimiter::new(config.clone());
        
        App::new()
            .wrap_api_with_spec(create_openapi_spec())
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(limiter))
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