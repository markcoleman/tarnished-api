use actix_web::{App, HttpResponse, HttpServer};
use paperclip::actix::{
    // extension trait for actix_web::App and proc-macro attributes
    OpenApiExt, api_v2_operation,
    // If you prefer the macro syntax for defining routes, import the paperclip macros
    // get, post, put, delete
    // use this instead of actix_web::web
    web::{self},
};

#[api_v2_operation]
async fn hello() -> HttpResponse {
    // Return a plain text response.
    HttpResponse::Ok().body("Hello, world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger (make sure to run with RUST_LOG=info, for example)
    env_logger::init();

    // Print a startup message for convenience.
    println!("Server running at http://127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            .wrap_api() // Enables Paperclip's OpenAPI support.
            .service(
                web::resource("/")
                    .route(web::get().to(hello))
            )
            // Expose the generated OpenAPI spec at /api/spec/v2.
            .with_json_spec_at("/api/spec/v2")
            .build()
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}