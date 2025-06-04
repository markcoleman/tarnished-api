use actix_web::{App, Error};
use paperclip::actix::{OpenApiExt, api_v2_operation, Apiv2Schema, web};
use paperclip::v2::models::{DefaultApiRaw, Info};
use serde::{Serialize, Deserialize};

// Define a schema for the health response
#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct HealthResponse {
    pub status: String,
}

#[api_v2_operation(
    summary = "Health Check Endpoint",
    description = "Returns the current health status of the API in JSON format.",
    tags("Health"),
    responses(
        (status = 200, description = "Successful response", body = HealthResponse)
    )
)]
pub async fn health() -> Result<web::Json<HealthResponse>, Error> {
    let response = HealthResponse {
        status: "healthy".to_string(),
    };
    Ok(web::Json(response))
}

/// Creates the shared OpenAPI configuration for the app
pub fn create_openapi_spec() -> DefaultApiRaw {
    DefaultApiRaw {
        info: Info {
            title: "Tarnished API".into(),
            version: "1.0.0".into(),
            description: Some("A sample API built with Actix and Paperclip".into()),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Creates a basic app with shared configuration (health endpoint + OpenAPI)
/// This can be used both for testing and as a base for the main application
pub fn create_base_app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .wrap_api_with_spec(create_openapi_spec())
        .service(
            web::resource("/api/health")
                .route(web::get().to(health))
        )
        .with_json_spec_at("/api/spec/v2")
        .build()
}