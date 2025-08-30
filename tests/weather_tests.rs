//! Weather endpoint integration tests.

use actix_web::{test, web, App};
use tarnished_api::{weather, WeatherQuery, WeatherResponse};

#[actix_web::test]
async fn test_weather_endpoint_missing_params() {
    let app = test::init_service(App::new().route("/api/weather", web::get().to(weather))).await;

    let req = test::TestRequest::get().uri("/api/weather").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_weather_endpoint_empty_zip() {
    let app = test::init_service(App::new().route("/api/weather", web::get().to(weather))).await;

    let req = test::TestRequest::get()
        .uri("/api/weather?zip=")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_weather_endpoint_invalid_latitude() {
    let app = test::init_service(App::new().route("/api/weather", web::get().to(weather))).await;

    let req = test::TestRequest::get()
        .uri("/api/weather?lat=100&lon=0")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_weather_endpoint_invalid_longitude() {
    let app = test::init_service(App::new().route("/api/weather", web::get().to(weather))).await;

    let req = test::TestRequest::get()
        .uri("/api/weather?lat=0&lon=200")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_weather_endpoint_only_latitude() {
    let app = test::init_service(App::new().route("/api/weather", web::get().to(weather))).await;

    let req = test::TestRequest::get()
        .uri("/api/weather?lat=34.05")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_weather_endpoint_only_longitude() {
    let app = test::init_service(App::new().route("/api/weather", web::get().to(weather))).await;

    let req = test::TestRequest::get()
        .uri("/api/weather?lon=-118.25")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_weather_query_serialization() {
    // Test WeatherQuery deserialization
    let query_zip = WeatherQuery {
        zip: Some("90210".to_string()),
        lat: None,
        lon: None,
    };

    let query_coords = WeatherQuery {
        zip: None,
        lat: Some(34.05),
        lon: Some(-118.25),
    };

    // Serialize and deserialize to ensure it works
    let json_zip = serde_json::to_string(&query_zip).unwrap();
    let deserialized_zip: WeatherQuery = serde_json::from_str(&json_zip).unwrap();
    assert_eq!(deserialized_zip.zip, Some("90210".to_string()));

    let json_coords = serde_json::to_string(&query_coords).unwrap();
    let deserialized_coords: WeatherQuery = serde_json::from_str(&json_coords).unwrap();
    assert_eq!(deserialized_coords.lat, Some(34.05));
    assert_eq!(deserialized_coords.lon, Some(-118.25));
}

#[actix_web::test]
async fn test_weather_response_serialization() {
    let response = WeatherResponse {
        location: "Los Angeles, CA".to_string(),
        weather: "Clear".to_string(),
        emoji: "☀️".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: WeatherResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.location, "Los Angeles, CA");
    assert_eq!(deserialized.weather, "Clear");
    assert_eq!(deserialized.emoji, "☀️");
}
