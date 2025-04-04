# Tarnished API

Tarnished API is a simple HTTP API built in Rust using [Actix-web](https://actix.rs) and [Paperclip](https://github.com/wafflespeanut/paperclip). This repository demonstrates how to create a well-documented REST API with automatic OpenAPI specification generation, integrated health-check endpoints, and a beautifully styled index page that displays the OpenAPI spec in a user-friendly format.

## Features

- **Health Check Endpoint:**  
  The `/api/health` endpoint returns a JSON object indicating the current status of the API (e.g., `{ "status": "healthy" }`). The response is defined using a `HealthResponse` struct and documented via Paperclip annotations.

- **OpenAPI Specification:**  
  The API automatically generates and serves an OpenAPI (Swagger) spec at `/api/spec/v2`. This helps you quickly integrate with other services and document your API.

- **Index Page:**  
  The root route (`/`) serves an `index.html` file that uses JavaScript to fetch the OpenAPI spec and pretty print it. This provides a quick way to view the API documentation in your browser.

- **Continuous Integration:**  
  GitHub Actions is configured to run tests, build the project, and run lint checks (using Clippy) on pull requests and pushes to the main branch, providing early and fast feedback.

- **Dependabot:**  
  Dependabot is configured to monitor Cargo dependencies and devcontainer configurations, keeping the project up-to-date with minimal effort.
