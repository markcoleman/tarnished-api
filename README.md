# Tarnished API

[![Rust CI](https://github.com/markcoleman/tarnished-api/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/markcoleman/tarnished-api/actions/workflows/ci.yml)

Tarnished API is a simple HTTP API built in Rust using [Actix-web](https://actix.rs) and [Paperclip](https://github.com/wafflespeanut/paperclip). This repository demonstrates how to create a well-documented REST API with automatic OpenAPI specification generation, integrated health-check endpoints, and a beautifully styled index page that displays the OpenAPI spec in a user-friendly format.

## Features

- **Health Check Endpoint:**  
  The `/api/health` endpoint returns a JSON object indicating the current status of the API (e.g., `{ "status": "healthy" }`). The response is defined using a `HealthResponse` struct and documented via Paperclip annotations.

- **Security Headers:**  
  All HTTP responses include modern security headers to protect against common vulnerabilities:
  - `X-Content-Type-Options: nosniff` - Prevents MIME type sniffing
  - `X-Frame-Options: DENY` - Prevents clickjacking attacks
  - `X-XSS-Protection: 1; mode=block` - Enables browser XSS protection
  - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` - Prevents various injection attacks
  - `Referrer-Policy: no-referrer` - Controls referrer information

- **OpenAPI Specification:**  
  The API automatically generates and serves an OpenAPI (Swagger) spec at `/api/spec/v2`. This helps you quickly integrate with other services and document your API.

- **Index Page:**  
  The root route (`/`) serves an `index.html` file that uses JavaScript to fetch the OpenAPI spec and pretty print it. This provides a quick way to view the API documentation in your browser.

- **Authentication & Audit Logging:**  
  The API includes sample authentication endpoints (`/auth/login` and `/auth/validate`) with comprehensive audit logging. All authentication events are logged in structured JSON format including timestamps, IP addresses, user IDs, methods, and outcomes. Logs can be configured for different verbosity levels and are suitable for forwarding to observability platforms like New Relic.

- **Continuous Integration:**  
  GitHub Actions is configured to run tests, build the project, and run lint checks (using Clippy) on pull requests and pushes to the main branch, providing early and fast feedback.

- **Dependabot:**  
  Dependabot is configured to monitor Cargo dependencies and devcontainer configurations, keeping the project up-to-date with minimal effort.


- **Software Bill of Materials (SBOM):**  
  Every build generates verifiable SBOMs in both CycloneDX and SPDX formats using syft. SBOMs are cryptographically signed using cosign with keyless OIDC signing, attached to Docker images, and uploaded as artifacts for supply chain transparency and vulnerability tracking.

## Configuration

The API can be configured using environment variables:

### Security Headers
- `SECURITY_CSP_ENABLED` (default: `true`) - Set to `false` to disable Content-Security-Policy header for development ease

### Rate Limiting  
- `RATE_LIMIT_RPM` (default: `100`) - Number of requests allowed per minute
- `RATE_LIMIT_PERIOD` (default: `60`) - Time window in seconds for rate limiting
## Authentication & Audit Logging Usage

The API includes comprehensive audit logging for authentication events. Here's how to use it:

### Environment Configuration

- `LOG_FORMAT=json` - Enable structured JSON logging (recommended for production)
- `RUST_LOG=info,auth_audit=info` - Set logging levels (auth_audit target for audit events)
- `AUTH_MAX_FAILURES=5` - Maximum failed attempts before flagging suspicious activity
- `AUTH_FAILURE_WINDOW=300` - Time window in seconds for failure tracking

### Authentication Endpoints

```bash
# Successful login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password123"}'

# Failed login (triggers audit log)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "wrongpassword"}'

# Token validation
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "token_12345"}'
```

### Audit Log Format

Audit events are logged in structured JSON format:

```json
{
  "event_id": "095b5c8f-ce3e-4bd6-ab4e-8dcc1d9efe30",
  "timestamp": "2025-06-15T18:15:53.687746775Z",
  "event_type": "login_success",
  "outcome": "success",
  "ip_address": "127.0.0.1",
  "user_id": "admin",
  "method": "POST",
  "endpoint": "/auth/login",
  "user_agent": "TestClient/1.0",
  "details": null
}
```
