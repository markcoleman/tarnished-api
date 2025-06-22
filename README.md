# Tarnished API

[![Rust CI](https://github.com/markcoleman/tarnished-api/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/markcoleman/tarnished-api/actions/workflows/ci.yml)

Tarnished API is a simple HTTP API built in Rust using [Actix-web](https://actix.rs) and [Paperclip](https://github.com/wafflespeanut/paperclip). This repository demonstrates how to create a well-documented REST API with automatic OpenAPI specification generation, integrated health-check endpoints, and a beautifully styled index page that displays the OpenAPI spec in a user-friendly format.

## Features

- **Health Check Endpoint:**  
  The `/api/health` endpoint returns a JSON object indicating the current status of the API (e.g., `{ "status": "healthy" }`). The response is defined using a `HealthResponse` struct and documented via Paperclip annotations.

- **Weather Information Endpoint:**  
  The `/api/weather` endpoint returns current weather information with emoji representation for a given location. Accepts either ZIP code (e.g., `?zip=90210`) or latitude/longitude coordinates (e.g., `?lat=34.05&lon=-118.25`). Returns JSON with location name, weather condition, and corresponding emoji (☀️, 🌧️, ❄️, 🌩️, etc.).

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

- **Code Security Scanning:**  
  CodeQL analysis runs on every push and pull request to the main branch, plus weekly scheduled scans, to detect potential security vulnerabilities and code quality issues in the Rust codebase.

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

### New Relic Integration
- `NEW_RELIC_LICENSE_KEY` - Your New Relic license key (enables New Relic integration when set)
- `NEW_RELIC_ENABLED` (default: `true`) - Set to `false` to disable New Relic even when license key is present
- `NEW_RELIC_SERVICE_NAME` (default: `tarnished-api`) - Service name for New Relic
- `NEW_RELIC_SERVICE_VERSION` (default: from Cargo.toml) - Service version for New Relic
- `NEW_RELIC_ENVIRONMENT` (default: `development`) - Environment name for New Relic
- `NEW_RELIC_LOG_ENDPOINT` (default: `https://log-api.newrelic.com/log/v1`) - New Relic logs endpoint

### Weather API Integration
- `OPENWEATHER_API_KEY` - **Required** - Your OpenWeatherMap API key for weather data (get one free at https://openweathermap.org/api)
- `OPENWEATHER_BASE_URL` (default: `https://api.openweathermap.org/data/2.5`) - OpenWeatherMap API base URL

## Authentication & Audit Logging Usage

The API includes comprehensive audit logging for authentication events. Here's how to use it:

### Environment Configuration

- `LOG_FORMAT=json` - Enable structured JSON logging (recommended for production)
- `RUST_LOG=info,auth_audit=info` - Set logging levels (auth_audit target for audit events)
- `AUTH_MAX_FAILURES=5` - Maximum failed attempts before flagging suspicious activity
- `AUTH_FAILURE_WINDOW=300` - Time window in seconds for failure tracking
- `NEW_RELIC_LICENSE_KEY` - Set to enable New Relic logging integration

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

### Weather Endpoint Usage

The weather endpoint provides current weather information with emoji representations:

```bash
# Get weather by ZIP code
curl "http://localhost:8080/api/weather?zip=90210"

# Response:
# {
#   "location": "Beverly Hills, US",
#   "weather": "Clear",
#   "emoji": "☀️"
# }

# Get weather by coordinates
curl "http://localhost:8080/api/weather?lat=34.05&lon=-118.25"

# Response:
# {
#   "location": "Los Angeles, US", 
#   "weather": "Rain",
#   "emoji": "🌧️"
# }
```

**Supported Weather Emojis:**
- ☀️ Clear skies
- ☁️ Cloudy conditions  
- 🌧️ Rain
- 🌦️ Light rain/drizzle
- 🌩️ Thunderstorms
- ❄️ Snow
- 🌫️ Fog, mist, or haze
- 🌬️ Windy conditions
- 🌪️ Severe weather (tornado)

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

## New Relic Observability Integration

The API includes comprehensive New Relic logging integration with the following features:

### ✅ Enhanced Structured Logging
- JSON-formatted logs compatible with New Relic log ingestion
- Automatic inclusion of trace metadata (commit SHA, Git ref, environment)
- Request correlation with unique request IDs
- HTTP request and response logging with timing metrics

### ✅ Sensitive Data Protection
- Automatic redaction of passwords, tokens, API keys, and secrets
- PII filtering (email addresses, SSN patterns, credit card numbers)
- Safe logging of authentication events without exposing credentials

### ✅ Error and Panic Capture
- Global panic handler forwarding panics to New Relic logs
- Structured error logging with stack traces and context
- Authentication failure tracking and suspicious activity detection

### ✅ Custom Metadata Fields
All logs include contextual metadata:
- `request_id` - Unique identifier for request correlation
- `commit_sha` - Git commit hash (from GITHUB_SHA)
- `git_ref` - Git branch/tag reference (from GITHUB_REF)
- `environment` - Deployment environment
- `user_agent` - Client user agent string
- `ip_address` - Client IP address
- `method` and `path` - HTTP method and request path
- `status` and `duration_ms` - Response status and timing

### ✅ CI/CD Integration
GitHub Actions workflow includes:
- Build and test step timing forwarded to New Relic
- Workflow metadata (run ID, actor, PR number, commit message)
- Automated log forwarding for build/test failures

### Example Log Output

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "target": "auth_audit",
  "fields": {
    "event_id": "550e8400-e29b-41d4-a716-446655440000",
    "event_type": "login_success",
    "outcome": "success",
    "ip_address": "192.168.1.100",
    "user_id": "admin",
    "method": "POST",
    "endpoint": "/auth/login",
    "user_agent": "curl/7.68.0",
    "commit_sha": "abc123def456",
    "git_ref": "refs/heads/main",
    "environment": "production",
    "request_id": "req_789xyz"
  },
  "message": "{\"event_id\":\"550e8400-e29b-41d4-a716-446655440000\",...}"
}
```

## Project Structure

The codebase is organized into focused modules following Rust best practices:

```
src/
├── lib.rs                 # Main library with module exports
├── main.rs               # Application entry point
├── newrelic.rs           # New Relic integration
├── config/               # Configuration structures
│   ├── mod.rs           #   Module exports
│   ├── metrics.rs       #   Metrics configuration
│   ├── rate_limit.rs    #   Rate limiting configuration
│   ├── hmac.rs          #   HMAC signature configuration
│   └── security.rs      #   Security headers configuration
├── models/               # Data structures and schemas
│   ├── mod.rs           #   Module exports
│   ├── api.rs           #   API response models
│   ├── auth.rs          #   Authentication models
│   └── audit.rs         #   Audit logging data structures
├── handlers/             # HTTP request handlers
│   ├── mod.rs           #   Module exports
│   ├── health.rs        #   Health check endpoint
│   ├── version.rs       #   Version information endpoint
│   ├── metrics.rs       #   Prometheus metrics endpoint
│   ├── auth.rs          #   Authentication endpoints
│   └── openapi.rs       #   OpenAPI spec generation
├── middleware/           # Custom middleware
│   ├── mod.rs           #   Module exports
│   ├── security.rs      #   Security headers middleware
│   ├── request_id.rs    #   Request ID tracking middleware
│   └── metrics.rs       #   Metrics collection middleware
├── services/             # Business logic services
│   ├── mod.rs           #   Module exports
│   ├── metrics.rs       #   Prometheus metrics service
│   ├── rate_limit.rs    #   Rate limiting service
│   ├── auth.rs          #   Authentication services
│   └── suspicious_activity.rs # Suspicious activity tracking
└── utils/                # Utility functions
    ├── mod.rs           #   Module exports
    ├── http.rs          #   HTTP utility functions
    ├── hmac.rs          #   HMAC signature utilities
    └── route.rs         #   Route pattern extraction
```

### Module Responsibilities

#### `models/`
Contains all data structures, request/response models, and type definitions. This includes:
- API response schemas (HealthResponse, VersionResponse)
- Authentication models (LoginRequest, LoginResponse, TokenValidationRequest)
- Audit logging structures (AuthAuditEvent, AuthEventType, AuthEventOutcome)

#### `handlers/`
HTTP request handlers that process incoming requests and generate responses:
- `health.rs` - Health check endpoint with optional HMAC validation
- `version.rs` - Version information with rate limiting
- `metrics.rs` - Prometheus metrics endpoint with toggleable collection
- `auth.rs` - Login and token validation with comprehensive audit logging
- `openapi.rs` - OpenAPI specification generation and app factory

#### `middleware/`
Custom middleware for cross-cutting concerns:
- `security.rs` - Security headers (CSP, HSTS, XSS protection, etc.)
- `request_id.rs` - Request ID generation and tracking for distributed tracing
- `metrics.rs` - Automatic metrics collection for all HTTP requests

#### `services/`
Business logic and core services:
- `metrics.rs` - Prometheus metrics collection and rendering
- `rate_limit.rs` - In-memory rate limiting with configurable limits
- `auth.rs` - HMAC signature validation and response signing
- `suspicious_activity.rs` - Failed authentication attempt tracking

#### `utils/`
Utility functions and helpers:
- `http.rs` - Client IP extraction, user agent parsing
- `hmac.rs` - HMAC-SHA256 signature generation and validation
- `route.rs` - Route pattern extraction for metrics

#### `config/`
Configuration structures with environment variable loading:
- `metrics.rs` - Metrics collection configuration
- `rate_limit.rs` - Rate limiting parameters
- `hmac.rs` - HMAC signature settings
- `security.rs` - Security headers configuration

### Developer Experience Benefits

🧭 **Improved Discoverability**: Clear module hierarchy makes finding functionality intuitive
📦 **High Modularity**: Each module has a single responsibility, enabling parallel development
🧼 **Better Maintainability**: Separation of concerns reduces bugs and accelerates code reviews
🚀 **Enhanced Developer Velocity**: New developers can quickly understand and contribute to the codebase
📚 **Comprehensive Documentation**: Each module and public function includes detailed doc comments

## GitHub Copilot Agent

🤖 **AI-Powered Development Assistance**: This repository includes a configured GitHub Copilot Agent that provides context-aware assistance tailored specifically to our Rust HTTP API development.

The Copilot Agent is configured with:
- **Project-specific knowledge**: Understanding of our Actix-web architecture, Paperclip OpenAPI patterns, and security implementations
- **Rust expertise**: Guidance on ownership, borrowing, async patterns, and error handling specific to web API development
- **Code quality standards**: Adherence to our testing patterns, security practices, and code organization conventions
- **Optimized scope**: Focused on relevant source files (`src/`, `tests/`, `examples/`) while excluding build artifacts and dependencies

### Using the Copilot Agent

The agent provides intelligent assistance for:
- Writing and refactoring Rust code with Actix-web patterns
- Implementing secure HTTP handlers with proper error handling
- Creating comprehensive tests following our established patterns  
- Adding OpenAPI documentation with Paperclip annotations
- Following our security-first development practices

Configuration details can be found in `.github/copilot.yml`, which defines the agent's understanding of our codebase structure, conventions, and best practices.

