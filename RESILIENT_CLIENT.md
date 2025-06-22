# Resilient HTTP Client

This module provides a resilient HTTP client with built-in retry logic, timeouts, and circuit breakers for improved API reliability.

## Features

- **Exponential Backoff with Jitter**: Automatically retries failed requests with increasing delays and random jitter to prevent thundering herd problems
- **Configurable Timeouts**: Separate timeouts for read (1s default) and write (5s default) operations
- **Circuit Breaker**: Prevents cascading failures by temporarily blocking requests to failing services
- **Comprehensive Metrics**: Prometheus metrics for monitoring retries, timeouts, and circuit breaker states
- **Rich Logging**: Detailed tracing logs with request context, retry counts, and failure reasons
- **Environment Configuration**: Full configuration via environment variables with sensible defaults

## Usage

### Basic Usage

```rust
use tarnished_api::{ResilientClient, ResilientClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use default configuration
    let config = ResilientClientConfig::default();
    let mut client = ResilientClient::new(config, None)?;
    
    // Make a GET request with automatic retries
    let response = client.get("https://api.example.com/data").await?;
    println!("Status: {}", response.status());
    
    // Make a POST request with JSON payload
    let data = serde_json::json!({"key": "value"});
    let response = client.post("https://api.example.com/create", &data).await?;
    
    Ok(())
}
```

### With Metrics

```rust
use tarnished_api::{ResilientClient, ResilientClientConfig, ResilientClientMetrics};
use prometheus::Registry;

let config = ResilientClientConfig::default();
let registry = Registry::new();
let metrics = ResilientClientMetrics::new(&registry)?;
let mut client = ResilientClient::new(config, Some(metrics))?;

// All requests will now be tracked in Prometheus metrics
let response = client.get("https://api.example.com/data").await?;
```

### Environment Configuration

Set environment variables to customize behavior:

```bash
# Timeout configuration (in seconds)
export RESILIENT_CLIENT_READ_TIMEOUT=2
export RESILIENT_CLIENT_WRITE_TIMEOUT=10
export RESILIENT_CLIENT_CONNECT_TIMEOUT=5

# Retry configuration
export RESILIENT_CLIENT_RETRY_MAX_ATTEMPTS=5
export RESILIENT_CLIENT_RETRY_INITIAL_DELAY_MS=200
export RESILIENT_CLIENT_RETRY_MAX_DELAY_MS=10000
export RESILIENT_CLIENT_RETRY_JITTER_FACTOR=0.2
export RESILIENT_CLIENT_RETRY_ON_STATUS="408,429,500,502,503,504"

# Circuit breaker configuration
export RESILIENT_CLIENT_CB_FAILURE_THRESHOLD=10
export RESILIENT_CLIENT_CB_SUCCESS_THRESHOLD=5
export RESILIENT_CLIENT_CB_TIMEOUT_SECONDS=120

# Logging
export RESILIENT_CLIENT_DETAILED_LOGGING=true
```

Then load the configuration:

```rust
let config = ResilientClientConfig::from_env();
let mut client = ResilientClient::new(config, None)?;
```

## Error Handling

The client provides user-friendly error messages suitable for API responses:

```rust
match client.get("https://api.example.com/data").await {
    Ok(response) => {
        // Handle successful response
    }
    Err(error) => {
        // Get user-friendly error message
        let message = error.user_message();
        println!("Error: {}", message);
        
        // Examples:
        // "Service temporarily unavailable due to timeout"
        // "Service temporarily unavailable, please try again later"
        // "Service returned error status 503, please try again"
    }
}
```

## Metrics

The following Prometheus metrics are automatically collected:

- `resilient_http_requests_total` - Total HTTP requests by destination, method, and outcome
- `resilient_http_request_duration_seconds` - Request duration histogram
- `resilient_http_retry_attempts_total` - Retry attempts by destination and reason
- `resilient_http_circuit_breaker_state` - Circuit breaker state (0=closed, 1=open, 2=half-open)
- `resilient_http_timeouts_total` - Timeout occurrences by destination and type

## Integration with Existing Services

The resilient client integrates seamlessly with the existing tarnished-api infrastructure:

- **New Relic**: Metrics are compatible with New Relic dashboards
- **Tracing**: Uses the same tracing infrastructure for consistent logging
- **Configuration**: Follows the same environment-based configuration patterns
- **Error Handling**: Consistent error types and user messaging

## Circuit Breaker Behavior

The circuit breaker implements a three-state pattern:

1. **Closed**: Normal operation, all requests allowed
2. **Open**: Service is failing, requests are blocked
3. **Half-Open**: Testing if service has recovered

The circuit opens after reaching the failure threshold and stays open for the configured timeout period. During half-open state, a limited number of requests are allowed to test service recovery.

## Production Recommendations

For production deployments:

- Set `RESILIENT_CLIENT_READ_TIMEOUT=1` for fast read operations
- Set `RESILIENT_CLIENT_WRITE_TIMEOUT=5` for write operations that may take longer
- Configure `RESILIENT_CLIENT_CB_FAILURE_THRESHOLD` based on your service's expected failure rate
- Enable detailed logging during initial deployment, then disable for performance
- Monitor the circuit breaker metrics to identify problematic dependencies
- Use jitter factor between 0.1-0.3 to prevent synchronized retries across instances