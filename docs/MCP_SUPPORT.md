# Model Context Protocol (MCP) Support

The Tarnished API now supports the Model Context Protocol (MCP) alongside standard REST conventions, enabling context-aware interactions while maintaining full backward compatibility.

## Overview

MCP support allows clients to include context metadata in requests and receive enriched responses with trace information, model versioning, and timing data. This is particularly useful for:

- Agent-based systems that need request tracking
- Orchestrated workflows requiring correlation IDs
- Debugging and observability across service boundaries
- Context propagation in distributed systems

## How It Works

### Request Detection

The API automatically detects MCP-aware requests by checking for specific headers:

- `X-MCP-Context`: Indicates an MCP-aware request
- `X-Client`: Client identifier for MCP requests  
- `X-Trace-ID`: Trace identifier for request tracking
- `X-Correlation-ID`: Optional correlation ID for linking related requests

### Response Formats

#### Standard REST Response (No MCP Headers)
```json
{
  "status": "healthy"
}
```

#### MCP-Enhanced Response (With MCP Headers)
```json
{
  "data": {
    "status": "healthy"
  },
  "context": {
    "trace_id": "550e8400-e29b-41d4-a716-446655440000",
    "model_version": "0.1.0",
    "timestamp": "2024-01-01T12:00:00Z",
    "correlation_id": "user-provided-correlation-id",
    "client_id": "my-agent-client"
  }
}
```

## Usage Examples

### Standard REST Client
```bash
# Traditional REST call - no change required
curl http://localhost:8080/api/health
# Returns: {"status": "healthy"}
```

### MCP-Aware Client
```bash
# Request with MCP context
curl -H "X-MCP-Context: true" \
     -H "X-Client: my-agent" \
     http://localhost:8080/api/health

# Returns wrapped response with context metadata
```

### Custom Trace Propagation
```bash
# Propagate custom trace and correlation IDs
curl -H "X-Trace-ID: my-trace-123" \
     -H "X-Client: orchestrator" \
     -H "X-Correlation-ID: workflow-456" \
     http://localhost:8080/api/version
```

## Backward Compatibility

**Zero Breaking Changes**: All existing clients continue to work exactly as before. The MCP support is purely additive:

- REST clients receive responses in the original format
- Field access patterns remain unchanged (`response.status` still works)
- No wrapper objects are introduced for non-MCP requests
- All existing tests pass without modification

## Implementation Details

### Smart Serialization

The `McpResponse<T>` type uses custom serialization logic:

```rust
// REST mode: serialize data directly
{"status": "healthy"}

// MCP mode: serialize with wrapper
{"data": {"status": "healthy"}, "context": {...}}
```

### Middleware Integration

The MCP middleware is integrated into the request pipeline:

1. **Detection**: Check for MCP headers in incoming requests
2. **Context Creation**: Generate or extract context metadata
3. **Storage**: Store context in request extensions
4. **Handler Access**: Handlers can access context via helper functions
5. **Response Wrapping**: Conditionally wrap responses based on context presence

### Supported Endpoints

Currently, the following endpoints support MCP:

- `/api/health` - Health check with optional context
- `/api/version` - Version info with optional context

Additional endpoints can easily be converted by:
1. Updating the handler to return `McpResponse<T>`
2. Using `extract_mcp_context()` to check for MCP context
3. Conditionally wrapping the response

## Configuration

No additional configuration is required. MCP support is automatically available and clients can opt-in by including the appropriate headers.

## Monitoring and Observability

MCP requests are logged with trace information:

```
DEBUG mcp_middleware: MCP request detected trace_id="abc-123" client_id="my-agent"
DEBUG health_handler: Returning MCP-enhanced health response trace_id="abc-123"
```

## OpenAPI Documentation

The OpenAPI specification has been updated to document:
- MCP header requirements
- Response format variations
- Example request/response pairs for both modes

Access the interactive documentation at `/api/spec/v2` when running the server.

## Testing

Comprehensive test coverage includes:
- REST-only request scenarios
- MCP-enabled request scenarios  
- Context propagation validation
- Backward compatibility verification
- Malformed header handling

Run the tests:
```bash
cargo test mcp_integration_tests
```

## Demo

Run the included demo script to see MCP in action:
```bash
./demo_mcp.sh
```

This will start the server and demonstrate the differences between REST and MCP responses.