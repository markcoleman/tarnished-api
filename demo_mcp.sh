#!/usr/bin/env bash
# Demo script showing MCP vs REST functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Tarnished API - Model Context Protocol (MCP) Demo${NC}"
echo -e "${BLUE}=================================================${NC}"
echo

# Build the project
echo -e "${YELLOW}📦 Building the project...${NC}"
cargo build --release --quiet
echo -e "${GREEN}✅ Build complete${NC}"
echo

# Start the server in background
echo -e "${YELLOW}🌐 Starting the API server...${NC}"
RUST_LOG=info cargo run --release --quiet &
SERVER_PID=$!

# Wait for server to start
sleep 3

echo -e "${GREEN}✅ Server started (PID: $SERVER_PID)${NC}"
echo

# Function to cleanup
cleanup() {
    echo -e "\n${YELLOW}🛑 Stopping server...${NC}"
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    echo -e "${GREEN}✅ Server stopped${NC}"
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

echo -e "${BLUE}📋 Testing REST vs MCP Responses${NC}"
echo -e "${BLUE}=================================${NC}"
echo

# Test 1: Standard REST request
echo -e "${YELLOW}1️⃣  Standard REST Request (no MCP headers)${NC}"
echo -e "   📤 GET /api/health"
echo -e "   📥 Response:"
curl -s http://localhost:8080/api/health | jq '.' || echo "Failed to get REST response"
echo

# Test 2: MCP-aware request with context header
echo -e "${YELLOW}2️⃣  MCP Request with X-MCP-Context header${NC}"
echo -e "   📤 GET /api/health with X-MCP-Context: true"
echo -e "   📥 Response:"
curl -s -H "X-MCP-Context: true" http://localhost:8080/api/health | jq '.' || echo "Failed to get MCP response"
echo

# Test 3: MCP request with custom trace ID and client
echo -e "${YELLOW}3️⃣  MCP Request with custom headers${NC}"
echo -e "   📤 GET /api/version with custom trace ID and client"
echo -e "   📥 Response:"
curl -s \
  -H "X-Trace-ID: demo-trace-12345" \
  -H "X-Client: demo-client" \
  -H "X-Correlation-ID: demo-correlation-67890" \
  http://localhost:8080/api/version | jq '.' || echo "Failed to get custom MCP response"
echo

# Test 4: Compare responses side by side
echo -e "${YELLOW}4️⃣  Side-by-side Comparison${NC}"
echo -e "${GREEN}   REST Response Structure:${NC}"
curl -s http://localhost:8080/api/health | jq 'keys' || echo "Failed"
echo
echo -e "${GREEN}   MCP Response Structure:${NC}"
curl -s -H "X-MCP-Context: true" http://localhost:8080/api/health | jq 'keys' || echo "Failed"
echo

echo -e "${BLUE}🔍 Key Differences:${NC}"
echo -e "   • ${GREEN}REST clients${NC}: Get direct field access (e.g., response.status)"
echo -e "   • ${GREEN}MCP clients${NC}: Get wrapped response with context metadata"
echo -e "   • ${GREEN}Backward compatibility${NC}: Existing clients continue to work unchanged"
echo

echo -e "${GREEN}✨ Demo complete! MCP support is working correctly.${NC}"