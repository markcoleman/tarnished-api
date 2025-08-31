# Tarnished API Development Tasks
# 
# A collection of common development commands for the Tarnished API project.
# Install just: https://github.com/casey/just
#
# Usage: just <command>
# Examples:
#   just test      # Run all tests
#   just dev       # Start development server
#   just lint      # Run linter and formatter

# Default recipe - show available commands
default:
    @just --list

# Install development dependencies and tools
setup:
    @echo "🔧 Setting up development environment..."
    cargo install cargo-watch cargo-audit cargo-outdated
    @echo "✅ Development setup complete!"

# Format code using rustfmt
fmt:
    @echo "🎨 Formatting code..."
    cargo fmt

# Check code formatting without applying changes
fmt-check:
    @echo "🔍 Checking code formatting..."
    cargo fmt --check

# Run clippy linter
lint:
    @echo "🔍 Running clippy linter..."
    cargo clippy -- -D warnings

# Fix clippy warnings automatically where possible
lint-fix:
    @echo "🔧 Auto-fixing clippy warnings..."
    cargo clippy --fix --allow-dirty --allow-staged

# Run all tests
test:
    @echo "🧪 Running tests..."
    cargo test

# Run tests with output shown
test-verbose:
    @echo "🧪 Running tests (verbose)..."
    cargo test -- --nocapture

# Run integration tests only
test-integration:
    @echo "🧪 Running integration tests..."
    cargo test --test integration_tests

# Check code compilation without running
check:
    @echo "🔍 Checking code compilation..."
    cargo check

# Build the project in debug mode
build:
    @echo "🔨 Building project (debug)..."
    cargo build

# Build the project in release mode
build-release:
    @echo "🔨 Building project (release)..."
    cargo build --release

# Run the development server with auto-reload
dev:
    @echo "🚀 Starting development server with auto-reload..."
    cargo watch -x run

# Run the server directly
run:
    @echo "🚀 Starting server..."
    cargo run

# Run security audit
audit:
    @echo "🔒 Running security audit..."
    cargo audit

# Check for outdated dependencies
outdated:
    @echo "📦 Checking for outdated dependencies..."
    cargo outdated

# Clean build artifacts
clean:
    @echo "🧹 Cleaning build artifacts..."
    cargo clean

# Run all quality checks (format, lint, test)
check-all: fmt-check lint test
    @echo "✅ All quality checks passed!"

# Fix all auto-fixable issues and run tests
fix-all: fmt lint-fix test
    @echo "✅ All fixes applied and tests passed!"

# Build Docker image
docker-build tag="tarnished-api:latest":
    @echo "🐳 Building Docker image: {{tag}}"
    docker build -t {{tag}} .

# Run Docker container
docker-run port="8080":
    @echo "🐳 Running Docker container on port {{port}}"
    docker run -p {{port}}:8080 tarnished-api:latest

# Deploy to local Kubernetes (requires kubectl and kind)
k8s-deploy:
    @echo "☸️  Deploying to local Kubernetes..."
    ./scripts/deploy-local.sh

# Generate and open API documentation
docs:
    @echo "📚 Generating documentation..."
    cargo doc --open

# Run HMAC demo example
example-hmac:
    @echo "🔐 Running HMAC signature demo..."
    cargo run --example hmac_demo

# Run development server example
example-dev-server:
    @echo "🚀 Running development server demo..."
    cargo run --example dev_server

# Run API client example (requires server to be running)
example-client:
    @echo "📡 Running API client demo..."
    cargo run --example api_client

# Show project statistics
stats:
    @echo "📊 Project statistics:"
    @echo "Lines of Rust code:"
    @find src -name "*.rs" -exec wc -l {} + | tail -1
    @echo "Number of tests:"
    @grep -r "#\[.*test\]" src tests --include="*.rs" | wc -l
    @echo "Dependencies:"
    @grep "^[a-zA-Z]" Cargo.toml | wc -l

# Show environment info
env:
    @echo "🌍 Development environment info:"
    @echo "Rust version: $(rustc --version)"
    @echo "Cargo version: $(cargo --version)"
    @echo "Current directory: $(pwd)"
    @echo "Git branch: $(git branch --show-current 2>/dev/null || echo 'not in git repo')"