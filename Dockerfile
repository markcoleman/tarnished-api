# ----------------------------------------
# Stage 1: Build the application
# ----------------------------------------
    FROM rust:slim-bullseye AS builder

    # Set the working directory inside the container
    WORKDIR /app
    
    # Copy the Cargo manifest files first for better caching
    COPY Cargo.toml Cargo.lock ./
    
    # Create a dummy source file to pre-cache dependencies
    RUN mkdir src && echo "fn main() {}" > src/main.rs
    
    # Cache dependencies without building the full project
    RUN cargo fetch
    
    # Copy the entire project source code
    COPY . .
    
    # Build the application in release mode
    RUN cargo build --release
    
    # ----------------------------------------
    # Stage 2: Create the runtime image
    # ----------------------------------------
    FROM debian:stable-slim
    
    # Install any additional runtime dependencies if needed (optional)
    RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
    
    # Set the working directory in the runtime image
    WORKDIR /app
    
    # Copy the compiled binary from the builder stage (adjust binary name as needed)
    COPY --from=builder /app/target/release/tarnished-api .
    
    # Expose the port your application listens on (e.g., 8080)
    EXPOSE 8080
    
    # Command to run the binary
    CMD ["./tarnished-api"]