# ----------------------------------------
# Stage 1: Build the application
# ----------------------------------------
    FROM rust:1.86-slim-bookworm AS builder

    # Set the working directory inside the container
    WORKDIR /app
    
    # Copy the Cargo manifest files for better caching.
    COPY Cargo.toml Cargo.lock ./
    
    # Create a dummy source file to pre-cache dependencies.
    RUN mkdir src && echo "fn main() {}" > src/main.rs
    
    # Cache dependencies without building the full project.
    RUN cargo fetch
    
    # Now copy the actual project sources.
    COPY . .
    
    # Build the application in release mode.
    RUN cargo build --release
    
    # ----------------------------------------
    # Stage 2: Create the runtime image
    # ----------------------------------------
    FROM debian:stable-slim
    
    # Install runtime dependencies (ca-certificates) with minimal recommendations.
    RUN apt-get update -qq && \
        apt-get install -y --no-install-recommends ca-certificates && \
        rm -rf /var/lib/apt/lists/*
    
    # Set the working directory in the runtime image.
    WORKDIR /app
    
    # Copy the compiled binary from the builder stage.
    COPY --from=builder /app/target/release/tarnished-api .
    
    # Expose the port your application listens on.
    EXPOSE 8080
    
    # Command to run the binary.
    CMD ["./tarnished-api"]