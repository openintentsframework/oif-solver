# ------------------------------------------------------------------------------
# Build environment
# ------------------------------------------------------------------------------
    FROM rust:1.86-bookworm AS builder

    # Install build dependencies
    RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        && rm -rf /var/lib/apt/lists/*
    
    WORKDIR /app
    
    # Copy manifests first for better layer caching
    COPY Cargo.toml Cargo.lock ./
    COPY crates/solver-account/Cargo.toml crates/solver-account/
    COPY crates/solver-config/Cargo.toml crates/solver-config/
    COPY crates/solver-core/Cargo.toml crates/solver-core/
    COPY crates/solver-delivery/Cargo.toml crates/solver-delivery/
    COPY crates/solver-demo/Cargo.toml crates/solver-demo/
    COPY crates/solver-discovery/Cargo.toml crates/solver-discovery/
    COPY crates/solver-order/Cargo.toml crates/solver-order/
    COPY crates/solver-pricing/Cargo.toml crates/solver-pricing/
    COPY crates/solver-service/Cargo.toml crates/solver-service/
    COPY crates/solver-settlement/Cargo.toml crates/solver-settlement/
    COPY crates/solver-storage/Cargo.toml crates/solver-storage/
    COPY crates/solver-types/Cargo.toml crates/solver-types/
    
    # Create dummy source files to build dependencies
    RUN mkdir -p crates/solver-account/src && echo "fn main() {}" > crates/solver-account/src/lib.rs \
        && mkdir -p crates/solver-config/src && echo "fn main() {}" > crates/solver-config/src/lib.rs \
        && mkdir -p crates/solver-core/src && echo "fn main() {}" > crates/solver-core/src/lib.rs \
        && mkdir -p crates/solver-delivery/src && echo "fn main() {}" > crates/solver-delivery/src/lib.rs \
        && mkdir -p crates/solver-demo/src && echo "fn main() {}" > crates/solver-demo/src/main.rs \
        && mkdir -p crates/solver-discovery/src && echo "fn main() {}" > crates/solver-discovery/src/lib.rs \
        && mkdir -p crates/solver-order/src && echo "fn main() {}" > crates/solver-order/src/lib.rs \
        && mkdir -p crates/solver-pricing/src && echo "fn main() {}" > crates/solver-pricing/src/lib.rs \
        && mkdir -p crates/solver-service/src && echo "fn main() {}" > crates/solver-service/src/main.rs \
        && mkdir -p crates/solver-settlement/src && echo "fn main() {}" > crates/solver-settlement/src/lib.rs \
        && mkdir -p crates/solver-storage/src && echo "fn main() {}" > crates/solver-storage/src/lib.rs \
        && mkdir -p crates/solver-types/src && echo "fn main() {}" > crates/solver-types/src/lib.rs
    
    # Build dependencies only (this layer will be cached)
    RUN cargo build --release --package solver-service 2>/dev/null || true
    
    # Remove dummy source files
    RUN find crates -name "*.rs" -delete
    
    # Copy actual source code
    COPY crates crates
    
    # Touch the source files to ensure they're newer than the cached build
    RUN find crates -name "*.rs" -exec touch {} +
    
    # Build the actual application
    RUN cargo build --release --package solver-service
    
    # ------------------------------------------------------------------------------
    # Runtime environment
    # ------------------------------------------------------------------------------
    FROM debian:bookworm-slim AS runtime
    
    # Install runtime dependencies
    RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        && rm -rf /var/lib/apt/lists/*
    
    # Create non-root user for security
    RUN groupadd --gid 1000 solver \
        && useradd --uid 1000 --gid solver --shell /bin/bash --create-home solver
    
    WORKDIR /app
    
    # Copy the compiled binary
    COPY --from=builder /app/target/release/solver /app/solver
    
    # Create config directory
    RUN mkdir -p /app/config && chown -R solver:solver /app
    
    # Switch to non-root user
    USER solver
    
    # Expose the default API port
    EXPOSE 3000
    
    # Health check
    HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
        CMD curl -f http://localhost:3000/health || exit 1 1Code has comments. Press enter to view.
    
    # Set default environment variables
    ENV RUST_LOG=info
    ENV CONFIG_FILE=/app/config/config.toml
    
    # Default command
    ENTRYPOINT ["/app/solver"]
    CMD ["--config", "/app/config/config.toml"]