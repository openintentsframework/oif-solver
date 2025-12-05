# ------------------------------------------------------------------------------
# Build environment
# ------------------------------------------------------------------------------
# Rustc v1.86.0
FROM cgr.dev/chainguard/rust:latest-dev@sha256:33faad9a26e8437ed9725bea3eb2d1e85facd1c035a31af8d485ea8c0a935532 AS builder

USER root
RUN apk update && apk --no-cache add \
    openssl-dev \
    perl

ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig

WORKDIR /usr/app

# Copy source code
COPY . .

# Build with cargo cache mounts for faster rebuilds
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/app/target \
    cargo install --root /usr/app --path crates/solver-service --locked

# ------------------------------------------------------------------------------
# Runtime environment
# ------------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base

WORKDIR /app

# Copy the compiled binary
COPY --from=builder --chown=nonroot:nonroot /usr/app/bin/solver /app/solver

# Remove unnecessary tools for smaller attack surface
USER root
RUN apk del wolfi-base apk-tools

USER nonroot

# Expose the default API port
EXPOSE 3000

# Set default environment variables
ENV RUST_LOG=info

# Config must be mounted at runtime via volume mount
# Example: docker run -v $(pwd)/config:/app/config:ro oif-solver --config /app/config/testnet.toml
ENTRYPOINT ["/app/solver"]
