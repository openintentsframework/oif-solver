# ------------------------------------------------------------------------------
# Build environment
# ------------------------------------------------------------------------------
# Rustc v1.86.0
FROM cgr.dev/chainguard/rust:latest-dev@sha256:33faad9a26e8437ed9725bea3eb2d1e85facd1c035a31af8d485ea8c0a935532 AS builder

# Optional features (e.g., "kms" for AWS KMS signer support)
ARG FEATURES=""

USER root
RUN apk update && apk --no-cache add \
    openssl-dev \
    perl

ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig

WORKDIR /usr/app

# Copy source code
COPY . .

# Build with cargo cache mounts for faster rebuilds
# If FEATURES is set, add --features flag
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/app/target \
    if [ -n "$FEATURES" ]; then \
      cargo install --root /usr/app --path crates/solver-service --features "$FEATURES" --locked; \
    else \
      cargo install --root /usr/app --path crates/solver-service --locked; \
    fi

# ------------------------------------------------------------------------------
# Runtime environment
# ------------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base@sha256:417d791afa234c538bca977fe0f44011d2381e60a9fde44c938bd17b9cc38f66

WORKDIR /app

# Copy the compiled binary
COPY --from=builder --chown=nonroot:nonroot /usr/app/bin/solver /app/solver

USER nonroot

# Expose the default API port
EXPOSE 3000

# Set default environment variables
ENV RUST_LOG=info
ENV REDIS_URL=redis://localhost:6379

# Configuration is seeded to Redis on first run, then loaded automatically.
# See config/example.env.docker for required environment variables.
#
# First run (seed configuration):
#   docker run --env-file .env.docker -v $(pwd)/config:/app/config:ro oif-solver \
#     --seed testnet --seed-overrides /app/config/seed-overrides-testnet.json
#
# Subsequent runs (load from Redis):
#   docker run --env-file .env.docker -e SOLVER_ID=your-solver-id oif-solver
#
# With KMS (build with: docker build --build-arg FEATURES=kms -t oif-solver .):
#   docker run --env-file .env.docker -v $(pwd)/config:/app/config:ro oif-solver \
#     --seed testnet --seed-overrides /app/config/seed-overrides-kms.json
ENTRYPOINT ["/app/solver"]
