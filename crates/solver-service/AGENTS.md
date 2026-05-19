# solver-service — Agent Guide

The HTTP service binary. Produces the `solver` binary. Every other `solver-*` crate is a library consumed by this one or by `solver-demo`.

## What lives here vs elsewhere

This crate is the HTTP shell: Axum handlers, server wiring, auth middleware, request/response types. Orchestration logic belongs in `solver-core`; persistence behind traits in `solver-storage`; signing in `solver-account`. Do not add cross-crate business logic here.

## Feature flags

- `kms` — gates AWS KMS signers via `solver-account/kms`. Default off (local signing). Enable with `--features kms`.

## Required environment at startup

See root `AGENTS.md` for the full list. The ones this crate reads directly:

- `REDIS_URL` (default `redis://localhost:6379`)
- `STORAGE_BACKEND` (`redis` default, `file` alternative)
- `STORAGE_PATH` (used only with file backend)

## Config loading

Runtime configuration is assembled in `src/config_merge.rs`. That file is the seed-override + env-var entry point: `REDIS_URL` and `STORAGE_BACKEND` are read here directly, and seed templates are overridden by user-supplied `SeedOverrides`. **Read `config_merge.rs` before changing how config is loaded.**

`src/server.rs` also reads `REDIS_URL` independently for the admin Redis client.

## Run locally

```
cargo run -p solver-service
```

Or, since `solver-service` is a default member:

```
cargo run --bin solver
```
