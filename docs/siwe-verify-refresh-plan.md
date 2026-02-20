# SIWE Verify Refresh-Token Plan

## Goal
Update `POST /api/v1/auth/siwe/verify` so it returns the same response shape as `POST /api/v1/auth/register` (access token + refresh token + expiry metadata), while preserving existing SIWE security checks and admin allowlist enforcement.

## Current State (Reviewed)
- `POST /api/v1/auth/siwe/verify` currently returns `TokenResponse` (access token only).
- `POST /api/v1/auth/register` returns `RegisterResponse` (access + refresh + `client_id` + expiry timestamps + scopes + token type).
- SIWE verify already validates:
  - signature/address match
  - domain and chain ID
  - nonce single-use
  - signer in `auth.admin.admin_addresses`
- `/auth/refresh` already supports rotating refresh tokens for any valid subject/scope pair.

## What Is Missing
1. SIWE verify does not generate a refresh token.
2. SIWE verify does not return `RegisterResponse` fields:
  - `refresh_token`
  - `client_id`
  - `access_token_expires_at`
  - `refresh_token_expires_at`
  - `scopes`
3. OpenAPI still documents SIWE verify as access-token-only.
4. README/docs still describe SIWE as no-refresh.
5. No tests asserting SIWE verify returns refresh-capable token pairs.

## Breaking Change Warning
- This is a response-shape breaking change for existing SIWE clients.
- Current `/auth/siwe/verify` success schema (`TokenResponse`):
  - `{ access_token, token_type, expires_in, scope }`
- Proposed `/auth/siwe/verify` success schema (`RegisterResponse`):
  - `{ access_token, refresh_token, client_id, access_token_expires_at, refresh_token_expires_at, scopes, token_type }`
- Mitigation options:
  - coordinated client rollout, or
  - temporary compatibility endpoint/version.

## Recommended Contract
- Change `POST /api/v1/auth/siwe/verify` success payload from `TokenResponse` to `RegisterResponse`.
- Keep HTTP status `200`.
- `client_id` should default to SIWE signer address string (`0x...`) to remain deterministic and auditable.
- `scopes` should be `["admin-all"]`.
- Access token TTL (documented from current code):
  - `TOKEN_DEFAULT_TTL_SECONDS = 900`
  - `TOKEN_MAX_TTL_SECONDS = 3600`
  - SIWE currently uses `TOKEN_DEFAULT_TTL_SECONDS.min(TOKEN_MAX_TTL_SECONDS)`, which is 900 with current constants.
  - Plan: preserve this current SIWE access-token behavior unless explicitly changed.
- Refresh token TTL:
  - Use existing auth config (`refresh_token_expiry_hours`), same as `/auth/register`.
- Async consideration:
  - Access-token generation is sync.
  - Refresh-token generation is async (`.await`).
  - SIWE handler is already async, so this integrates directly.
- Error handling requirement:
  - If refresh-token generation fails, return the same error pattern as `/auth/register`:
    - HTTP `500`
    - `{ "error": "Failed to generate refresh token" }`
  - Keep access-token generation failure behavior unchanged (`500`, access-token error message).

## Implementation Plan
1. Update SIWE verify handler in `crates/solver-service/src/apis/auth.rs`.
2. After SIWE validation + admin allowlist check:
  - generate access token (current 900s behavior)
  - generate refresh token via `JwtService::generate_refresh_token`
  - compute `access_token_expires_at` from token claims (reuse register pattern)
  - compute `refresh_token_expires_at` from config (reuse register pattern)
  - return `RegisterResponse`
3. Keep `/auth/refresh` endpoint unchanged (already compatible with SIWE-issued refresh tokens).
4. Reuse existing DTOs/components where possible:
  - `RegisterResponse`
  - `AuthScope::AdminAll`
  - JWT helper methods already used by register/refresh.
  - error-response patterns used by register.
5. Update OpenAPI (`api-spec/auth-api.yaml`):
  - `/auth/siwe/verify` 200 schema -> `RegisterResponse`
  - examples and token lifecycle notes.
6. Update docs:
  - `README.md`
  - `docs/admin-authentication.md`
  to reflect SIWE verify now returns refresh token.

## Testing Plan
1. Add handler test: SIWE verify returns `RegisterResponse` with:
  - non-empty `access_token`
  - non-empty `refresh_token`
  - `client_id` equals signer address
  - `scopes == ["admin-all"]`
2. Add handler test: SIWE-issued refresh token works with `POST /auth/refresh` and preserves `admin-all`.
3. Add handler test: SIWE verify when auth service is disabled returns graceful failure (`503`).
4. Add handler test: SIWE-issued refresh token embeds expected scopes (`admin-all`) before refresh call.
5. Add regression test: invalid SIWE nonce/signature still fails and does not mint tokens.
6. Keep existing SIWE parser/verification tests unchanged.

## Compatibility Notes
- This is a response-shape change for existing SIWE clients that currently parse `TokenResponse`.
- If backward compatibility is required, add a transition endpoint instead of changing existing response in place.

## Optional Follow-Up
- Refactor shared token issuance logic (register + siwe verify) into a helper to avoid duplicated expiry calculations and response assembly.
