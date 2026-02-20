# SIWE-Only Admin Auth Removal Plan

## Goal
Remove client-credentials admin auth (`/api/v1/auth/token`) and make SIWE the only admin token issuance flow.

## Scope Clarification

- Remove:
  - `/api/v1/auth/token`
  - `AUTH_CLIENT_ID`
  - `AUTH_CLIENT_SECRET`
  - `token_client_id` and `token_client_secret` config fields
- Keep:
  - `/api/v1/auth/register` for non-admin self-registration
  - `AUTH_PUBLIC_REGISTER_ENABLED` as the toggle for `/auth/register`
  - SIWE flow (`/auth/siwe/nonce`, `/auth/siwe/verify`) and `/auth/refresh`

## Why This Is Safe

- `/auth/token` currently supports only `admin-all`, so it is not used for non-admin OAuth scopes.
- SIWE now returns access + refresh tokens and already supports admin allowlist checks.

## Breaking Changes

1. `POST /api/v1/auth/token` removed.
2. `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET` no longer supported.
3. Any client/UI calling `/auth/token` must migrate to SIWE.

## Admin UI Impact

- Any UI tab or client action that requests admin JWT via client credentials must be removed or migrated.
- If another repo contains `JwtConfig.tsx` / `requestAdminToken()` that calls `/auth/token`, that code must switch to SIWE login.

## Implementation Order

1. Docs and examples update (SIWE-only messaging).
2. Backend code removal.
3. Tests and verification.

## Step-by-Step

### 1) Docs/spec first

- Update `README.md`:
  - remove `/auth/token` usage and `AUTH_CLIENT_ID`/`AUTH_CLIENT_SECRET` env docs
  - document SIWE-only admin token acquisition
- Update `api-spec/auth-api.yaml`:
  - remove `/auth/token` path
  - remove `TokenRequest` and `TokenResponse` schemas
  - update auth flow and security notes to SIWE-only for admin auth
- Update `docs/admin-authentication.md`:
  - remove "Option A: Client Credentials JWT"
  - keep SIWE as admin auth path
- Update `.env.example`:
  - remove `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET`
  - keep `AUTH_PUBLIC_REGISTER_ENABLED` if `/auth/register` stays enabled option

### 2) Remove backend client-credentials code

- `crates/solver-service/src/server.rs`:
  - remove `/auth/token` route and `handle_auth_token`
- `crates/solver-service/src/apis/auth.rs`:
  - remove `TokenRequest`, `TokenResponse`
  - remove `issue_client_token` and `issue_client_token_with_peer`
  - remove helper/rate-limiting logic used only by `/auth/token`
  - keep register/refresh/SIWE handlers
- `crates/solver-types/src/auth.rs`:
  - remove `token_client_id` and `token_client_secret` from `AuthConfig`
  - remove related defaults/tests
- `crates/solver-service/src/config_merge.rs`:
  - remove `AUTH_CLIENT_ID`/`AUTH_CLIENT_SECRET` loading/validation
  - keep `AUTH_PUBLIC_REGISTER_ENABLED` handling

### 3) Tests and verification

- Remove `/auth/token` tests and update fixtures relying on token client fields.
- Add/keep tests for:
  - SIWE admin issuance + refresh behavior
  - `/auth/register` gating via `AUTH_PUBLIC_REGISTER_ENABLED`
  - config build success without `AUTH_CLIENT_SECRET`
- Run:
  - `cargo fmt --all`
  - `cargo test -p solver-types`
  - `cargo test -p solver-service`
  - `cargo test -p solver-storage`
- Final grep sanity check:
  - `rg "AUTH_CLIENT_ID|AUTH_CLIENT_SECRET|/auth/token|token_client_id|token_client_secret"`

## Rollout Notes

- Coordinate backend and UI deployment to avoid temporary login breakage.
- If external clients still rely on `/auth/token`, communicate a migration window before release.
