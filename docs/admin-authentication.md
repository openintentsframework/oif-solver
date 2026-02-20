# Admin Authentication Guide

This guide covers admin authentication for `/api/v1/admin/*` endpoints.

## Configuration

Admin wallet addresses must be configured under `auth.admin.admin_addresses`:

```json
{
  "admin": {
    "enabled": true,
    "domain": "localhost",
    "admin_addresses": ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]
  }
}
```

Any signer in `admin_addresses` is authorized for SIWE login and EIP-712 admin action checks.

## Nonce Endpoints

- `POST /api/v1/auth/siwe/nonce`: SIWE login nonce (used before `/auth/siwe/verify`).
- `POST /api/v1/admin/nonce` (and GET alias): EIP-712 admin-action nonce (used for signed admin actions).

These serve different signing domains and should remain separate.

## SIWE JWT (Wallet Login)

```bash
ADMIN_ADDRESS=0xYourAdminWalletAddress

# 1) Request nonce + canonical SIWE message
NONCE_RESPONSE=$(curl -s -X POST http://localhost:3000/api/v1/auth/siwe/nonce \
  -H "Content-Type: application/json" \
  -d "{\"address\":\"$ADMIN_ADDRESS\"}")

SIWE_MESSAGE=$(echo "$NONCE_RESPONSE" | jq -r '.message')

# 2) Sign SIWE_MESSAGE with your wallet
SIWE_SIGNATURE=0x...

# 3) Verify and receive access + refresh tokens
SIWE_TOKENS=$(curl -s -X POST http://localhost:3000/api/v1/auth/siwe/verify \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg message "$SIWE_MESSAGE" --arg signature "$SIWE_SIGNATURE" '{message: $message, signature: $signature}')")

TOKEN=$(echo "$SIWE_TOKENS" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$SIWE_TOKENS" | jq -r '.refresh_token')
```

`/auth/siwe/verify` returns:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "client_id": "0x...",
  "access_token_expires_at": 1771463174,
  "refresh_token_expires_at": 1774051574,
  "scopes": ["admin-all"],
  "token_type": "Bearer"
}
```

## Refresh SIWE Tokens

SIWE refresh tokens can be rotated using `/api/v1/auth/refresh`:

```bash
curl -s -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg refresh_token "$REFRESH_TOKEN" '{refresh_token: $refresh_token}')"
```

## Calling Admin Endpoints

```bash
curl http://localhost:3000/api/v1/admin/config \
  -H "Authorization: Bearer $TOKEN"
```
