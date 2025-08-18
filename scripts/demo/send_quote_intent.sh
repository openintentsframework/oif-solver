#!/usr/bin/env bash

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_BASE="${1:-http://127.0.0.1:3000}"
QUOTE_ENDPOINT="$API_BASE/api/quotes"
ORDERS_ENDPOINT="$API_BASE/api/orders"

echo -e "${BLUE}🎯 Requesting quote and submitting signed intent${NC}"
echo -e "${YELLOW}API:${NC} $API_BASE"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo -e "${RED}$1 not found${NC}"; exit 1; }; }
need_cmd jq
need_cmd curl

if [ ! -f "config/demo.toml" ]; then
  echo -e "${RED}Missing config/demo.toml${NC}"; exit 1
fi

# Parse config values
ORIGIN_CHAIN_ID=31337
DEST_CHAIN_ID=31338

USER_ADDR=$(grep -A 4 '\[accounts\]' config/demo.toml | grep 'user = ' | head -1 | cut -d'"' -f2)
RECIPIENT_ADDR=$(grep -A 4 '\[accounts\]' config/demo.toml | grep 'recipient = ' | head -1 | cut -d'"' -f2)

TOKENA_ORIGIN=$(awk '/\[\[networks.31337.tokens\]\]/{f=1} f && /address =/{gsub(/"/, "", $3); print $3; exit}' config/demo/networks.toml)
TOKENA_DEST=$(awk '/\[\[networks.31338.tokens\]\]/{f=1} f && /address =/{gsub(/"/, "", $3); print $3; exit}' config/demo/networks.toml)

# Build ERC-7930 interop addresses (UII) for demo chains
to_uii() {
  local chain_id="$1"; local evm_addr="$2"
  local chain_ref=""
  if [ "$chain_id" = "31337" ]; then chain_ref="7a69"; fi
  if [ "$chain_id" = "31338" ]; then chain_ref="7a6a"; fi
  local clean_addr=$(echo "$evm_addr" | sed 's/^0x//')
  echo "0x0100000214${chain_ref}${clean_addr}"
}

USER_UII_ORIGIN=$(to_uii $ORIGIN_CHAIN_ID $USER_ADDR)
RECIPIENT_UII_DEST=$(to_uii $DEST_CHAIN_ID $RECIPIENT_ADDR)
TOKENA_UII_ORIGIN=$(to_uii $ORIGIN_CHAIN_ID $TOKENA_ORIGIN)
TOKENA_UII_DEST=$(to_uii $DEST_CHAIN_ID $TOKENA_DEST)

ONE="1000000000000000000"

QUOTE_PAYLOAD=$(jq -n \
  --arg user "$USER_UII_ORIGIN" \
  --arg a_user "$USER_UII_ORIGIN" \
  --arg a_asset "$TOKENA_UII_ORIGIN" \
  --arg a_amount "$ONE" \
  --arg r_receiver "$RECIPIENT_UII_DEST" \
  --arg r_asset "$TOKENA_UII_DEST" \
  --arg r_amount "$ONE" \
  '{
    user: $user,
    availableInputs: [ { user: $a_user, asset: $a_asset, amount: $a_amount } ],
    requestedOutputs: [ { receiver: $r_receiver, asset: $r_asset, amount: $r_amount } ],
    preference: "speed",
    minValidUntil: 600
  }')

echo -e "${YELLOW}📤 Sending quote request...${NC}"
QUOTE_RESP=$(curl -s -X POST "$QUOTE_ENDPOINT" -H "Content-Type: application/json" -d "$QUOTE_PAYLOAD")

if ! echo "$QUOTE_RESP" | jq -e '.quotes[0]' >/dev/null 2>&1; then
  echo -e "${RED}Quote request failed${NC}"
  echo "$QUOTE_RESP" | jq .
  exit 1
fi

echo -e "${GREEN}✅ Quote received${NC}"
echo "$QUOTE_RESP" | jq '.quotes[0] | {quoteId, validUntil, orders: ( .orders | length )}'

TMP_QUOTE_JSON="/tmp/quote_$$.json"
echo "$QUOTE_RESP" > "$TMP_QUOTE_JSON"

echo -e "${YELLOW}✍️  Signing and submitting intent via build_transaction.sh...${NC}"
scripts/demo/build_transaction.sh "$TMP_QUOTE_JSON" "$ORDERS_ENDPOINT"

echo -e "${GREEN}🎉 Intent Submitted${NC}"

