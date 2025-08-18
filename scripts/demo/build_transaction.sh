#!/usr/bin/env bash

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🧱 Building StandardOrder + signing digest + POSTing to solver${NC}"

if ! command -v jq >/dev/null 2>&1; then
  echo -e "${RED}jq is required${NC}"; exit 1
fi
if ! command -v cast >/dev/null 2>&1; then
  echo -e "${RED}foundry (cast) is required${NC}"; exit 1
fi

# Input handling
# Usage:
#   ./build_transaction.sh <quote.json> [api_url]
#   cat quote.json | ./build_transaction.sh [api_url]

API_URL="${2:-${1:-}}"
QUOTE_SRC=""
if [ -t 0 ]; then
  # No stdin; expect file in $1
  if [ -n "${1:-}" ] && [ -f "$1" ]; then
    QUOTE_SRC="$1"
    # Shift api url if provided as $2
    if [ -n "${2:-}" ]; then API_URL="$2"; fi
  else
    echo -e "${RED}Provide a quote JSON file or pipe JSON via stdin${NC}"; exit 1
  fi
else
  # Read from stdin
  QUOTE_SRC="/tmp/quote_$$.json"
  cat > "$QUOTE_SRC"
fi

# Defaults
API_URL="${API_URL:-http://localhost:3000/api/orders}"

echo -e "${YELLOW}Reading quote from:${NC} ${QUOTE_SRC}"
echo -e "${YELLOW}POST endpoint:${NC} ${API_URL}"

# Load accounts from config
if [ ! -f "config/demo.toml" ]; then
  echo -e "${RED}Missing config/demo.toml${NC}"; exit 1
fi
USER_ADDR=$(grep -A 4 '\[accounts\]' config/demo.toml | grep 'user = ' | head -1 | cut -d'"' -f2)
USER_PRIVATE_KEY=$(grep -A 4 '\[accounts\]' config/demo.toml | grep 'user_private_key = ' | head -1 | cut -d'"' -f2)

if [ -z "$USER_ADDR" ] || [ -z "$USER_PRIVATE_KEY" ]; then
  echo -e "${RED}Failed to read user account from config/demo.toml${NC}"; exit 1
fi

echo -e "${BLUE}👤 User:${NC} $USER_ADDR"

# Extract fields from quote JSON
DIGEST=$(jq -r '.quotes[0].orders[0].message.digest' "$QUOTE_SRC")
NONCE=$(jq -r '.quotes[0].orders[0].message.eip712.nonce' "$QUOTE_SRC")
DEADLINE=$(jq -r '.quotes[0].orders[0].message.eip712.deadline' "$QUOTE_SRC")
EXPIRY=$(jq -r '.quotes[0].orders[0].message.eip712.witness.expires' "$QUOTE_SRC")
ORACLE_ADDRESS=$(jq -r '.quotes[0].orders[0].message.eip712.witness.inputOracle' "$QUOTE_SRC")
ORIGIN_CHAIN_ID=$(jq -r '.quotes[0].orders[0].message.eip712.signing.domain.chainId' "$QUOTE_SRC")
ORIGIN_TOKEN=$(jq -r '.quotes[0].orders[0].message.eip712.permitted[0].token' "$QUOTE_SRC")
AMOUNT=$(jq -r '.quotes[0].orders[0].message.eip712.permitted[0].amount' "$QUOTE_SRC")
DEST_CHAIN_ID=$(jq -r '.quotes[0].orders[0].message.eip712.witness.outputs[0].chainId' "$QUOTE_SRC")
OUTPUT_SETTLER_BYTES32=$(jq -r '.quotes[0].orders[0].message.eip712.witness.outputs[0].settler' "$QUOTE_SRC")
DEST_TOKEN_BYTES32=$(jq -r '.quotes[0].orders[0].message.eip712.witness.outputs[0].token' "$QUOTE_SRC")
RECIPIENT_BYTES32=$(jq -r '.quotes[0].orders[0].message.eip712.witness.outputs[0].recipient' "$QUOTE_SRC")

if [ -z "$DIGEST" ] || [ "$DIGEST" = "null" ]; then
  echo -e "${RED}Missing digest in quote JSON${NC}"; exit 1
fi

echo -e "${BLUE}🔎 Parsed from quote:${NC}"
echo "  Nonce:      $NONCE"
echo "  Deadline:   $DEADLINE"
echo "  Expiry:     $EXPIRY"
echo "  Oracle:     $ORACLE_ADDRESS"
echo "  Origin CID: $ORIGIN_CHAIN_ID"
echo "  OriginTok:  $ORIGIN_TOKEN"
echo "  Amount:     $AMOUNT"
echo "  Dest CID:   $DEST_CHAIN_ID"
echo "  Settler32:  $OUTPUT_SETTLER_BYTES32"
echo "  DestTok32:  $DEST_TOKEN_BYTES32"
echo "  Rcpt32:     $RECIPIENT_BYTES32"

# Sign digest with no-hash (EIP-712 digest already computed by server)
echo -e "${YELLOW}✍️  Signing digest...${NC}"
SIGNATURE=$(cast wallet sign --no-hash --private-key "$USER_PRIVATE_KEY" "$DIGEST")
if [ -z "$SIGNATURE" ]; then
  echo -e "${RED}Failed to sign digest${NC}"; exit 1
fi
PREFIXED_SIGNATURE="0x00${SIGNATURE:2}"
echo -e "${GREEN}✅ Signature:${NC} $PREFIXED_SIGNATURE"

# Build StandardOrder
STANDARD_ORDER_ABI_TYPE='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'

ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
FILL_DEADLINE=$DEADLINE

echo -e "${YELLOW}🧩 Encoding StandardOrder...${NC}"
ORDER_DATA=$(cast abi-encode "$STANDARD_ORDER_ABI_TYPE" \
"(${USER_ADDR},${NONCE},${ORIGIN_CHAIN_ID},${EXPIRY},${FILL_DEADLINE},${ORACLE_ADDRESS},[[$ORIGIN_TOKEN,$AMOUNT]],[($ZERO_BYTES32,$OUTPUT_SETTLER_BYTES32,${DEST_CHAIN_ID},$DEST_TOKEN_BYTES32,$AMOUNT,$RECIPIENT_BYTES32,0x,0x)])")

if [ -z "$ORDER_DATA" ]; then
  echo -e "${RED}Failed to encode StandardOrder${NC}"; exit 1
fi

echo -e "${GREEN}✅ Order encoded${NC}"
echo -e "${BLUE}📦 Payload preview:${NC}"
PAYLOAD=$(jq -n --arg order "$ORDER_DATA" --arg sponsor "$USER_ADDR" --arg sig "$PREFIXED_SIGNATURE" '{order:$order, sponsor:$sponsor, signature:$sig}')
echo "$PAYLOAD" | jq .

echo -e "${YELLOW}🚀 Posting to solver...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL" -H "Content-Type: application/json" -d "$PAYLOAD")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
  echo -e "${GREEN}✅ Submitted successfully${NC}"
  echo "$BODY" | jq .
  ORDER_ID=$(echo "$BODY" | jq -r '.order_id // empty')
  if [ -n "$ORDER_ID" ]; then
    echo -e "${BLUE}Order ID:${NC} $ORDER_ID"
  fi
else
  echo -e "${RED}❌ Submission failed${NC} (HTTP $HTTP_CODE)"
  echo "$BODY"
  exit 1
fi

echo -e "${GREEN}🎉 Transaction built${NC}"