#!/bin/bash

# Human-friendly Quote API test runner with balances and scenario coverage

set -e

# Colors and emojis
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CHECK="✅"
CROSS="❌"
WARN="⚠️"
INFO="ℹ️"
SPARKS="✨"
BOX="📦"
BAL="💰"
TESTTUBE="🧪"

API_URL="http://127.0.0.1:3000"
QUOTE_ENDPOINT="$API_URL/api/quotes"

# Requirements
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo -e "${RED}$CROSS '$1' not found${NC}"; exit 1; }; }
need_cmd jq
need_cmd curl
need_cmd bc
need_cmd cast
need_cmd openssl

if [ ! -f "config/demo.toml" ]; then
  echo -e "${RED}$CROSS Configuration not found!${NC}"
  echo -e "${YELLOW}$INFO Run './scripts/demo/setup_local_anvil.sh' first${NC}"
  exit 1
fi

# Parse config values (same approach as send_onchain_intent.sh)
ORIGIN_CHAIN_ID=31337
DEST_CHAIN_ID=31338

ORIGIN_RPC_URL=$(grep -A 2 '\[networks.31337\]' config/demo.toml | grep 'rpc_url = ' | cut -d'"' -f2)
DEST_RPC_URL=$(grep -A 2 '\[networks.31338\]' config/demo.toml | grep 'rpc_url = ' | cut -d'"' -f2)

SOLVER_ADDR=$(grep -A 4 '\[accounts\]' config/demo.toml | grep 'solver = ' | cut -d'"' -f2)
USER_ADDR=$(grep -A 4 '\[accounts\]' config/demo.toml | grep 'user = ' | cut -d'"' -f2)
RECIPIENT_ADDR=$(grep -A 4 '\[accounts\]' config/demo.toml | grep 'recipient = ' | cut -d'"' -f2)

# Token addresses
TOKENA_ORIGIN=$(awk '/\[\[networks.31337.tokens\]\]/{f=1} f && /address =/{gsub(/"/, "", $3); print $3; exit}' config/demo.toml)
TOKENB_ORIGIN=$(awk '/\[\[networks.31337.tokens\]\]/{c++} c==2 && /address =/{gsub(/"/, "", $3); print $3; exit}' config/demo.toml)
TOKENA_DEST=$(awk '/\[\[networks.31338.tokens\]\]/{f=1} f && /address =/{gsub(/"/, "", $3); print $3; exit}' config/demo.toml)
TOKENB_DEST=$(awk '/\[\[networks.31338.tokens\]\]/{c++} c==2 && /address =/{gsub(/"/, "", $3); print $3; exit}' config/demo.toml)

# ERC-7930 UII builder (demo networks chainRef mapping)
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
TOKENB_UII_ORIGIN=$(to_uii $ORIGIN_CHAIN_ID $TOKENB_ORIGIN)
TOKENB_UII_DEST=$(to_uii $DEST_CHAIN_ID $TOKENB_DEST)

# Balance helpers
check_balance() {
  local address=$1; local name=$2; local rpc_url=$3; local token=$4
  local bal_hex=$(cast call "$token" "balanceOf(address)" "$address" --rpc-url "$rpc_url" 2>&1 | grep -E '^0x[0-9a-fA-F]+' | tail -1)
  if [ -z "$bal_hex" ]; then echo -e "   $name: 0 (RPC error)"; return; fi
  local bal_dec=$(cast to-dec "$bal_hex" 2>/dev/null || echo "0")
  local bal_fmt=$(echo "scale=4; $bal_dec / 1000000000000000000" | bc -l 2>/dev/null || echo "0")
  echo -e "   $name: ${bal_fmt}"
}

show_balances() {
  echo -e "${BLUE}$BAL TokenA Balances${NC}"
  echo -e " - Chain ${ORIGIN_CHAIN_ID} (origin):"
  check_balance "$USER_ADDR" "User" "$ORIGIN_RPC_URL" "$TOKENA_ORIGIN"
  check_balance "$SOLVER_ADDR" "Solver" "$ORIGIN_RPC_URL" "$TOKENA_ORIGIN"
  echo -e " - Chain ${DEST_CHAIN_ID} (dest):"
  check_balance "$USER_ADDR" "User" "$DEST_RPC_URL" "$TOKENA_DEST"
  check_balance "$SOLVER_ADDR" "Solver" "$DEST_RPC_URL" "$TOKENA_DEST"

  echo -e "${BLUE}$BAL TokenB Balances${NC}"
  echo -e " - Chain ${ORIGIN_CHAIN_ID} (origin):"
  check_balance "$USER_ADDR" "User" "$ORIGIN_RPC_URL" "$TOKENB_ORIGIN"
  check_balance "$SOLVER_ADDR" "Solver" "$ORIGIN_RPC_URL" "$TOKENB_ORIGIN"
  echo -e " - Chain ${DEST_CHAIN_ID} (dest):"
  check_balance "$USER_ADDR" "User" "$DEST_RPC_URL" "$TOKENB_DEST"
  check_balance "$SOLVER_ADDR" "Solver" "$DEST_RPC_URL" "$TOKENB_DEST"
}

print_success_quote_summary() {
  local resp="$1"
  local count=$(echo "$resp" | jq '.quotes | length')
  local provider=$(echo "$resp" | jq -r '.quotes[0].provider')
  local quote_id=$(echo "$resp" | jq -r '.quotes[0].quoteId')
  local eta=$(echo "$resp" | jq -r '.quotes[0].eta')
  local valid_until=$(echo "$resp" | jq -r '.quotes[0].validUntil')

  echo -e "${GREEN}$CHECK Quote received${NC}"
  echo -e "  Provider: $provider"
  echo -e "  QuoteId:  $quote_id"
  echo -e "  ETA:      ${eta}s"
  echo -e "  ValidUntil: $valid_until"
  echo -e "  Orders:   ${count} (objects in array)"

  # Print requested outputs and available inputs briefly
  echo -e "  RequestedOutputs:"
  echo "$resp" | jq -r '.quotes[0].details.requestedOutputs[] | "    - amount: \(.amount), asset: \(.asset), receiver: \(.receiver)"'
  echo -e "  AvailableInputs:"
  echo "$resp" | jq -r '.quotes[0].details.availableInputs[] | "    - amount: \(.amount), asset: \(.asset), user: \(.user)"'
}

print_error_summary() {
  local resp="$1"
  local err=$(echo "$resp" | jq -r '.error // empty')
  local msg=$(echo "$resp" | jq -r '.message // empty')
  if [ -n "$err" ]; then
    echo -e "${RED}$CROSS Error: $err${NC}"
    [ -n "$msg" ] && echo -e "  $msg"
  else
    echo -e "${RED}$CROSS Unexpected response${NC}"
    echo "$resp" | jq '.'
  fi
}

send_quote() {
  local payload="$1"
  curl -s -X POST "$QUOTE_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "$payload"
}

run_scenario() {
  local title="$1"; shift
  local payload="$1"; shift
  local expect_success="$1"; shift || true

  echo -e "${YELLOW}$TESTTUBE $title${NC}"
  local resp=$(send_quote "$payload")
  local is_success=$(echo "$resp" | jq -e '.quotes' >/dev/null 2>&1 && echo yes || echo no)

  if [ "$is_success" = "yes" ]; then
    print_success_quote_summary "$resp"
    if [ "$expect_success" = "no" ]; then
      echo -e "${WARN} Expected failure but received a quote"
    fi
  else
    print_error_summary "$resp"
    if [ "$expect_success" = "yes" ]; then
      echo -e "${WARN} Expected success but got an error"
    fi
  fi
  echo ""
}

echo -e "${BLUE}$BOX Testing OIF Solver Quote API at ${QUOTE_ENDPOINT}${NC}"
echo "================================================="

# 1) Show balances first
show_balances
echo ""

# Amount helpers
ONE="1000000000000000000"       # 1 token
HALF="500000000000000000"       # 0.5 token
TWO="2000000000000000000"       # 2 tokens
FIVE_HUNDRED="500000000000000000000" # 500 tokens

# 2) Valid quote (TokenA origin -> TokenA dest)
PAYLOAD_VALID=$(cat << EOF
{
  "user": "$USER_UII_ORIGIN",
  "availableInputs": [
    { "user": "$USER_UII_ORIGIN", "asset": "$TOKENA_UII_ORIGIN", "amount": "$ONE" }
  ],
  "requestedOutputs": [
    { "receiver": "$RECIPIENT_UII_DEST", "asset": "$TOKENA_UII_DEST", "amount": "$ONE" }
  ],
  "preference": "price",
  "minValidUntil": 600
}
EOF
)
run_scenario "Valid quote (TokenA 31337 → TokenA 31338)" "$PAYLOAD_VALID" yes

# 3) Valid structure but unsupported chain (dest chainRef not configured: pretend 31339 => 0x7a6b)
UNSUPPORTED_CHAIN_REF="7a6b"
TOKENA_UII_UNSUPPORTED_CHAIN="0x0100000214${UNSUPPORTED_CHAIN_REF}$(echo $TOKENA_DEST | sed 's/^0x//')"
RECIPIENT_UII_UNSUPPORTED_CHAIN="0x0100000214${UNSUPPORTED_CHAIN_REF}$(echo $RECIPIENT_ADDR | sed 's/^0x//')"
PAYLOAD_UNSUPPORTED_CHAIN=$(cat << EOF
{
  "user": "$USER_UII_ORIGIN",
  "availableInputs": [
    { "user": "$USER_UII_ORIGIN", "asset": "$TOKENA_UII_ORIGIN", "amount": "$ONE" }
  ],
  "requestedOutputs": [
    { "receiver": "$RECIPIENT_UII_UNSUPPORTED_CHAIN", "asset": "$TOKENA_UII_UNSUPPORTED_CHAIN", "amount": "$ONE" }
  ],
  "preference": "speed"
}
EOF
)
run_scenario "Unsupported destination chain (structure OK)" "$PAYLOAD_UNSUPPORTED_CHAIN" no

# 4) Supported chains but unsupported token (random token on dest)
RANDOM_TOKEN_DEST="0x$(openssl rand -hex 20)"
TOKEN_UII_RANDOM_DEST=$(to_uii $DEST_CHAIN_ID $RANDOM_TOKEN_DEST)
PAYLOAD_UNSUPPORTED_TOKEN=$(cat << EOF
{
  "user": "$USER_UII_ORIGIN",
  "availableInputs": [
    { "user": "$USER_UII_ORIGIN", "asset": "$TOKENA_UII_ORIGIN", "amount": "$ONE" }
  ],
  "requestedOutputs": [
    { "receiver": "$RECIPIENT_UII_DEST", "asset": "$TOKEN_UII_RANDOM_DEST", "amount": "$ONE" }
  ]
}
EOF
)
run_scenario "Unsupported token on destination (structure OK)" "$PAYLOAD_UNSUPPORTED_TOKEN" no

# 5) Supported assets but insufficient solver dest balance (request 500 tokens)
PAYLOAD_INSUFF_BAL=$(cat << EOF
{
  "user": "$USER_UII_ORIGIN",
  "availableInputs": [
    { "user": "$USER_UII_ORIGIN", "asset": "$TOKENA_UII_ORIGIN", "amount": "$FIVE_HUNDRED" }
  ],
  "requestedOutputs": [
    { "receiver": "$RECIPIENT_UII_DEST", "asset": "$TOKENA_UII_DEST", "amount": "$FIVE_HUNDRED" }
  ]
}
EOF
)
run_scenario "Insufficient solver balance on destination (500 tokens)" "$PAYLOAD_INSUFF_BAL" no

# 6) Invalid request (no inputs)
PAYLOAD_INVALID=$(cat << EOF
{
  "user": "$USER_UII_ORIGIN",
  "availableInputs": [],
  "requestedOutputs": [
    { "receiver": "$RECIPIENT_UII_DEST", "asset": "$TOKENA_UII_DEST", "amount": "$ONE" }
  ]
}
EOF
)
run_scenario "Invalid request (no available inputs)" "$PAYLOAD_INVALID" no

echo -e "${GREEN}$SPARKS Quote API testing complete!${NC}"
echo -e "${INFO} Ensure the solver service is running: 'cargo run --bin solver -- --config config/demo.toml'"