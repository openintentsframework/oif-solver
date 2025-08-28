#!/bin/bash
# Send an off-chain cross-chain intent using Resource Lock (The Compact)
# This script mirrors send_offchain_intent.sh but builds Compact signatures
# and sets a special 0x02 prefix to indicate Compact flow to the solver.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}📤 Sending EIP-7683 Intent via Resource Lock (The Compact)${NC}"
echo "========================================="

if [ ! -f "config/demo.toml" ] || [ ! -f "config/demo/networks.toml" ]; then
  echo -e "${RED}❌ Configuration not found!${NC}"
  echo -e "${YELLOW}💡 Run './scripts/demo/setup_local_anvil.sh' first${NC}"
  exit 1
fi

MAIN_CONFIG="config/demo.toml"
NETWORKS_CONFIG="config/demo/networks.toml"

# Load addresses
INPUT_SETTLER_COMPACT=$(grep -A 5 '\[networks.31337\]' $NETWORKS_CONFIG | grep 'input_settler_compact_address = ' | cut -d'"' -f2)
THE_COMPACT=$(grep -A 5 '\[networks.31337\]' $NETWORKS_CONFIG | grep 'the_compact_address = ' | cut -d'"' -f2)
OUTPUT_SETTLER_ADDRESS=$(grep -A 5 '\[networks.31338\]' $NETWORKS_CONFIG | grep 'output_settler_address = ' | cut -d'"' -f2)

# Load precomputed Compact params from setup (now in root)
if [ -f "compact.env" ]; then
  # shellcheck disable=SC1091
  source compact.env
  echo -e "${GREEN}✅ Loaded compact.env with TOKEN_ID_HEX=$TOKEN_ID_HEX${NC}"
fi

# Extract oracle address from the new config format
ORACLE_ADDRESS=$(grep -A 3 '\[settlement.implementations.direct.oracles\]' $MAIN_CONFIG | grep 'input = ' | sed 's/.*31337 = \["\([^"]*\)".*/\1/')

if [ -z "$ORACLE_ADDRESS" ]; then
  echo -e "${RED}❌ Failed to extract ORACLE_ADDRESS from config${NC}"
  echo -e "${YELLOW}💡 Check that the oracle configuration exists in $MAIN_CONFIG${NC}"
  exit 1
fi

echo -e "${GREEN}✅ Using Oracle Address: $ORACLE_ADDRESS${NC}"

DEFAULT_ORIGIN_TOKEN=$(awk '/\[\[networks.31337.tokens\]\]/{f=1} f && /address =/{gsub(/"/, "", $3); print $3; exit}' $NETWORKS_CONFIG)
DEFAULT_DEST_TOKEN=$(awk '/\[\[networks.31338.tokens\]\]/{f=1} f && /address =/{gsub(/"/, "", $3); print $3; exit}' $NETWORKS_CONFIG)

SOLVER_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'solver = ' | cut -d'"' -f2)
USER_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'user = ' | cut -d'"' -f2)
USER_PRIVATE_KEY=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'user_private_key = ' | cut -d'"' -f2)
RECIPIENT_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'recipient = ' | cut -d'"' -f2)

# Extract RPC URLs (supports both rpc_url and [[rpc_urls]] formats)
ORIGIN_RPC_URL=$(sed -n "/\\[\\[networks.$ORIGIN_CHAIN_ID.rpc_urls\\]\\]/,/^\\[/p" $NETWORKS_CONFIG | grep -E '^[[:space:]]*http[[:space:]]*=' | head -1 | cut -d'"' -f2)
DEST_RPC_URL=$(sed -n "/\\[\\[networks.$DEST_CHAIN_ID.rpc_urls\\]\\]/,/^\\[/p" $NETWORKS_CONFIG | grep -E '^[[:space:]]*http[[:space:]]*=' | head -1 | cut -d'"' -f2)
if [ -z "$ORIGIN_RPC_URL" ]; then
  ORIGIN_RPC_URL=$(grep -A 2 "\\[networks.$ORIGIN_CHAIN_ID\\]" $NETWORKS_CONFIG | grep 'rpc_url[[:space:]]*=' | cut -d'"' -f2)
fi
if [ -z "$DEST_RPC_URL" ]; then
  DEST_RPC_URL=$(grep -A 2 "\\[networks.$DEST_CHAIN_ID\\]" $NETWORKS_CONFIG | grep 'rpc_url[[:space:]]*=' | cut -d'"' -f2)
fi
# Fallback defaults
if [ -z "$ORIGIN_RPC_URL" ]; then ORIGIN_RPC_URL="http://localhost:8545"; fi
if [ -z "$DEST_RPC_URL" ]; then DEST_RPC_URL="http://localhost:8546"; fi

ORIGIN_CHAIN_ID=31337
DEST_CHAIN_ID=31338

ORIGIN_TOKEN_ADDRESS=${1:-$DEFAULT_ORIGIN_TOKEN}
DEST_TOKEN_ADDRESS=${2:-$DEFAULT_DEST_TOKEN}

API_URL=${3:-"http://localhost:3000/api/orders"}

AMOUNT="1000000000000000000" # 1e18

# Build StandardOrder bytes (same as escrow script but used for Compact witness)
CURRENT_TIME=$(date +%s)
NONCE=$(perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000')
FILL_DEADLINE=$((CURRENT_TIME + 7200))  # 2 hours
EXPIRY=$((CURRENT_TIME + 7200))  # 2 hours

# Convert origin token address to uint256 for inputs (uint256[2][]) field  
ORIGIN_TOKEN_U256=$(cast to-dec "$ORIGIN_TOKEN_ADDRESS")

# Build bytes32 representations using left-padding (matches normalize_bytes32_address)
ZERO_BYTES32="0x0000000000000000000000000000000000000000000000000000000000000000"
OUTPUT_SETTLER_BYTES32="0x000000000000000000000000$(echo $OUTPUT_SETTLER_ADDRESS | cut -c3-)"
DEST_TOKEN_BYTES32="0x000000000000000000000000$(echo $DEST_TOKEN_ADDRESS | cut -c3-)" 
RECIPIENT_BYTES32="0x000000000000000000000000$(echo $RECIPIENT_ADDR | cut -c3-)"

STANDARD_ORDER_ABI_TYPE='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'

# Get TOKEN_ID using TheCompact (like test file approach)
if [ -z "$TOKEN_ID_HEX" ]; then
  echo -e "${BLUE}💰 Computing TOKEN_ID via TheCompact (like test file)...${NC}"
  
  # Check user balance first
  USER_TOKEN_BALANCE=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $USER_ADDR --rpc-url $ORIGIN_RPC_URL)
  USER_BALANCE_DEC=$(cast to-dec $USER_TOKEN_BALANCE 2>/dev/null || echo "0")
  
  if [ $(echo "$USER_BALANCE_DEC < $AMOUNT" | bc) -eq 1 ]; then
    echo -e "${RED}❌ Insufficient token balance for user${NC}"
    echo -e "${YELLOW}💡 Run setup script first${NC}"
    exit 1
  fi
  
  # Approve TheCompact to spend user tokens (like test file)
  cast send $ORIGIN_TOKEN_ADDRESS "approve(address,uint256)" $THE_COMPACT $AMOUNT \
    --rpc-url $ORIGIN_RPC_URL \
    --private-key $USER_PRIVATE_KEY > /dev/null
  
  # Use depositERC20 to get the TOKEN_ID (like test file: depositERC20 returns tokenId)
  echo -e "${BLUE}   Depositing via TheCompact to get TOKEN_ID...${NC}"
  DEPOSIT_TX=$(cast send $THE_COMPACT "depositERC20(address,bytes12,uint256,address)" \
    $ORIGIN_TOKEN_ADDRESS $ALWAYS_OK_ALLOCATOR_LOCK_TAG $AMOUNT $USER_ADDR \
    --rpc-url $ORIGIN_RPC_URL \
    --private-key $USER_PRIVATE_KEY 2>&1)
  
  # Extract tokenId from deposit transaction receipt (TheCompact emits Transfer event with tokenId)
  if [ $? -eq 0 ]; then
    # Get TX hash and receipt
    TX_HASH=$(echo "$DEPOSIT_TX" | grep -Eo '0x[0-9a-fA-F]{64}' | head -n1)
    if [ -n "$TX_HASH" ]; then
      # Get the tokenId from Transfer event logs (id field in ERC1155 Transfer event)
      RECEIPT=$(cast receipt $TX_HASH --rpc-url $ORIGIN_RPC_URL --json)
      TOKEN_ID_HEX=$(echo "$RECEIPT" | jq -r '.logs[] | select(.topics[0] == "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62") | .topics[3]' | head -n1)
      echo -e "${GREEN}✅ TOKEN_ID from deposit: $TOKEN_ID_HEX${NC}"
    fi
  fi
  
  # Fallback: compute manually if extraction failed
  if [ -z "$TOKEN_ID_HEX" ] || [ "$TOKEN_ID_HEX" = "null" ]; then
    echo -e "${YELLOW}   Fallback: computing TOKEN_ID manually${NC}"
    TOKEN_ID_HEX=0x$(echo $ALWAYS_OK_ALLOCATOR_LOCK_TAG | cut -c3-)$(echo $ORIGIN_TOKEN_ADDRESS | cut -c3-)
    echo -e "${GREEN}✅ Computed TOKEN_ID: $TOKEN_ID_HEX${NC}"
  fi
else
  echo -e "${GREEN}✅ Using TOKEN_ID from config: $TOKEN_ID_HEX${NC}"
fi

TOKEN_ID_U256=$(cast to-dec $TOKEN_ID_HEX)

# Compute commitments hash (simplified approach)
LOCK_TYPE_HASH=$(cast keccak "Lock(bytes12 lockTag,address token,uint256 amount)")
LOCK_HASH=$(cast keccak $(cast abi-encode "f(bytes32,bytes12,address,uint256)" "$LOCK_TYPE_HASH" "$ALWAYS_OK_ALLOCATOR_LOCK_TAG" "$ORIGIN_TOKEN_ADDRESS" "$AMOUNT"))
COMMITMENTS_HASH=$(cast keccak "$LOCK_HASH")

ORDER_DATA=$(cast abi-encode "$STANDARD_ORDER_ABI_TYPE" \
  "(${USER_ADDR},${NONCE},${ORIGIN_CHAIN_ID},${EXPIRY},${FILL_DEADLINE},${ORACLE_ADDRESS},[[${TOKEN_ID_U256},${AMOUNT}]],[(${ZERO_BYTES32},${OUTPUT_SETTLER_BYTES32},${DEST_CHAIN_ID},${DEST_TOKEN_BYTES32},${AMOUNT},${RECIPIENT_BYTES32},0x,0x)])")

echo -e "${BLUE}📋 Order Details (Compact):${NC}"
echo -e "   Origin Token: $ORIGIN_TOKEN_ADDRESS"
echo -e "   Dest Token:   $DEST_TOKEN_ADDRESS"
echo -e "   TheCompact:   $THE_COMPACT"
echo -e "   InputSettlerCompact: $INPUT_SETTLER_COMPACT"

# Build Compact signatures payload
# We need: sponsorSignature over BatchCompact type and optional allocatorData (empty for demo)

# Compute witness hash manually using the exact same logic as StandardOrderType.witnessHash
MANDATE_TYPE_HASH=$(cast keccak "Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)")
MANDATE_OUTPUT_TYPE_HASH=$(cast keccak "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)")

# Compute individual output hash (matches MandateOutputType.hashOutput)
OUTPUT_HASH=$(cast keccak $(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32,bytes32)" \
  "$MANDATE_OUTPUT_TYPE_HASH" "$ZERO_BYTES32" "$OUTPUT_SETTLER_BYTES32" "$DEST_CHAIN_ID" "$DEST_TOKEN_BYTES32" "$AMOUNT" "$RECIPIENT_BYTES32" \
  "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"))

# Compute outputs hash (matches MandateOutputType.hashOutputs - just hash the single output hash)
OUTPUTS_HASH=$(cast keccak "$OUTPUT_HASH")

# Compute witness hash (matches StandardOrderType.witnessHash)
WITNESS_HASH=$(cast keccak $(cast abi-encode "f(bytes32,uint32,address,bytes32)" "$MANDATE_TYPE_HASH" "$FILL_DEADLINE" "$ORACLE_ADDRESS" "$OUTPUTS_HASH"))

# Witness hash computed using contract function

# Build BatchCompact EIP-712 digest using TheCompact DOMAIN_SEPARATOR
DOMAIN_SEPARATOR=$(cast call $THE_COMPACT "DOMAIN_SEPARATOR()" --rpc-url $ORIGIN_RPC_URL)

BATCH_COMPACT_TYPE_HASH=$(cast keccak "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)")

INNER_STRUCT_HASH=$(cast keccak $(cast abi-encode "f(bytes32,address,address,uint256,uint256,bytes32,bytes32)" \
  "$BATCH_COMPACT_TYPE_HASH" "$INPUT_SETTLER_COMPACT" "$USER_ADDR" "$NONCE" "$EXPIRY" "$COMMITMENTS_HASH" "$WITNESS_HASH"))

FINAL_DIGEST=$(cast keccak "0x1901${DOMAIN_SEPARATOR:2}${INNER_STRUCT_HASH:2}")

echo -e "${BLUE}🔏 Signing Compact sponsor signature...${NC}"
SPONSOR_SIG=$(cast wallet sign --no-hash --private-key "$USER_PRIVATE_KEY" "$FINAL_DIGEST")
echo -e "${GREEN}✅ Sponsor signature: $SPONSOR_SIG${NC}"

# For demo, no allocat0xd93f642f64180aor data (empty bytes)
ALLOCATOR_DATA="0x"

# Lock type is now determined by originSubmission.schemes in the JSON payload
# For Resource Lock (The Compact), we use "erc-4337" scheme

# Prefix signatures: for Compact we send abi.encode(sponsorSig, allocatorData) as-is (no type prefix)
SIG_BYTES=$(cast abi-encode "f(bytes,bytes)" "$SPONSOR_SIG" "$ALLOCATOR_DATA")
COMPACT_SIGNATURE="$SIG_BYTES"

# Generate unique quote ID
NONCE_FOR_QUOTE=$(perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000')

JSON_PAYLOAD=$(cat <<EOF
{
  "order": "$ORDER_DATA",
  "signature": "$COMPACT_SIGNATURE",
  "quoteId": "resource_lock_quote_${NONCE_FOR_QUOTE}",
  "provider": "oif-solver-resource-lock",
  "failureHandling": "retry",
  "originSubmission": {
    "mode": "user",
    "schemes": [
      "erc4337"
    ]
  }
}
EOF
)

echo -e "${YELLOW}🚀 Sending order to discovery API...${NC}"
echo -e "   Endpoint: $API_URL"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL" -H "Content-Type: application/json" -d "$JSON_PAYLOAD")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
  echo -e "${GREEN}✅ Order submitted successfully!${NC}"
  echo -e "   Response: $RESPONSE_BODY"
  
  # Extract order ID from response
  ORDER_ID=$(echo "$RESPONSE_BODY" | jq -r '.orderId // empty')
  if [ -n "$ORDER_ID" ]; then
    echo -e "${GREEN}📋 Order ID: $ORDER_ID${NC}"
  fi
  
  echo -e ""
  echo -e "${GREEN}🎉 Resource Lock Intent Submitted!${NC}"
  echo -e "${BLUE}📡 The solver should discover this intent via the API${NC}"
  echo -e "   Route: TOKA → TOKA (via The Compact)"
else
  echo -e "${RED}❌ Failed to submit order${NC}"
  echo -e "   HTTP Status: $HTTP_CODE"
  echo -e "   Response: $RESPONSE_BODY"
  exit 1
fi

