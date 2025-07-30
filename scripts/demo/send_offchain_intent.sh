#!/bin/bash
# send_offchain_intent.sh - Send a test intent via the offchain API
#
# This script creates an off-chain EIP-7683 cross-chain intent by submitting it to the
# solver's HTTP API. This demonstrates the gasless flow where users sign intents off-chain.
#
# FLOW:
# 1. Load configuration:
#    - Read deployed contract addresses from config/demo.toml
#    - Set up API endpoint (http://localhost:8081/intent)
#
# 2. Approve Permit2:
#    - Check if user has approved Permit2 to spend TEST tokens
#    - If not, approve max amount for Permit2 contract
#    - This is a one-time setup per token
#
# 3. Build order data:
#    - Create same MandateERC7683 struct as on-chain flow
#    - Set deadlines (5 min open deadline, 1 hour fill deadline)
#    - Encode cross-chain transfer details
#
# 4. Generate EIP-712 signature:
#    - Create typed data for PermitBatchWitnessTransferFrom
#    - Include GaslessCrossChainOrder as witness data
#    - Sign with user's private key following EIP-712 standard
#    - This authorizes Permit2 to transfer tokens when order is opened
#
# 5. Submit to API:
#    - POST the signed order to the discovery API
#    - API validates the order and signature
#    - API calls InputSettler to compute order ID
#    - Intent is broadcast to solver for fulfillment
#
# KEY DIFFERENCES FROM ON-CHAIN:
#   - No gas needed for intent creation
#   - Uses Permit2 for token transfers
#   - Requires EIP-712 signature
#   - Submitted via HTTP instead of direct contract call
#
# PREREQUISITES:
#   - Run ./setup_local_anvil.sh first
#   - Solver service must be running with offchain discovery enabled
#
# USAGE:
#   ./send_offchain_intent.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📤 Sending EIP-7683 Intent via Offchain API${NC}"
echo "========================================="

# Check if config exists
if [ ! -f "config/demo.toml" ]; then
    echo -e "${RED}❌ Configuration not found!${NC}"
    echo -e "${YELLOW}💡 Run './setup_local_anvil.sh' first${NC}"
    exit 1
fi

# Extract addresses from config
INPUT_SETTLER_ADDRESS=$(grep 'input_settler_address = ' config/demo.toml | cut -d'"' -f2)
OUTPUT_SETTLER_ADDRESS=$(grep 'output_settler_address = ' config/demo.toml | cut -d'"' -f2)
SOLVER_ADDR=$(grep 'solver_address = ' config/demo.toml | cut -d'"' -f2)
ORACLE_ADDRESS=$(grep 'oracle_address = ' config/demo.toml | cut -d'"' -f2)
ORIGIN_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.origin\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
DEST_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.destination\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
USER_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'user = ' | cut -d'"' -f2)
RECIPIENT_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'recipient = ' | cut -d'"' -f2)

# API endpoint
API_URL="http://localhost:8081/intent"

# Amount in wei (1 token = 1e18 wei)
AMOUNT="1000000000000000000"

# Calculate timestamps
CURRENT_TIME=$(date +%s)
OPEN_DEADLINE=$((CURRENT_TIME + 300))  # 5 minutes from now
FILL_DEADLINE=$((CURRENT_TIME + 3600)) # 1 hour from now

# Function to approve tokens for Permit2
approve_permit2() {
    local PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"
    
    echo -e "${BLUE}🔐 Checking Permit2 allowance...${NC}"
    
    # Check current allowance
    CURRENT_ALLOWANCE=$(cast call "$ORIGIN_TOKEN_ADDRESS" \
        "allowance(address,address)" \
        "$USER_ADDR" \
        "$PERMIT2_ADDRESS" \
        --rpc-url http://localhost:8545)
    
    if [ "$CURRENT_ALLOWANCE" = "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
        echo -e "${BLUE}   Insufficient allowance, approving Permit2...${NC}"
        
        # Get user private key
        USER_KEY=$(grep 'user_private_key = ' config/demo.toml | cut -d'"' -f2)
        
        # Approve max amount
        TX_HASH=$(cast send "$ORIGIN_TOKEN_ADDRESS" \
            "approve(address,uint256)" \
            "$PERMIT2_ADDRESS" \
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
            --private-key "$USER_KEY" \
            --rpc-url http://localhost:8545 \
            --json | jq -r '.transactionHash')
        
        echo -e "${GREEN}✅ Permit2 approved (tx: ${TX_HASH:0:10}...)${NC}"
    else
        echo -e "${GREEN}✅ Sufficient allowance already exists${NC}"
    fi
}

# Approve Permit2 if needed
approve_permit2

# Build order data (same structure as send_onchain_intent.sh)
build_order_data() {
    # Calculate expiry (1 hour from now)
    EXPIRY=$((CURRENT_TIME + 3600))
    
    # Convert values to hex format
    AMOUNT_HEX=$(printf "%064x" $AMOUNT)
    EXPIRY_HEX=$(printf "%064x" $EXPIRY)
    
    # Remove 0x prefix and pad addresses to 32 bytes
    ORIGIN_TOKEN_BYTES32="000000000000000000000000${ORIGIN_TOKEN_ADDRESS:2}"
    DEST_TOKEN_BYTES32="000000000000000000000000${DEST_TOKEN_ADDRESS:2}"
    RECIPIENT_BYTES32="000000000000000000000000${RECIPIENT_ADDR:2}"
    ORACLE_BYTES32="000000000000000000000000${ORACLE_ADDRESS:2}"
    
    # Build MandateERC7683 struct
    ORDER_DATA="0x"
    
    # Offset to struct (32 bytes)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000020"
    
    # expiry (uint32 padded to 32 bytes)
    ORDER_DATA="${ORDER_DATA}${EXPIRY_HEX}"
    
    # localOracle
    ORDER_DATA="${ORDER_DATA}${ORACLE_BYTES32}"
    
    # offset to inputs array (0x80 = 128 bytes from struct start)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000080"
    
    # offset to outputs array (0xe0 = 224 bytes from struct start)
    ORDER_DATA="${ORDER_DATA}00000000000000000000000000000000000000000000000000000000000000e0"
    
    # inputs array: 1 input
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000001"
    
    # Input struct: (token, amount)
    ORDER_DATA="${ORDER_DATA}${ORIGIN_TOKEN_BYTES32}"
    ORDER_DATA="${ORDER_DATA}${AMOUNT_HEX}"
    
    # outputs array: 1 output  
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000001"
    
    # offset to first output (0x20 = 32 bytes from outputs array start)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000020"
    
    # MandateOutput struct:
    # oracle (bytes32) - zero for same-chain
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000000"
    
    # settler (bytes32) - use OutputSettler on destination chain
    OUTPUT_SETTLER_BYTES32="000000000000000000000000${OUTPUT_SETTLER_ADDRESS:2}"
    ORDER_DATA="${ORDER_DATA}${OUTPUT_SETTLER_BYTES32}"
    
    # chainId - destination chain (31338)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000007a6a"
    
    # token (bytes32) - destination token
    ORDER_DATA="${ORDER_DATA}${DEST_TOKEN_BYTES32}"
    
    # amount - same amount
    ORDER_DATA="${ORDER_DATA}${AMOUNT_HEX}"
    
    # recipient (bytes32)
    ORDER_DATA="${ORDER_DATA}${RECIPIENT_BYTES32}"
    
    # offset to call data (0x100 = 256 bytes from output struct start)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000100"
    
    # offset to context data (0x120 = 288 bytes from output struct start)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000120"
    
    # call data - empty (length = 0)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000000"
    
    # context data - empty (length = 0)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000000"
}

# Build the order data
build_order_data

# EIP-712 typehash for MandateERC7683
ORDER_DATA_TYPE="0x532668680e4ed97945ec5ed6aee3633e99abe764fd2d2861903dc7c109b00e82"

# Generate a random nonce
NONCE=$((RANDOM + 1000))

# Create JSON payload
JSON_PAYLOAD=$(cat <<EOF
{
  "order": {
    "originSettler": "$INPUT_SETTLER_ADDRESS",
    "user": "$USER_ADDR",
    "nonce": "$NONCE",
    "originChainId": "31337",
    "openDeadline": $OPEN_DEADLINE,
    "fillDeadline": $FILL_DEADLINE,
    "orderDataType": "$ORDER_DATA_TYPE",
    "orderData": "$ORDER_DATA"
  },
  "signature": null,
  "quote_id": null,
  "provider": "OIF-Solver"
}
EOF
)

echo -e "${BLUE}📋 Order Details:${NC}"
echo -e "   Origin Settler: $INPUT_SETTLER_ADDRESS"
echo -e "   User: $USER_ADDR"
echo -e "   Recipient: $RECIPIENT_ADDR"
echo -e "   Amount: 1.0 TEST tokens"
echo -e "   Origin Chain: 31337"
echo -e "   Dest Chain: 31338"
echo -e "   Open Deadline: $(date -r $OPEN_DEADLINE 2>/dev/null || date -d @$OPEN_DEADLINE)"
echo -e "   Fill Deadline: $(date -r $FILL_DEADLINE 2>/dev/null || date -d @$FILL_DEADLINE)"

echo ""
echo -e "${YELLOW}🔏 Generating EIP-712 signature...${NC}"

# Get user private key from config
USER_PRIVATE_KEY=$(grep 'user_private_key = ' config/demo.toml | cut -d'"' -f2)

# Create EIP-712 typed data JSON for cast
create_eip712_json() {
    cat <<EOF
{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}
    ],
    "PermitBatchWitnessTransferFrom": [
      {"name": "permitted", "type": "TokenPermissions[]"},
      {"name": "spender", "type": "address"},
      {"name": "nonce", "type": "uint256"},
      {"name": "deadline", "type": "uint256"},
      {"name": "witness", "type": "GaslessCrossChainOrder"}
    ],
    "TokenPermissions": [
      {"name": "token", "type": "address"},
      {"name": "amount", "type": "uint256"}
    ],
    "GaslessCrossChainOrder": [
      {"name": "originSettler", "type": "address"},
      {"name": "user", "type": "address"},
      {"name": "nonce", "type": "uint256"},
      {"name": "originChainId", "type": "uint256"},
      {"name": "openDeadline", "type": "uint32"},
      {"name": "fillDeadline", "type": "uint32"},
      {"name": "orderDataType", "type": "bytes32"},
      {"name": "orderData", "type": "MandateERC7683"}
    ],
    "MandateERC7683": [
      {"name": "expiry", "type": "uint32"},
      {"name": "localOracle", "type": "address"},
      {"name": "inputs", "type": "uint256[2][]"},
      {"name": "outputs", "type": "MandateOutput[]"}
    ],
    "MandateOutput": [
      {"name": "oracle", "type": "bytes32"},
      {"name": "settler", "type": "bytes32"},
      {"name": "chainId", "type": "uint256"},
      {"name": "token", "type": "bytes32"},
      {"name": "amount", "type": "uint256"},
      {"name": "recipient", "type": "bytes32"},
      {"name": "callData", "type": "bytes"},
      {"name": "contextData", "type": "bytes"}
    ]
  },
  "primaryType": "PermitBatchWitnessTransferFrom",
  "domain": {
    "name": "Permit2",
    "chainId": 31337,
    "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  },
  "message": {
    "permitted": [
      {
        "token": "$ORIGIN_TOKEN_ADDRESS",
        "amount": "$AMOUNT"
      }
    ],
    "spender": "$INPUT_SETTLER_ADDRESS",
    "nonce": "$NONCE",
    "deadline": $OPEN_DEADLINE,
    "witness": {
      "originSettler": "$INPUT_SETTLER_ADDRESS",
      "user": "$USER_ADDR",
      "nonce": "$NONCE",
      "originChainId": "31337",
      "openDeadline": $OPEN_DEADLINE,
      "fillDeadline": $FILL_DEADLINE,
      "orderDataType": "$ORDER_DATA_TYPE",
      "orderData": {
        "expiry": $EXPIRY,
        "localOracle": "$ORACLE_ADDRESS",
        "inputs": [
          ["$((0x$ORIGIN_TOKEN_BYTES32))", "$AMOUNT"]
        ],
        "outputs": [
          {
            "oracle": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "settler": "0x$OUTPUT_SETTLER_BYTES32",
            "chainId": "31338",
            "token": "0x$DEST_TOKEN_BYTES32",
            "amount": "$AMOUNT",
            "recipient": "0x$RECIPIENT_BYTES32",
            "callData": "0x",
            "contextData": "0x"
          }
        ]
      }
    }
  }
}
EOF
}

# Save EIP-712 data to a temporary file
EIP712_FILE="/tmp/eip712_order_$$.json"
create_eip712_json > "$EIP712_FILE"

# Compute proper EIP-712 signature
echo -e "${BLUE}Computing EIP-712 signature...${NC}"

# Clean up the temp file since we won't use it
rm -f "$EIP712_FILE"

# Compute type hashes based on the contract definitions
# From MandateOutputType.sol - MANDATE_OUTPUT_TYPE_STUB
MANDATE_OUTPUT_TYPE="MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
MANDATE_OUTPUT_TYPE_HASH=$(cast keccak "$MANDATE_OUTPUT_TYPE")

# From Order7683Type.sol - CATALYST_WITNESS_TYPE
MANDATE_ERC7683_TYPE="MandateERC7683(uint32 expiry,address localOracle,uint256[2][] inputs,MandateOutput[] outputs)${MANDATE_OUTPUT_TYPE}"
MANDATE_ERC7683_TYPE_HASH=$(cast keccak "$MANDATE_ERC7683_TYPE")

# From Order7683Type.sol - ERC7683_GASLESS_CROSS_CHAIN_ORDER  
GASLESS_ORDER_TYPE="GaslessCrossChainOrder(address originSettler,address user,uint256 nonce,uint256 originChainId,uint32 openDeadline,uint32 fillDeadline,bytes32 orderDataType,MandateERC7683 orderData)${MANDATE_ERC7683_TYPE}"
GASLESS_ORDER_TYPE_HASH=$(cast keccak "$GASLESS_ORDER_TYPE")

TOKEN_PERMISSIONS_TYPE="TokenPermissions(address token,uint256 amount)"
TOKEN_PERMISSIONS_TYPE_HASH=$(cast keccak "$TOKEN_PERMISSIONS_TYPE")

# From Order7683Type.sol - PERMIT2_ERC7683_GASLESS_CROSS_CHAIN_ORDER
# The format for Permit2 is different - it includes "GaslessCrossChainOrder witness)" then the types
PERMIT_BATCH_WITNESS_STRING="PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,GaslessCrossChainOrder witness)${GASLESS_ORDER_TYPE}${TOKEN_PERMISSIONS_TYPE}"
PERMIT_BATCH_WITNESS_TYPE_HASH=$(cast keccak "$PERMIT_BATCH_WITNESS_STRING")

# Domain separator for Permit2
DOMAIN_TYPE_HASH=$(cast keccak "EIP712Domain(string name,uint256 chainId,address verifyingContract)")
PERMIT2_NAME_HASH=$(cast keccak "Permit2")
DOMAIN_SEPARATOR=$(cast abi-encode "f(bytes32,bytes32,uint256,address)" "$DOMAIN_TYPE_HASH" "$PERMIT2_NAME_HASH" "31337" "0x000000000022D473030F116dDEE9F6B43aC78BA3")
DOMAIN_SEPARATOR_HASH=$(cast keccak "$DOMAIN_SEPARATOR")


# Helper function to compute hash of MandateOutput
compute_mandate_output_hash() {
    local oracle="0x0000000000000000000000000000000000000000000000000000000000000000"
    local settler="0x000000000000000000000000${OUTPUT_SETTLER_ADDRESS:2}"
    local chainId="31338"
    local token="0x000000000000000000000000${DEST_TOKEN_ADDRESS:2}"
    local amount="$AMOUNT"
    local recipient="0x000000000000000000000000${RECIPIENT_ADDR:2}"
    # For empty bytes, keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    local callDataHash="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    local contextDataHash="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    
    
    # Encode MandateOutput struct
    local encoded=$(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32,bytes32)" \
        "$MANDATE_OUTPUT_TYPE_HASH" \
        "$oracle" \
        "$settler" \
        "$chainId" \
        "$token" \
        "$amount" \
        "$recipient" \
        "$callDataHash" \
        "$contextDataHash")
    
    cast keccak "$encoded"
}

# Compute outputs array hash
# For MandateOutputType.hashOutputsM with single output: keccak256(outputHash)
MANDATE_OUTPUT_HASH=$(compute_mandate_output_hash)
OUTPUTS_HASH=$(cast keccak "$MANDATE_OUTPUT_HASH")

# Compute inputs array hash using abi.encodePacked
# For a single input [token, amount], we pack them together
INPUT_TOKEN_PADDED="000000000000000000000000${ORIGIN_TOKEN_ADDRESS:2}"
# Pack the array element (token as uint256, amount as uint256)
AMOUNT_HEX=$(printf '%064x' $AMOUNT)
INPUTS_PACKED="${INPUT_TOKEN_PADDED}${AMOUNT_HEX}"
INPUTS_HASH=$(cast keccak "0x$INPUTS_PACKED")

# Compute MandateERC7683 hash
ORDER_DATA_ENCODED=$(cast abi-encode "f(bytes32,uint32,address,bytes32,bytes32)" \
    "$MANDATE_ERC7683_TYPE_HASH" \
    "$EXPIRY" \
    "$ORACLE_ADDRESS" \
    "$INPUTS_HASH" \
    "$OUTPUTS_HASH")
ORDER_DATA_HASH=$(cast keccak "$ORDER_DATA_ENCODED")

# Compute GaslessCrossChainOrder hash (witness hash)
GASLESS_ORDER_ENCODED=$(cast abi-encode "f(bytes32,address,address,uint256,uint256,uint32,uint32,bytes32,bytes32)" \
    "$GASLESS_ORDER_TYPE_HASH" \
    "$INPUT_SETTLER_ADDRESS" \
    "$USER_ADDR" \
    "$NONCE" \
    "31337" \
    "$OPEN_DEADLINE" \
    "$FILL_DEADLINE" \
    "$ORDER_DATA_TYPE" \
    "$ORDER_DATA_HASH")
GASLESS_ORDER_HASH=$(cast keccak "$GASLESS_ORDER_ENCODED")

# Compute TokenPermissions hash
TOKEN_PERM_ENCODED=$(cast abi-encode "f(bytes32,address,uint256)" \
    "$TOKEN_PERMISSIONS_TYPE_HASH" \
    "$ORIGIN_TOKEN_ADDRESS" \
    "$AMOUNT")
TOKEN_PERM_HASH=$(cast keccak "$TOKEN_PERM_ENCODED")

# The witness hash is the GaslessCrossChainOrder hash
WITNESS_HASH="$GASLESS_ORDER_HASH"

# Compute PermitBatchWitnessTransferFrom struct with array hashes
PERMITTED_ARRAY_HASH=$(cast keccak "$TOKEN_PERM_HASH")

# The main struct for signing includes the array hash
MAIN_STRUCT_ENCODED=$(cast abi-encode "f(bytes32,bytes32,address,uint256,uint256,bytes32)" \
    "$PERMIT_BATCH_WITNESS_TYPE_HASH" \
    "$PERMITTED_ARRAY_HASH" \
    "$INPUT_SETTLER_ADDRESS" \
    "$NONCE" \
    "$OPEN_DEADLINE" \
    "$WITNESS_HASH")
MAIN_STRUCT_HASH=$(cast keccak "$MAIN_STRUCT_ENCODED")

# Create final digest
DIGEST_PREFIX="0x1901"
DIGEST="${DIGEST_PREFIX}${DOMAIN_SEPARATOR_HASH:2}${MAIN_STRUCT_HASH:2}"
FINAL_DIGEST=$(cast keccak "$DIGEST")

# Sign the digest using --no-hash flag for EIP-712 signatures
SIGNATURE=$(cast wallet sign --no-hash --private-key "$USER_PRIVATE_KEY" "$FINAL_DIGEST")
SIGN_EXIT_CODE=$?

# Check if signing succeeded
if [ $SIGN_EXIT_CODE -ne 0 ] || [ -z "$SIGNATURE" ] || [ "$SIGNATURE" = "" ]; then
    echo -e "${RED}❌ Signing failed!${NC}"
    exit 1
else
    echo -e "${GREEN}✅ EIP-712 signature generated: $SIGNATURE${NC}"
fi

# Update JSON payload with signature
JSON_PAYLOAD=$(echo "$JSON_PAYLOAD" | jq --arg sig "$SIGNATURE" '.signature = $sig')

echo -e "${GREEN}✅ Signature added to order${NC}"

echo ""
echo -e "${BLUE}📄 Final JSON Payload:${NC}"
echo "$JSON_PAYLOAD" | jq .

echo ""
echo -e "${YELLOW}🚀 Sending order to offchain API...${NC}"
echo -e "   Endpoint: $API_URL"

# Send the request
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "$JSON_PAYLOAD")

# Extract HTTP status code and response body
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✅ Order submitted successfully!${NC}"
    echo -e "   Response: $RESPONSE_BODY"
    
    # Extract order ID if available
    ORDER_ID=$(echo "$RESPONSE_BODY" | grep -o '"order_id":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$ORDER_ID" ]; then
        echo -e "${BLUE}   Order ID: $ORDER_ID${NC}"
    fi
else
    echo -e "${RED}❌ Failed to submit order${NC}"
    echo -e "   HTTP Status: $HTTP_CODE"
    echo -e "   Response: $RESPONSE_BODY"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 Offchain Intent Submitted!${NC}"
echo -e "${YELLOW}📡 The solver should discover this intent via the API${NC}"