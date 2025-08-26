#!/bin/bash
# Send an off-chain cross-chain intent via the solver's HTTP API
# This demonstrates the gasless flow using Permit2 and EIP-712 signatures
#
# NOTE: This script has been tested on macOS systems only.
#
# Prerequisites: Run ./setup_local_anvil.sh and start the solver service
# Usage: 
#   ./send_offchain_intent.sh [origin_token] [dest_token] [--direct|api_url]
#   ./send_offchain_intent.sh                              # Use default TokenA
#   ./send_offchain_intent.sh 0xABC... 0xDEF...          # Specific tokens
#   ./send_offchain_intent.sh --direct                     # Use discovery service
#   ./send_offchain_intent.sh 0xABC... 0xDEF... --direct  # Specific tokens + discovery
#   ./send_offchain_intent.sh balances                     # Check balances only

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📤 Sending EIP-7683 Intent via Offchain API${NC}"
echo "========================================="

# Check if modular config exists
if [ ! -f "config/demo.toml" ] || [ ! -f "config/demo/networks.toml" ]; then
    echo -e "${RED}❌ Configuration not found!${NC}"
    echo -e "${YELLOW}💡 Run './setup_local_anvil.sh' first${NC}"
    exit 1
fi

# Use modular configuration paths
MAIN_CONFIG="config/demo.toml"
NETWORKS_CONFIG="config/demo/networks.toml"

# Load addresses from networks config
# For origin chain (31337)
INPUT_SETTLER_ADDRESS=$(grep -A 5 '\[networks.31337\]' $NETWORKS_CONFIG | grep 'input_settler_address = ' | cut -d'"' -f2)
OUTPUT_SETTLER_ADDRESS_ORIGIN=$(grep -A 5 '\[networks.31337\]' $NETWORKS_CONFIG | grep 'output_settler_address = ' | cut -d'"' -f2)
# For destination chain (31338)
INPUT_SETTLER_ADDRESS_DEST=$(grep -A 5 '\[networks.31338\]' $NETWORKS_CONFIG | grep 'input_settler_address = ' | cut -d'"' -f2)
OUTPUT_SETTLER_ADDRESS=$(grep -A 5 '\[networks.31338\]' $NETWORKS_CONFIG | grep 'output_settler_address = ' | cut -d'"' -f2)

# Get oracle address from settlement section in main config
# Extract oracle address for origin chain (31337) from the new format: input = { 31337 = ["0x..."] }
ORACLE_ADDRESS=$(grep -A5 '\[settlement.implementations.direct.oracles\]' $MAIN_CONFIG | grep 'input = ' | sed 's/.*31337 = \["\([^"]*\)".*/\1/')

# Parse token addresses from networks config
# For origin chain tokens (31337)
DEFAULT_ORIGIN_TOKEN=$(awk '/\[\[networks.31337.tokens\]\]/{f=1} f && /address =/{gsub(/"/, "", $3); print $3; exit}' $NETWORKS_CONFIG)
TOKENB_ORIGIN=$(awk '/\[\[networks.31337.tokens\]\]/{c++} c==2 && /address =/{gsub(/"/, "", $3); print $3; exit}' $NETWORKS_CONFIG)

# For destination chain tokens (31338)
DEFAULT_DEST_TOKEN=$(awk '/\[\[networks.31338.tokens\]\]/{f=1} f && /address =/{gsub(/"/, "", $3); print $3; exit}' $NETWORKS_CONFIG)
TOKENB_DEST=$(awk '/\[\[networks.31338.tokens\]\]/{c++} c==2 && /address =/{gsub(/"/, "", $3); print $3; exit}' $NETWORKS_CONFIG)

# Account addresses from main config
SOLVER_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'solver = ' | cut -d'"' -f2)
USER_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'user = ' | cut -d'"' -f2)
USER_PRIVATE_KEY=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'user_private_key = ' | cut -d'"' -f2)
RECIPIENT_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'recipient = ' | cut -d'"' -f2)

# Load RPC URLs from networks config (extract HTTP URL from first rpc_urls entry)
ORIGIN_RPC_URL=$(awk '/\[\[networks.31337.rpc_urls\]\]/{f=1} f && /^http = /{print; exit}' $NETWORKS_CONFIG | cut -d'"' -f2)
DEST_RPC_URL=$(awk '/\[\[networks.31338.rpc_urls\]\]/{f=1} f && /^http = /{print; exit}' $NETWORKS_CONFIG | cut -d'"' -f2)
ORIGIN_CHAIN_ID=31337
DEST_CHAIN_ID=31338

# Parse command line arguments
ORIGIN_TOKEN_ADDRESS=""
DEST_TOKEN_ADDRESS=""
API_MODE=""

# Check if first argument is balances command
if [ "$1" = "balances" ]; then
    COMMAND="balances"
else
    COMMAND="send"
    # Process arguments for send command
    for arg in "$@"; do
        if [ "$arg" = "--direct" ]; then
            API_MODE="direct"
        elif [ "$arg" = "--help" ]; then
            API_MODE="help"
        elif [[ "$arg" =~ ^http ]]; then
            API_MODE="custom"
            API_URL="$arg"
        elif [[ "$arg" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
            if [ -z "$ORIGIN_TOKEN_ADDRESS" ]; then
                ORIGIN_TOKEN_ADDRESS="$arg"
            elif [ -z "$DEST_TOKEN_ADDRESS" ]; then
                DEST_TOKEN_ADDRESS="$arg"
            fi
        fi
    done
fi

# Set default tokens if not provided
if [ -z "$ORIGIN_TOKEN_ADDRESS" ]; then
    ORIGIN_TOKEN_ADDRESS="$DEFAULT_ORIGIN_TOKEN"
fi
if [ -z "$DEST_TOKEN_ADDRESS" ]; then
    DEST_TOKEN_ADDRESS="$DEFAULT_DEST_TOKEN"
fi

# Determine token symbols
get_token_symbol() {
    local addr="$1"
    if [ "$addr" = "$DEFAULT_ORIGIN_TOKEN" ] || [ "$addr" = "$DEFAULT_DEST_TOKEN" ]; then
        echo "TOKA"
    elif [ "$addr" = "$TOKENB_ORIGIN" ] || [ "$addr" = "$TOKENB_DEST" ]; then
        echo "TOKB"
    else
        echo "CUSTOM"
    fi
}

ORIGIN_SYMBOL=$(get_token_symbol "$ORIGIN_TOKEN_ADDRESS")
DEST_SYMBOL=$(get_token_symbol "$DEST_TOKEN_ADDRESS")

# Function to check balances (same as in onchain script)
check_balance() {
    local address=$1
    local name=$2
    local rpc_url=${3:-$ORIGIN_RPC_URL}
    local token_addr=${4:-$ORIGIN_TOKEN_ADDRESS}
    
    local balance_hex=$(cast call $token_addr "balanceOf(address)" $address --rpc-url $rpc_url 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    
    if [ -z "$balance_hex" ]; then
        echo -e "   $name: 0 tokens (Error: check RPC connection)"
        return
    fi
    
    local balance_dec=$(cast to-dec $balance_hex 2>/dev/null || echo "0")
    # Use explicit decimal division instead of exponentiation
    local balance_formatted=$(echo "scale=2; $balance_dec / 1000000000000000000" | bc -l 2>/dev/null || echo "0")
    echo -e "   $name: ${balance_formatted} tokens"
}

# Function to show current balances
show_balances() {
    if [ "$COMMAND" = "balances" ]; then
        # Show all token balances when checking balances
        echo -e "${BLUE}💰 TokenA Balances on Origin Chain ($ORIGIN_CHAIN_ID):${NC}"
        check_balance $USER_ADDR "User" $ORIGIN_RPC_URL $DEFAULT_ORIGIN_TOKEN
        check_balance $SOLVER_ADDR "Solver" $ORIGIN_RPC_URL $DEFAULT_ORIGIN_TOKEN
        check_balance $RECIPIENT_ADDR "Recipient" $ORIGIN_RPC_URL $DEFAULT_ORIGIN_TOKEN
        check_balance $INPUT_SETTLER_ADDRESS "InputSettler" $ORIGIN_RPC_URL $DEFAULT_ORIGIN_TOKEN
        
        echo -e "${BLUE}💰 TokenB Balances on Origin Chain ($ORIGIN_CHAIN_ID):${NC}"
        check_balance $USER_ADDR "User" $ORIGIN_RPC_URL $TOKENB_ORIGIN
        check_balance $SOLVER_ADDR "Solver" $ORIGIN_RPC_URL $TOKENB_ORIGIN
        check_balance $RECIPIENT_ADDR "Recipient" $ORIGIN_RPC_URL $TOKENB_ORIGIN
        check_balance $INPUT_SETTLER_ADDRESS "InputSettler" $ORIGIN_RPC_URL $TOKENB_ORIGIN
        
        echo -e "${BLUE}💰 TokenA Balances on Destination Chain ($DEST_CHAIN_ID):${NC}"
        check_balance $USER_ADDR "User" $DEST_RPC_URL $DEFAULT_DEST_TOKEN
        check_balance $SOLVER_ADDR "Solver" $DEST_RPC_URL $DEFAULT_DEST_TOKEN
        check_balance $RECIPIENT_ADDR "Recipient" $DEST_RPC_URL $DEFAULT_DEST_TOKEN
        check_balance $OUTPUT_SETTLER_ADDRESS "OutputSettler" $DEST_RPC_URL $DEFAULT_DEST_TOKEN
        
        echo -e "${BLUE}💰 TokenB Balances on Destination Chain ($DEST_CHAIN_ID):${NC}"
        check_balance $USER_ADDR "User" $DEST_RPC_URL $TOKENB_DEST
        check_balance $SOLVER_ADDR "Solver" $DEST_RPC_URL $TOKENB_DEST
        check_balance $RECIPIENT_ADDR "Recipient" $DEST_RPC_URL $TOKENB_DEST
        check_balance $OUTPUT_SETTLER_ADDRESS "OutputSettler" $DEST_RPC_URL $TOKENB_DEST
    else
        # Show only relevant token balances for intent
        echo -e "${BLUE}💰 Current Balances on Origin Chain ($ORIGIN_CHAIN_ID) - $ORIGIN_SYMBOL:${NC}"
        check_balance $USER_ADDR "User" $ORIGIN_RPC_URL $ORIGIN_TOKEN_ADDRESS
        check_balance $SOLVER_ADDR "Solver" $ORIGIN_RPC_URL $ORIGIN_TOKEN_ADDRESS
        check_balance $RECIPIENT_ADDR "Recipient" $ORIGIN_RPC_URL $ORIGIN_TOKEN_ADDRESS
        check_balance $INPUT_SETTLER_ADDRESS "InputSettler" $ORIGIN_RPC_URL $ORIGIN_TOKEN_ADDRESS
        
        echo -e "${BLUE}💰 Current Balances on Destination Chain ($DEST_CHAIN_ID) - $DEST_SYMBOL:${NC}"
        check_balance $USER_ADDR "User" $DEST_RPC_URL $DEST_TOKEN_ADDRESS
        check_balance $SOLVER_ADDR "Solver" $DEST_RPC_URL $DEST_TOKEN_ADDRESS
        check_balance $RECIPIENT_ADDR "Recipient" $DEST_RPC_URL $DEST_TOKEN_ADDRESS
        check_balance $OUTPUT_SETTLER_ADDRESS "OutputSettler" $DEST_RPC_URL $DEST_TOKEN_ADDRESS
    fi
}

# Handle balances command
if [ "$COMMAND" = "balances" ]; then
    # Check required commands
    if ! command -v bc &> /dev/null; then
        echo -e "${RED}❌ 'bc' command not found!${NC}"
        echo -e "${YELLOW}💡 Install bc: brew install bc (macOS) or apt-get install bc (Linux)${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}📊 Checking Token Balances${NC}"
    echo "================================"
    show_balances
    exit 0
fi

# Set API endpoint based on mode (for send command)
if [ "$API_MODE" = "direct" ]; then
    API_PORT=$(grep -A 10 '\[discovery.implementations.offchain_eip7683\]' $MAIN_CONFIG | grep 'api_port = ' | awk '{print $3}')
    API_URL="http://localhost:${API_PORT:-8081}/intent"
    echo -e "${YELLOW}Using direct discovery API at $API_URL${NC}"
elif [ "$API_MODE" = "custom" ]; then
    echo -e "${YELLOW}Using custom API URL: $API_URL${NC}"
elif [ "$API_MODE" != "help" ]; then
    # Default: Use solver's /orders API
    API_URL="http://localhost:3000/api/orders"
fi

# Show help if requested
if [ "$API_MODE" = "help" ]; then
    echo "Usage: $0 [origin_token] [dest_token] [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  origin_token    Origin token address (default: TokenA)"
    echo "  dest_token      Destination token address (default: TokenA)"
    echo ""
    echo "Options:"
    echo "  --direct        Use discovery service directly (port 8081)"
    echo "  <URL>          Use custom API URL"
    echo "  --help         Show this help message"
    echo "  balances       Check all token balances"
    echo ""
    echo "Examples:"
    echo "  $0                                    # TokenA → TokenA via solver API"
    echo "  $0 --direct                          # TokenA → TokenA via discovery"
    echo "  $0 $DEFAULT_ORIGIN_TOKEN $TOKENB_DEST               # TokenA → TokenB"
    echo "  $0 $TOKENB_ORIGIN $DEFAULT_DEST_TOKEN               # TokenB → TokenA"
    echo "  $0 $DEFAULT_ORIGIN_TOKEN $TOKENB_DEST --direct      # TokenA → TokenB via discovery"
    echo "  $0 balances                          # Check all token balances"
    exit 0
fi

# Amount in wei (1 token = 1e18 wei)
AMOUNT="1000000000000000000"

# Check required commands
if ! command -v bc &> /dev/null; then
    echo -e "${RED}❌ 'bc' command not found!${NC}"
    echo -e "${YELLOW}💡 Install bc: brew install bc (macOS) or apt-get install bc (Linux)${NC}"
    exit 1
fi

# Approve tokens for Permit2
approve_permit2() {
    local PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"
    
    echo -e "${BLUE}🔐 Checking Permit2 allowance...${NC}"
    
    CURRENT_ALLOWANCE=$(cast call "$ORIGIN_TOKEN_ADDRESS" \
        "allowance(address,address)" \
        "$USER_ADDR" \
        "$PERMIT2_ADDRESS" \
        --rpc-url $ORIGIN_RPC_URL)
    
    if [ "$CURRENT_ALLOWANCE" = "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
        echo -e "${BLUE}   Approving Permit2...${NC}"
        
        TX_HASH=$(cast send "$ORIGIN_TOKEN_ADDRESS" \
            "approve(address,uint256)" \
            "$PERMIT2_ADDRESS" \
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
            --private-key "$USER_PRIVATE_KEY" \
            --rpc-url $ORIGIN_RPC_URL \
            --json | jq -r '.transactionHash')
        
        echo -e "${GREEN}✅ Permit2 approved${NC}"
    else
        echo -e "${GREEN}✅ Sufficient allowance already exists${NC}"
    fi
}

# Approve Permit2 if needed
approve_permit2

# Build StandardOrder data
build_order_data() {
    CURRENT_TIME=$(date +%s)
    # Use milliseconds for nonce to avoid collisions when sending multiple intents quickly
    NONCE=$(perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000')
    FILL_DEADLINE=$((CURRENT_TIME + 3600))  # 1 hour
    EXPIRY=$FILL_DEADLINE
    
    # Convert addresses to bytes32
    OUTPUT_SETTLER_BYTES32="0x000000000000000000000000${OUTPUT_SETTLER_ADDRESS:2}"
    DEST_TOKEN_BYTES32="0x000000000000000000000000${DEST_TOKEN_ADDRESS:2}"
    RECIPIENT_BYTES32="0x000000000000000000000000${RECIPIENT_ADDR:2}"
    
    # Encode StandardOrder (output oracle is zero)
    ZERO_BYTES32="0x0000000000000000000000000000000000000000000000000000000000000000"
    # ABI type for StandardOrder encoding:
    # f(
    #   (
    #     address user,
    #     uint256 nonce,
    #     uint256 originChainId,
    #     uint32 expiry,
    #     uint32 fillDeadline,
    #     address oracle,
   #     uint256[2][] inputTokens,
   #     (
   #       bytes32 outputOracle,
   #       bytes32 outputSettler,
   #       uint256 destinationChainId,
   #       bytes32 destToken,
   #       uint256 amount,
   #       bytes32 recipient,
   #       bytes extra1,
   #       bytes extra2
   #     )[] outputs
   #   )
   # )
   STANDARD_ORDER_ABI_TYPE='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'
   ORDER_DATA=$(cast abi-encode "$STANDARD_ORDER_ABI_TYPE" \
       "(${USER_ADDR},${NONCE},${ORIGIN_CHAIN_ID},${EXPIRY},${FILL_DEADLINE},${ORACLE_ADDRESS},[[$ORIGIN_TOKEN_ADDRESS,$AMOUNT]],[($ZERO_BYTES32,$OUTPUT_SETTLER_BYTES32,${DEST_CHAIN_ID},$DEST_TOKEN_BYTES32,$AMOUNT,$RECIPIENT_BYTES32,0x,0x)])")
}

# Build the order data
build_order_data

echo -e "${BLUE}📋 Order Details:${NC}"
echo -e "   User: $USER_ADDR → Recipient: $RECIPIENT_ADDR"
echo -e "   Amount: 1.0 tokens ($ORIGIN_SYMBOL on chain $ORIGIN_CHAIN_ID → $DEST_SYMBOL on chain $DEST_CHAIN_ID)"
echo -e "   Origin Token: $ORIGIN_TOKEN_ADDRESS"
echo -e "   Dest Token:   $DEST_TOKEN_ADDRESS"
echo -e "   Fill Deadline: $(date -r $FILL_DEADLINE 2>/dev/null || date -d @$FILL_DEADLINE)"

echo ""
echo -e "${BLUE}📊 Current Balances:${NC}"
show_balances

echo ""
echo -e "${YELLOW}🔏 Generating EIP-712 signature...${NC}"

PERMIT2_NONCE=$NONCE

# Compute EIP-712 type hashes
MANDATE_OUTPUT_TYPE="MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
MANDATE_OUTPUT_TYPE_HASH=$(cast keccak "$MANDATE_OUTPUT_TYPE")

PERMIT2_WITNESS_TYPE="Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)${MANDATE_OUTPUT_TYPE}"
PERMIT2_WITNESS_TYPE_HASH=$(cast keccak "$PERMIT2_WITNESS_TYPE")

TOKEN_PERMISSIONS_TYPE="TokenPermissions(address token,uint256 amount)"
TOKEN_PERMISSIONS_TYPE_HASH=$(cast keccak "$TOKEN_PERMISSIONS_TYPE")

# Permit2 type string format
WITNESS_TYPE_STRING="Permit2Witness witness)${MANDATE_OUTPUT_TYPE}${TOKEN_PERMISSIONS_TYPE}Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)"
PERMIT_BATCH_WITNESS_STRING="PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,${WITNESS_TYPE_STRING}"

PERMIT_BATCH_WITNESS_TYPE_HASH=$(cast keccak "$PERMIT_BATCH_WITNESS_STRING")

# Domain separator for Permit2
DOMAIN_TYPE_HASH=$(cast keccak "EIP712Domain(string name,uint256 chainId,address verifyingContract)")
PERMIT2_NAME_HASH=$(cast keccak "Permit2")
DOMAIN_SEPARATOR=$(cast abi-encode "f(bytes32,bytes32,uint256,address)" "$DOMAIN_TYPE_HASH" "$PERMIT2_NAME_HASH" "$ORIGIN_CHAIN_ID" "0x000000000022D473030F116dDEE9F6B43aC78BA3")
DOMAIN_SEPARATOR_HASH=$(cast keccak "$DOMAIN_SEPARATOR")


# Compute hash of MandateOutput
compute_mandate_output_hash() {
    local oracle="0x0000000000000000000000000000000000000000000000000000000000000000"  # Zero for outputs
    local settler="$OUTPUT_SETTLER_BYTES32"
    local chainId="$DEST_CHAIN_ID"
    local token="$DEST_TOKEN_BYTES32"
    local amount="$AMOUNT"
    local recipient="$RECIPIENT_BYTES32"
    local callDataHash="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"  # keccak256("")
    local contextDataHash="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    
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
# Make sure bytes32 variables are defined before calling the function
OUTPUT_SETTLER_BYTES32="0x000000000000000000000000${OUTPUT_SETTLER_ADDRESS:2}"
DEST_TOKEN_BYTES32="0x000000000000000000000000${DEST_TOKEN_ADDRESS:2}"
RECIPIENT_BYTES32="0x000000000000000000000000${RECIPIENT_ADDR:2}"
MANDATE_OUTPUT_HASH=$(compute_mandate_output_hash)
OUTPUTS_HASH=$(cast keccak "$MANDATE_OUTPUT_HASH")

# Compute Permit2Witness hash
# From Permit2WitnessType.sol: keccak256(abi.encode(typeHash, expires, inputOracle, outputsHash))
PERMIT2_WITNESS_ENCODED=$(cast abi-encode "f(bytes32,uint32,address,bytes32)" \
    "$PERMIT2_WITNESS_TYPE_HASH" \
    "$EXPIRY" \
    "$ORACLE_ADDRESS" \
    "$OUTPUTS_HASH")
PERMIT2_WITNESS_HASH=$(cast keccak "$PERMIT2_WITNESS_ENCODED")

# Compute TokenPermissions hash
TOKEN_PERM_ENCODED=$(cast abi-encode "f(bytes32,address,uint256)" \
    "$TOKEN_PERMISSIONS_TYPE_HASH" \
    "$ORIGIN_TOKEN_ADDRESS" \
    "$AMOUNT")
TOKEN_PERM_HASH=$(cast keccak "$TOKEN_PERM_ENCODED")

# The witness hash is the Permit2Witness hash
WITNESS_HASH="$PERMIT2_WITNESS_HASH"

# Compute PermitBatchWitnessTransferFrom struct with array hashes
PERMITTED_ARRAY_HASH=$(cast keccak "$TOKEN_PERM_HASH")

# The main struct for signing includes the array hash
MAIN_STRUCT_ENCODED=$(cast abi-encode "f(bytes32,bytes32,address,uint256,uint256,bytes32)" \
    "$PERMIT_BATCH_WITNESS_TYPE_HASH" \
    "$PERMITTED_ARRAY_HASH" \
    "$INPUT_SETTLER_ADDRESS" \
    "$PERMIT2_NONCE" \
    "$FILL_DEADLINE" \
    "$WITNESS_HASH")
MAIN_STRUCT_HASH=$(cast keccak "$MAIN_STRUCT_ENCODED")

# Create final digest
DIGEST_PREFIX="0x1901"
DIGEST="${DIGEST_PREFIX}${DOMAIN_SEPARATOR_HASH:2}${MAIN_STRUCT_HASH:2}"
FINAL_DIGEST=$(cast keccak "$DIGEST")

# Debug output
echo -e "${BLUE}Debug: EIP-712 values${NC}"
echo "  Oracle address: $ORACLE_ADDRESS"
echo "  Oracle bytes32: 0x000000000000000000000000${ORACLE_ADDRESS:2}"
echo "  Mandate output hash: $MANDATE_OUTPUT_HASH"
echo "  Outputs hash: $OUTPUTS_HASH"
echo "  Witness hash: $WITNESS_HASH"
echo "  Type hash: $PERMIT_BATCH_WITNESS_TYPE_HASH"
echo "  Main struct hash: $MAIN_STRUCT_HASH"
echo "  Final digest: $FINAL_DIGEST"

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

# Lock type constants - these correspond to the LockType enum in the solver
LOCK_TYPE_PERMIT2_ESCROW=1      # Permit2-based escrow mechanism
LOCK_TYPE_EIP3009_ESCROW=2      # EIP-3009 based escrow mechanism  
LOCK_TYPE_RESOURCE_LOCK=3       # Resource lock mechanism (The Compact)

# Set the lock type to use for this intent
LOCK_TYPE=$LOCK_TYPE_PERMIT2_ESCROW

# Create the final JSON payload with signature
# The API expects the StandardOrder in bytes format along with the signature
# The signature needs to be prefixed with 0x00 for SIGNATURE_TYPE_PERMIT2
# lock_type values: 1=permit2-escrow, 2=eip3009-escrow, 3=resource-lock
PREFIXED_SIGNATURE="0x00${SIGNATURE:2}"
JSON_PAYLOAD=$(cat <<EOF
{
  "order": "$ORDER_DATA",
  "lock_type": "$LOCK_TYPE",
  "sponsor": "$USER_ADDR",
  "signature": "$PREFIXED_SIGNATURE"
}
EOF
)

echo -e "${GREEN}✅ Order ready for submission${NC}"

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
echo -e "${BLUE}   Route: $ORIGIN_SYMBOL → $DEST_SYMBOL${NC}"