#!/bin/bash
# send_onchain_intent.sh - Send a test intent transaction that calls InputSettler7683.open()
#
# This script creates an on-chain EIP-7683 cross-chain intent by calling the InputSettler
# contract's open() function. This demonstrates the flow for on-chain intent creation.
#
# FLOW:
# 1. Validate environment:
#    - Check that Anvil chains are running
#    - Verify contracts are deployed
#    - Load configuration from config/demo.toml
#
# 2. Build EIP-7683 intent data:
#    - Create MandateERC7683 struct with cross-chain order details
#    - Set 1 hour expiry time
#    - Specify input (1 TEST on origin) and output (1 TEST on destination)
#    - Encode data according to EIP-7683 specification
#
# 3. Approve tokens:
#    - Ensure InputSettler can spend user's TEST tokens
#    - Approve max amount if not already approved
#
# 4. Send intent transaction:
#    - Call InputSettler7683.open() with the encoded order data
#    - User's tokens are locked in the settler contract
#    - Intent is emitted as an on-chain event
#
# 5. Verify transaction:
#    - Check that user's balance decreased by 1 TEST
#    - Confirm tokens are held by InputSettler
#    - Display final balances on both chains
#
# PREREQUISITES:
#   - Run ./setup_local_anvil.sh first to deploy contracts
#   - Solver service should be running to discover and fill the intent
#
# USAGE:
#   ./send_onchain_intent.sh          - Send a complete intent transaction
#   ./send_onchain_intent.sh balances - Just check current balances
#   ./send_onchain_intent.sh approve  - Just approve tokens (no intent)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📤 Sending EIP-7683 Intent Transaction${NC}"
echo "====================================="

# Check required commands
if ! command -v bc &> /dev/null; then
    echo -e "${RED}❌ 'bc' command not found!${NC}"
    echo -e "${YELLOW}💡 Install bc: brew install bc (macOS) or apt-get install bc (Linux)${NC}"
    exit 1
fi

if ! command -v cast &> /dev/null; then
    echo -e "${RED}❌ 'cast' command not found!${NC}"
    echo -e "${YELLOW}💡 Install foundry: curl -L https://foundry.paradigm.xyz | bash${NC}"
    exit 1
fi

# Check if config exists
if [ ! -f "config/demo.toml" ]; then
    echo -e "${RED}❌ Configuration not found!${NC}"
    echo -e "${YELLOW}💡 Run './setup_local_anvil.sh' first${NC}"
    exit 1
fi

# Extract contract addresses from config - new format
# Parse the order section
INPUT_SETTLER_ADDRESS=$(grep 'input_settler_address = ' config/demo.toml | cut -d'"' -f2)
OUTPUT_SETTLER_ADDRESS=$(grep 'output_settler_address = ' config/demo.toml | cut -d'"' -f2)
SOLVER_ADDR=$(grep 'solver_address = ' config/demo.toml | cut -d'"' -f2)

# Parse the settlement section
ORACLE_ADDRESS=$(grep 'oracle_address = ' config/demo.toml | cut -d'"' -f2)

# Parse the demo configuration section
ORIGIN_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.origin\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
DEST_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.destination\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
USER_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'user = ' | cut -d'"' -f2)
USER_PRIVATE_KEY=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'user_private_key = ' | cut -d'"' -f2)
RECIPIENT_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'recipient = ' | cut -d'"' -f2)

# Configuration
ORIGIN_RPC_URL="http://localhost:8545"
DEST_RPC_URL="http://localhost:8546"
RPC_URL=$ORIGIN_RPC_URL  # Default for compatibility
AMOUNT="1000000000000000000"  # 1 token

echo -e "${BLUE}📋 Cross-Chain Intent Details:${NC}"
echo -e "   User (depositor): $USER_ADDR"
echo -e "   Solver:           $SOLVER_ADDR"
echo -e "   Recipient:        $RECIPIENT_ADDR"
echo -e "   Amount:           1.0 TEST tokens"
echo -e "   Origin Token:     $ORIGIN_TOKEN_ADDRESS (Chain 31337)"
echo -e "   Dest Token:       $DEST_TOKEN_ADDRESS (Chain 31338)"
echo -e "   InputSettler:     $INPUT_SETTLER_ADDRESS (Origin)"
echo -e "   OutputSettler:    $OUTPUT_SETTLER_ADDRESS (Destination)"


# Function to check balances
check_balance() {
    local address=$1
    local name=$2
    local rpc_url=${3:-$RPC_URL}
    local token_addr=${4:-$ORIGIN_TOKEN_ADDRESS}
    
    local balance_hex=$(cast call $token_addr "balanceOf(address)" $address --rpc-url $rpc_url 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    
    if [ -z "$balance_hex" ]; then
        echo -e "   $name: 0 TEST (Error: check RPC connection)"
        return
    fi
    
    local balance_dec=$(cast to-dec $balance_hex 2>/dev/null || echo "0")
    # Use explicit decimal division instead of exponentiation
    local balance_formatted=$(echo "scale=2; $balance_dec / 1000000000000000000" | bc -l 2>/dev/null || echo "0")
    echo -e "   $name: ${balance_formatted} TEST"
}

# Function to show current balances
show_balances() {
    echo -e "${BLUE}💰 Current Balances on Origin Chain (31337):${NC}"
    check_balance $USER_ADDR "User" $ORIGIN_RPC_URL $ORIGIN_TOKEN_ADDRESS
    check_balance $SOLVER_ADDR "Solver" $ORIGIN_RPC_URL $ORIGIN_TOKEN_ADDRESS
    check_balance $RECIPIENT_ADDR "Recipient" $ORIGIN_RPC_URL $ORIGIN_TOKEN_ADDRESS
    check_balance $INPUT_SETTLER_ADDRESS "InputSettler" $ORIGIN_RPC_URL $ORIGIN_TOKEN_ADDRESS
    
    echo -e "${BLUE}💰 Current Balances on Destination Chain (31338):${NC}"
    check_balance $USER_ADDR "User" $DEST_RPC_URL $DEST_TOKEN_ADDRESS
    check_balance $SOLVER_ADDR "Solver" $DEST_RPC_URL $DEST_TOKEN_ADDRESS
    check_balance $RECIPIENT_ADDR "Recipient" $DEST_RPC_URL $DEST_TOKEN_ADDRESS
    check_balance $OUTPUT_SETTLER_ADDRESS "OutputSettler" $DEST_RPC_URL $DEST_TOKEN_ADDRESS
}

# Function to build EIP-7683 intent data
build_intent_data() {
    echo -e "${YELLOW}🔧 Building EIP-7683 intent data...${NC}"
    
    # Calculate expiry (1 hour from now)
    EXPIRY=$(( $(date +%s) + 3600 ))
    
    # Convert values to hex format
    AMOUNT_HEX=$(printf "%064x" $AMOUNT)
    EXPIRY_HEX=$(printf "%064x" $EXPIRY)
    
    # Remove 0x prefix and pad addresses to 32 bytes (using origin token for input)
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
    
    # localOracle (use AlwaysYesOracle address)
    ORDER_DATA="${ORDER_DATA}${ORACLE_BYTES32}"
    
    # offset to inputs array (0x80 = 128 bytes from struct start)
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000080"
    
    # offset to outputs array (0xe0 = 224 bytes from struct start)
    ORDER_DATA="${ORDER_DATA}00000000000000000000000000000000000000000000000000000000000000e0"
    
    # inputs array: 1 input
    ORDER_DATA="${ORDER_DATA}0000000000000000000000000000000000000000000000000000000000000001"
    
    # Input struct: (token, amount) - user deposits this on origin chain
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
    
    # EIP-712 typehash for MandateERC7683
    ORDER_DATA_TYPE="0x532668680e4ed97945ec5ed6aee3633e99abe764fd2d2861903dc7c109b00e82"
    
    echo -e "${GREEN}✅ Intent data built successfully${NC}"
    echo -e "   Data length: ${#ORDER_DATA} characters"
    # Use platform-agnostic date formatting
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo -e "   Expiry: $(date -r $EXPIRY)"
    else
        # Linux
        echo -e "   Expiry: $(date -d @$EXPIRY)"
    fi
}

# Function to approve tokens
approve_tokens() {
    echo -e "${YELLOW}🔓 Approving InputSettler to spend tokens...${NC}"
    
    # Check current allowance
    CURRENT_ALLOWANCE=$(cast call $ORIGIN_TOKEN_ADDRESS \
        "allowance(address,address)" \
        $USER_ADDR \
        $INPUT_SETTLER_ADDRESS \
        --rpc-url $RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    
    # Convert to decimal for comparison
    ALLOWANCE_DEC=$(cast to-dec $CURRENT_ALLOWANCE 2>/dev/null || echo "0")
    REQUIRED_ALLOWANCE=$(cast to-dec $AMOUNT 2>/dev/null || echo "0")
    
    # Use bc for large number comparison
    if [ $(echo "$ALLOWANCE_DEC < $REQUIRED_ALLOWANCE" | bc) -eq 1 ]; then
        echo -e "${BLUE}   Insufficient allowance, approving...${NC}"
        
        APPROVE_TX=$(cast send $ORIGIN_TOKEN_ADDRESS \
            "approve(address,uint256)" \
            $INPUT_SETTLER_ADDRESS \
            "1000000000000000000000000" \
            --rpc-url $RPC_URL \
            --private-key $USER_PRIVATE_KEY 2>&1)
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Approval successful${NC}"
        else
            echo -e "${RED}❌ Approval failed:${NC}"
            echo "$APPROVE_TX"
            exit 1
        fi
    else
        echo -e "${GREEN}✅ Sufficient allowance already exists${NC}"
    fi
}

# Function to send intent transaction
send_intent() {
    echo -e "${YELLOW}🚀 Sending intent transaction...${NC}"
    
    # Call InputSettler7683.open()
    echo -e "${BLUE}   Calling InputSettler7683.open()...${NC}"
    
    INTENT_TX=$(cast send $INPUT_SETTLER_ADDRESS \
        "open((uint32,bytes32,bytes))" \
        "($EXPIRY,$ORDER_DATA_TYPE,$ORDER_DATA)" \
        --rpc-url $RPC_URL \
        --private-key $USER_PRIVATE_KEY 2>&1)
    
    if [ $? -eq 0 ]; then
        TX_HASH=$(echo "$INTENT_TX" | grep -o '"transactionHash":"0x[^"]*"' | head -1 | cut -d'"' -f4)
        
        if [ -z "$TX_HASH" ]; then
            TX_HASH=$(echo "$INTENT_TX" | grep -o '0x[a-fA-F0-9]\{64\}' | head -1)
        fi
        
        echo -e "${GREEN}✅ Intent transaction sent successfully!${NC}"
        
        if [ -n "$TX_HASH" ]; then
            echo -e "${BLUE}   Transaction Hash: $TX_HASH${NC}"
        fi
        
        # Wait for transaction to be mined
        WAIT_TIME="${WAIT_TIME:-30}"
        echo -e "${YELLOW}⏳ Waiting for transaction to be processed...(${WAIT_TIME}s)${NC}"
        sleep $WAIT_TIME
        
        return 0
    else
        echo -e "${RED}❌ Intent transaction failed:${NC}"
        echo "$INTENT_TX"
        return 1
    fi
}

# Function to verify transaction
verify_transaction() {
    echo -e "${YELLOW}🔍 Verifying cross-chain intent creation...${NC}"
    
    # For cross-chain intents, we expect:
    # Origin chain: User deposits tokens to InputSettler
    # Destination chain: No immediate changes (solver will fill later)
    
    # Get current balances on origin chain
    USER_BALANCE_HEX=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $USER_ADDR --rpc-url $ORIGIN_RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    USER_BALANCE_DEC=$(cast to-dec $USER_BALANCE_HEX 2>/dev/null || echo "0")
    
    SETTLER_BALANCE_HEX=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $INPUT_SETTLER_ADDRESS --rpc-url $ORIGIN_RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    SETTLER_BALANCE_DEC=$(cast to-dec $SETTLER_BALANCE_HEX 2>/dev/null || echo "0")
    
    # Calculate balance changes
    USER_BALANCE_CHANGE=$(echo "$USER_BALANCE_DEC - $INITIAL_USER_BALANCE" | bc)
    SETTLER_BALANCE_CHANGE=$(echo "$SETTLER_BALANCE_DEC - $INITIAL_SETTLER_BALANCE" | bc)
    
    # Expected changes: User loses 1 TEST (deposited via InputSettler)
    EXPECTED_USER_CHANGE=$(echo "-$AMOUNT" | bc)
    EXPECTED_SETTLER_CHANGE="0"
    
    # Verify origin chain changes
    USER_CORRECT=$(echo "$USER_BALANCE_CHANGE == $EXPECTED_USER_CHANGE" | bc)
    SETTLER_CORRECT=$(echo "$SETTLER_BALANCE_CHANGE == $EXPECTED_SETTLER_CHANGE" | bc)
    
    if [ "$USER_CORRECT" -eq 1 ] && [ "$SETTLER_CORRECT" -eq 1 ]; then
        echo -e "${GREEN}✅ Cross-chain intent created successfully!${NC}"
        echo ""
        echo -e "${BLUE}📊 Origin Chain (31337) - Intent Created:${NC}"
        echo -e "   User deposited: $(echo "scale=2; -1 * $USER_BALANCE_CHANGE / 1000000000000000000" | bc -l) TEST → InputSettler"
        echo -e "   InputSettler holding: $(echo "scale=2; $SETTLER_BALANCE_CHANGE / 1000000000000000000" | bc -l) TEST"
        echo ""
        echo -e "${YELLOW}⏳ Waiting for solver to fill on destination chain...${NC}"
        echo -e "   The solver will:"
        echo -e "   1. Send 1 TEST to recipient on destination chain (31338)"
        echo -e "   2. Claim 1 TEST from InputSettler on origin chain (31337)"
    else
        echo -e "${RED}❌ Intent creation failed${NC}"
        echo -e "   User balance change: $(echo "scale=2; $USER_BALANCE_CHANGE / 1000000000000000000" | bc -l) TEST (expected: -1.0)"
        echo -e "   InputSettler balance change: $(echo "scale=2; $SETTLER_BALANCE_CHANGE / 1000000000000000000" | bc -l) TEST (expected: +1.0)"
        return 1
    fi
    
    echo ""
    echo -e "${BLUE}📋 Cross-chain intent is ready for solver discovery${NC}"
}

# Global variables to store initial balances
INITIAL_USER_BALANCE=""
INITIAL_RECIPIENT_BALANCE=""
INITIAL_SOLVER_BALANCE=""
INITIAL_SETTLER_BALANCE=""

# Main execution
main() {
    # Check if Anvil is running
    if ! curl -s $RPC_URL > /dev/null; then
        echo -e "${RED}❌ Anvil is not running on $RPC_URL${NC}"
        echo -e "${YELLOW}💡 Run './setup_local_anvil.sh' first${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"
    
    # Verify contracts are deployed
    if ! cast code $ORIGIN_TOKEN_ADDRESS --rpc-url $RPC_URL | grep -q "0x"; then
        echo -e "${RED}❌ TestToken not deployed at $ORIGIN_TOKEN_ADDRESS${NC}"
        exit 1
    fi
    
    if ! cast code $INPUT_SETTLER_ADDRESS --rpc-url $RPC_URL | grep -q "0x"; then
        echo -e "${RED}❌ InputSettler7683 not deployed at $INPUT_SETTLER_ADDRESS${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All contracts verified${NC}"
    
    # Store initial balances for comparison
    echo -e "${BLUE}📊 Storing initial balances...${NC}"
    INITIAL_USER_BALANCE_HEX=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $USER_ADDR --rpc-url $ORIGIN_RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    INITIAL_USER_BALANCE=$(cast to-dec $INITIAL_USER_BALANCE_HEX 2>/dev/null || echo "0")
    
    INITIAL_SOLVER_BALANCE_HEX=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $SOLVER_ADDR --rpc-url $ORIGIN_RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    INITIAL_SOLVER_BALANCE=$(cast to-dec $INITIAL_SOLVER_BALANCE_HEX 2>/dev/null || echo "0")
    
    INITIAL_SETTLER_BALANCE_HEX=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $INPUT_SETTLER_ADDRESS --rpc-url $ORIGIN_RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    INITIAL_SETTLER_BALANCE=$(cast to-dec $INITIAL_SETTLER_BALANCE_HEX 2>/dev/null || echo "0")
    
    INITIAL_RECIPIENT_BALANCE_HEX=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $RECIPIENT_ADDR --rpc-url $ORIGIN_RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    INITIAL_RECIPIENT_BALANCE=$(cast to-dec $INITIAL_RECIPIENT_BALANCE_HEX 2>/dev/null || echo "0")
    
    # Show initial balances
    echo ""
    echo -e "${BLUE}📊 BEFORE Intent Creation:${NC}"
    show_balances
    
    # Build intent data
    echo ""
    build_intent_data
    
    # Approve tokens
    echo ""
    approve_tokens
    
    # Send intent
    echo ""
    send_intent
    
    # Verify results
    echo ""
    verify_transaction
    
    # Show final balances
    echo ""
    echo -e "${BLUE}📊 AFTER Intent Creation:${NC}"
    show_balances
    
    echo ""
    echo -e "${GREEN}🎉 Intent Transaction Complete!${NC}"
    echo -e "${YELLOW}🔍 Check discovery events at: http://localhost:8080/api/v1/discovery/stats${NC}"
}

# Handle different commands
case "${1:-send}" in
    "send")
        main
        ;;
    "balances")
        if [ -f "config/demo.toml" ]; then
            # Check required commands first
            if ! command -v bc &> /dev/null; then
                echo -e "${RED}❌ 'bc' command not found!${NC}"
                echo -e "${YELLOW}💡 Install bc: brew install bc (macOS) or apt-get install bc (Linux)${NC}"
                exit 1
            fi
            
            # Parse the order section
            INPUT_SETTLER_ADDRESS=$(grep 'input_settler_address = ' config/demo.toml | cut -d'"' -f2)
            OUTPUT_SETTLER_ADDRESS=$(grep 'output_settler_address = ' config/demo.toml | cut -d'"' -f2)
            SOLVER_ADDR=$(grep 'solver_address = ' config/demo.toml | cut -d'"' -f2)
            
            # Parse the demo configuration section
            ORIGIN_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.origin\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
            DEST_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.destination\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
            USER_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'user = ' | cut -d'"' -f2)
            RECIPIENT_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'recipient = ' | cut -d'"' -f2)
            ORIGIN_RPC_URL="http://localhost:8545"
            DEST_RPC_URL="http://localhost:8546"
            show_balances
        else
            echo -e "${RED}❌ Configuration not found!${NC}"
        fi
        ;;
    "approve")
        if [ -f "config/demo.toml" ]; then
            # Check required commands first
            if ! command -v bc &> /dev/null; then
                echo -e "${RED}❌ 'bc' command not found!${NC}"
                echo -e "${YELLOW}💡 Install bc: brew install bc (macOS) or apt-get install bc (Linux)${NC}"
                exit 1
            fi
            
            # Parse the order section
            INPUT_SETTLER_ADDRESS=$(grep 'input_settler_address = ' config/demo.toml | cut -d'"' -f2)
            
            # Parse the demo configuration section
            ORIGIN_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.origin\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
            USER_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'user = ' | cut -d'"' -f2)
            USER_PRIVATE_KEY=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'user_private_key = ' | cut -d'"' -f2)
            RPC_URL="http://localhost:8545"
            AMOUNT="1000000000000000000"  # 1 token
            approve_tokens
        else
            echo -e "${RED}❌ Configuration not found!${NC}"
        fi
        ;;
    *)
        echo "Usage: $0 [send|balances|approve]"
        echo ""
        echo "Commands:"
        echo "  send (default) - Send a complete intent transaction"
        echo "  balances       - Check current token balances"
        echo "  approve        - Just approve tokens (no intent)"
        exit 1
        ;;
esac