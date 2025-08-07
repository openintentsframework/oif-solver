#!/bin/bash
# Send an on-chain cross-chain intent by calling InputSettlerEscrow.open()
# Prerequisites: Run ./setup_local_anvil.sh and start the solver service
#
# Usage:
#   ./send_onchain_intent.sh          - Send intent transaction
#   ./send_onchain_intent.sh balances - Check balances only
#   ./send_onchain_intent.sh approve  - Approve tokens only

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

# Load addresses from config
INPUT_SETTLER_ADDRESS=$(grep 'input_settler_address = ' config/demo.toml | cut -d'"' -f2)
OUTPUT_SETTLER_ADDRESS=$(grep 'output_settler_address = ' config/demo.toml | cut -d'"' -f2)
SOLVER_ADDR=$(grep 'solver_address = ' config/demo.toml | cut -d'"' -f2)
ORACLE_ADDRESS=$(grep 'oracle_address = ' config/demo.toml | cut -d'"' -f2)
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
ORIGIN_CHAIN_ID=31337
DEST_CHAIN_ID=31338

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

# Build StandardOrder data
build_intent_data() {
    echo -e "${YELLOW}🔧 Building StandardOrder intent data...${NC}"
    
    CURRENT_TIME=$(date +%s)
    EXPIRY=$(( CURRENT_TIME + 3600 ))        # 1 hour
    FILL_DEADLINE=$(( CURRENT_TIME + 7200 )) # 2 hours
    NONCE=$CURRENT_TIME
    
    # Convert addresses to bytes32 (right-padded)
    ORACLE_BYTES32="0x0000000000000000000000000000000000000000000000000000000000000000"  # Zero for outputs
    SETTLER_BYTES32="0x000000000000000000000000$(echo $OUTPUT_SETTLER_ADDRESS | cut -c3-)"
    TOKEN_BYTES32="0x000000000000000000000000$(echo $DEST_TOKEN_ADDRESS | cut -c3-)"
    RECIPIENT_BYTES32="0x000000000000000000000000$(echo $RECIPIENT_ADDR | cut -c3-)"
    
    # Encode StandardOrder
    ORDER_DATA=$(cast abi-encode "f((address,uint256,uint256,uint32,uint32,address,(uint256,uint256)[],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))" \
        "($USER_ADDR,$NONCE,$ORIGIN_CHAIN_ID,$EXPIRY,$FILL_DEADLINE,$ORACLE_ADDRESS,[($ORIGIN_TOKEN_ADDRESS,$AMOUNT)],[($ORACLE_BYTES32,$SETTLER_BYTES32,$DEST_CHAIN_ID,$TOKEN_BYTES32,$AMOUNT,$RECIPIENT_BYTES32,0x,0x)])")
    
    echo -e "${GREEN}✅ StandardOrder data built${NC}"
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
    
    # Call InputSettlerEscrow.open()
    echo -e "${BLUE}   Calling InputSettlerEscrow.open()...${NC}"
    
    INTENT_TX=$(cast send $INPUT_SETTLER_ADDRESS \
        "open(bytes)" \
        "$ORDER_DATA" \
        --rpc-url $RPC_URL \
        --private-key $USER_PRIVATE_KEY 2>&1)
    
    CAST_EXIT_CODE=$?
    
    if [ $CAST_EXIT_CODE -eq 0 ]; then
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
        echo -e "${RED}❌ Intent transaction failed (exit code: $CAST_EXIT_CODE):${NC}"
        echo "$INTENT_TX"
        echo -e "${YELLOW}Debug info:${NC}"
        echo "  INPUT_SETTLER_ADDRESS: $INPUT_SETTLER_ADDRESS"
        echo "  ORDER_DATA length: ${#ORDER_DATA}"
        echo "  First 100 chars of ORDER_DATA: ${ORDER_DATA:0:100}..."
        return 1
    fi
}

# Verify transaction
verify_transaction() {
    echo -e "${YELLOW}🔍 Verifying intent creation...${NC}"
    
    # Get current balances
    USER_BALANCE_HEX=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $USER_ADDR --rpc-url $ORIGIN_RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    USER_BALANCE_DEC=$(cast to-dec $USER_BALANCE_HEX 2>/dev/null || echo "0")
    
    SETTLER_BALANCE_HEX=$(cast call $ORIGIN_TOKEN_ADDRESS "balanceOf(address)" $INPUT_SETTLER_ADDRESS --rpc-url $ORIGIN_RPC_URL 2>&1 | grep -E '^0x[0-9a-fA-F]+$' | tail -1)
    SETTLER_BALANCE_DEC=$(cast to-dec $SETTLER_BALANCE_HEX 2>/dev/null || echo "0")
    
    # Calculate changes
    USER_BALANCE_CHANGE=$(echo "$USER_BALANCE_DEC - $INITIAL_USER_BALANCE" | bc)
    SETTLER_BALANCE_CHANGE=$(echo "$SETTLER_BALANCE_DEC - $INITIAL_SETTLER_BALANCE" | bc)
    
    EXPECTED_USER_CHANGE=$(echo "-$AMOUNT" | bc)
    
    if [ $(echo "$USER_BALANCE_CHANGE == $EXPECTED_USER_CHANGE" | bc) -eq 1 ]; then
        echo -e "${GREEN}✅ Intent created successfully!${NC}"
        echo -e "   User deposited: 1.0 TEST → InputSettler"
    else
        echo -e "${RED}❌ Intent creation failed${NC}"
        return 1
    fi
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