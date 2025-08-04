#!/bin/bash
# Show current token balances across both chains
# Prerequisites: Run ./setup_local_anvil.sh first to generate config/demo.toml
#
# Usage:
#   ./show_balances.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📊 Current Token Balances${NC}"
echo "========================="

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
ORIGIN_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.origin\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
DEST_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.destination\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
USER_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'user = ' | cut -d'"' -f2)
RECIPIENT_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'recipient = ' | cut -d'"' -f2)

# Configuration
ORIGIN_RPC_URL="http://localhost:8545"
DEST_RPC_URL="http://localhost:8546"

# Function to check balances
check_balance() {
    local address=$1
    local name=$2
    local rpc_url=${3:-$ORIGIN_RPC_URL}
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

# Check if Anvil chains are running
echo -e "${BLUE}🔍 Checking RPC connections...${NC}"

if ! curl -s $ORIGIN_RPC_URL > /dev/null; then
    echo -e "${RED}❌ Origin chain not running on $ORIGIN_RPC_URL${NC}"
    echo -e "${YELLOW}💡 Run './setup_local_anvil.sh' first${NC}"
    exit 1
fi

if ! curl -s $DEST_RPC_URL > /dev/null; then
    echo -e "${RED}❌ Destination chain not running on $DEST_RPC_URL${NC}"
    echo -e "${YELLOW}💡 Run './setup_local_anvil.sh' first${NC}"
    exit 1
fi

echo -e "${GREEN}✅ RPC connections verified${NC}"
echo ""

# Show balances
show_balances

echo ""
echo -e "${GREEN}📊 Balance check complete!${NC}"