#!/bin/bash
# setup_local_anvil.sh - Deploy dual-chain local Anvil setup with EIP-7683 contracts
#
# This script sets up a complete local testing environment for EIP-7683 cross-chain intents:
#
# FLOW:
# 1. Start two Anvil chains:
#    - Origin chain (port 8545, chain ID 31337) - Where intents are created
#    - Destination chain (port 8546, chain ID 31338) - Where intents are fulfilled
#
# 2. Deploy contracts on both chains:
#    - Origin: TestToken, Permit2, TheCompact, AlwaysYesOracle, InputSettler7683
#    - Destination: TestToken, Permit2, OutputSettler7683
#
# 3. Setup initial state:
#    - Mint 100 TEST tokens to user on origin chain (for creating intents)
#    - Mint 100 TEST tokens to solver on destination chain (for fulfilling intents)
#    - Approve OutputSettler to spend solver's tokens
#
# 4. Generate configuration:
#    - Creates config/demo.toml with all deployed addresses
#    - Creates .env file with RPC URLs
#
# USAGE:
#   ./setup_local_anvil.sh         - Setup everything and keep running
#   ./setup_local_anvil.sh stop    - Stop all Anvil instances
#   ./setup_local_anvil.sh status  - Check if chains are running
#
# ACCOUNTS:
#   Solver: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (Anvil account #0)
#   User: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (Anvil account #1)
#   Recipient: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC (Anvil account #2)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - Origin Chain (where orders are created)
ORIGIN_CHAIN_ID=31337
ORIGIN_PORT=8545
ORIGIN_RPC_URL="http://localhost:$ORIGIN_PORT"

# Configuration - Destination Chain (where orders are fulfilled)
DEST_CHAIN_ID=31338
DEST_PORT=8546
DEST_RPC_URL="http://localhost:$DEST_PORT"

# Shared account keys (same across both chains)
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
PUBLIC_KEY="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
USER_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
USER_ADDR="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
RECIPIENT_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
RECIPIENT_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

echo -e "${BLUE}🔧 Setting up Dual-Chain Local Anvil with EIP-7683 Contracts${NC}"
echo "============================================================"
echo -e "${YELLOW}Origin Chain: $ORIGIN_RPC_URL (Chain ID: $ORIGIN_CHAIN_ID)${NC}"
echo -e "${YELLOW}Destination Chain: $DEST_RPC_URL (Chain ID: $DEST_CHAIN_ID)${NC}"

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}Port $1 is in use. Killing existing process...${NC}"
        kill -9 $(lsof -t -i:$1) 2>/dev/null || true
        sleep 2
    fi
}

# Function to start anvil instances
start_anvil_chain() {
    local chain_name=$1
    local chain_id=$2
    local port=$3
    local pid_file="${chain_name}_anvil.pid"
    local log_file="${chain_name}_anvil.log"
    
    echo -e "${YELLOW}🚀 Starting $chain_name Anvil on port $port (Chain ID: $chain_id)...${NC}"
    check_port $port
    
    ~/.foundry/bin/anvil \
        --chain-id $chain_id \
        --port $port \
        --host 0.0.0.0 \
        --accounts 10 \
        --balance 10000 \
        --gas-limit 30000000 \
        --code-size-limit 50000 \
        --base-fee 0 \
        --gas-price 1000000000 \
        --auto-impersonate \
        --block-time 2 \
        > $log_file 2>&1 &
    
    local anvil_pid=$!
    echo $anvil_pid > $pid_file
    
    # Wait for anvil to start
    echo -e "${YELLOW}⏳ Waiting for $chain_name Anvil to start...${NC}"
    for i in {1..15}; do
        if curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
            http://localhost:$port > /dev/null; then
            echo -e "${GREEN}✅ $chain_name Anvil started successfully${NC}"
            return 0
        fi
        sleep 1
    done
    
    echo -e "${RED}❌ Failed to start $chain_name Anvil${NC}"
    exit 1
}

# Function to start both chains
start_anvil() {
    start_anvil_chain "Origin" $ORIGIN_CHAIN_ID $ORIGIN_PORT
    start_anvil_chain "Destination" $DEST_CHAIN_ID $DEST_PORT
}

# Function to deploy a token contract
deploy_token() {
    local chain_name=$1
    local rpc_url=$2
    
    echo -e "${BLUE}🪙 Deploying TestToken on $chain_name chain...${NC}" >&2
    local token_output=$(~/.foundry/bin/forge create /tmp/TestToken.sol:TestToken \
        --rpc-url $rpc_url \
        --private-key $PRIVATE_KEY \
        --broadcast 2>&1)
    
    local token_address=$(echo "$token_output" | grep "Deployed to:" | awk '{print $3}')
    if [ -z "$token_address" ]; then
        echo -e "${RED}❌ Failed to deploy TestToken on $chain_name${NC}" >&2
        echo "$token_output" >&2
        exit 1
    fi
    echo -e "${GREEN}✅ TestToken deployed on $chain_name: $token_address${NC}" >&2
    echo $token_address
}

# Function to deploy Permit2 (needed on both chains)
deploy_permit2() {
    local chain_name=$1
    local rpc_url=$2
    
    echo -e "${BLUE}🔐 Checking Permit2 on $chain_name chain...${NC}" >&2
    local permit2_address="0x000000000022D473030F116dDEE9F6B43aC78BA3"
    
    # Check if Permit2 is already deployed
    local permit2_code=$(RUST_LOG= ~/.foundry/bin/cast code $permit2_address --rpc-url $rpc_url 2>&1)
    
    # Extract just the hex code from output
    permit2_code=$(echo "$permit2_code" | grep "^0x" | tail -n1)
    
    # If no valid hex found, default to "0x"
    if [ -z "$permit2_code" ]; then
        permit2_code="0x"
    fi
    if [ "$permit2_code" = "0x" ]; then
        echo -e "${YELLOW}   Permit2 NOT deployed, fetching bytecode from mainnet...${NC}" >&2
        
        # Get Permit2 bytecode from mainnet
        echo -e "${BLUE}   Fetching from mainnet (this may take a moment)...${NC}" >&2
        
        # Get Permit2 bytecode from mainnet using a temp file
        local temp_file="/tmp/permit2_code_$$.txt"
        RUST_LOG= ~/.foundry/bin/cast code $permit2_address --rpc-url https://eth.llamarpc.com > "$temp_file" 2>/dev/null
        
        # Read the bytecode from file
        local mainnet_permit2_code=""
        if [ -f "$temp_file" ]; then
            mainnet_permit2_code=$(grep "^0x" "$temp_file" | head -n1)
            rm -f "$temp_file"
        fi
        
        if [ ! -z "$mainnet_permit2_code" ] && [ "$mainnet_permit2_code" != "0x" ]; then
            echo -e "${BLUE}   Deploying Permit2 bytecode (${#mainnet_permit2_code} chars)...${NC}" >&2
            
            # Deploy using mainnet bytecode
            echo -e "${BLUE}   Executing deployment...${NC}" >&2
            local deploy_output=$(~/.foundry/bin/cast rpc anvil_setCode $permit2_address "$mainnet_permit2_code" --rpc-url $rpc_url 2>&1)
            local deploy_exit_code=$?
            
            if [ $deploy_exit_code -ne 0 ]; then
                echo -e "${RED}   ❌ Deployment command failed with exit code: $deploy_exit_code${NC}" >&2
                echo -e "${RED}   Error output: $deploy_output${NC}" >&2
                exit 1
            fi
            
            # Verify deployment by checking the code again
            echo -e "${BLUE}   Verifying deployment...${NC}" >&2
            local new_code_output=$(RUST_LOG= ~/.foundry/bin/cast code $permit2_address --rpc-url $rpc_url 2>&1)
            
            # Extract just the hex code
            local new_code=$(echo "$new_code_output" | grep "^0x" | tail -n1)
            if [ ! -z "$new_code" ] && [ "$new_code" != "0x" ] && [[ "$new_code" =~ ^0x[0-9a-fA-F]+$ ]]; then
                echo -e "${GREEN}   ✅ Permit2 deployed successfully (${#new_code} chars)${NC}" >&2
            else
                echo -e "${RED}   ❌ Failed to deploy Permit2 - verification failed${NC}" >&2
                echo -e "${RED}   Deploy output: '$deploy_output'${NC}" >&2
                echo -e "${RED}   Verification output: '$new_code_output'${NC}" >&2
                echo -e "${RED}   Extracted code: '$new_code'${NC}" >&2
                echo -e "${RED}   ❌ Off-chain intents will NOT work${NC}" >&2
                exit 1
            fi
        else
            echo -e "${RED}   ❌ Could not fetch Permit2 bytecode from mainnet${NC}" >&2
            echo -e "${RED}   ❌ Off-chain intents will NOT work without Permit2${NC}" >&2
            exit 1
        fi
    else
        echo -e "${GREEN}   ✅ Permit2 already deployed (${#permit2_code} chars)${NC}" >&2
    fi
    
    echo $permit2_address
}

# Function to deploy contracts
deploy_contracts() {
    echo -e "${YELLOW}📋 Deploying EIP-7683 contracts on both chains...${NC}"
    
    # Clone oif-contracts if it doesn't exist
    if [ ! -d "oif-contracts" ]; then
        echo -e "${YELLOW}📥 Cloning oif-contracts repository...${NC}"
        git clone https://github.com/openintentsframework/oif-contracts
    fi
    
    cd oif-contracts
    
    # Create TestToken contract
    cat > /tmp/TestToken.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract TestToken {
    string public name = "TestToken";
    string public symbol = "TEST";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor() {
        totalSupply = 0;
    }
    
    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
    
    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }
    
    function mint(address to, uint256 value) public {
        balanceOf[to] += value;
        totalSupply += value;
        emit Transfer(address(0), to, value);
    }
}
EOF

    echo -e "${YELLOW}=== ORIGIN CHAIN DEPLOYMENT ====${NC}"
    
    # Deploy token on Origin chain
    echo -e "${BLUE}🪙 Starting Origin token deployment...${NC}"
    ORIGIN_TOKEN_ADDRESS=$(deploy_token "Origin" $ORIGIN_RPC_URL)
    if [ -z "$ORIGIN_TOKEN_ADDRESS" ]; then
        echo -e "${RED}❌ Failed to get Origin token address${NC}"
        exit 1
    fi
    echo -e "${GREEN}🪙 Origin token address captured: $ORIGIN_TOKEN_ADDRESS${NC}"
    
    # Deploy Permit2 on Origin chain
    ORIGIN_PERMIT2_ADDRESS=$(deploy_permit2 "Origin" $ORIGIN_RPC_URL)
    
    # Deploy The Compact on Origin chain
    echo -e "${BLUE}🏦 Deploying The Compact on Origin chain...${NC}"
    ORIGIN_COMPACT_OUTPUT=$(~/.foundry/bin/forge create lib/the-compact/src/TheCompact.sol:TheCompact \
        --rpc-url $ORIGIN_RPC_URL \
        --private-key $PRIVATE_KEY \
        --broadcast 2>&1)
    
    ORIGIN_COMPACT_ADDRESS=$(echo "$ORIGIN_COMPACT_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
    if [ -z "$ORIGIN_COMPACT_ADDRESS" ]; then
        echo -e "${RED}❌ Failed to deploy The Compact on Origin${NC}"
        echo "$ORIGIN_COMPACT_OUTPUT"
        exit 1
    fi
    echo -e "${GREEN}✅ The Compact deployed on Origin: $ORIGIN_COMPACT_ADDRESS${NC}"

    # Deploy Oracle on Origin chain
    echo -e "${BLUE}🔮 Deploying AlwaysYesOracle on Origin chain...${NC}"
    ORACLE_OUTPUT=$(~/.foundry/bin/forge create test/mocks/AlwaysYesOracle.sol:AlwaysYesOracle \
        --rpc-url $ORIGIN_RPC_URL \
        --private-key $PRIVATE_KEY \
        --broadcast 2>&1)
    
    ORACLE_ADDRESS=$(echo "$ORACLE_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
    if [ -z "$ORACLE_ADDRESS" ]; then
        echo -e "${RED}❌ Failed to deploy AlwaysYesOracle on Origin${NC}"
        echo "$ORACLE_OUTPUT"
        exit 1
    fi
    echo -e "${GREEN}✅ AlwaysYesOracle deployed on Origin: $ORACLE_ADDRESS${NC}"

    # Deploy InputSettler on Origin chain
    echo -e "${BLUE}⚖️ Deploying InputSettler7683 on Origin chain...${NC}"
    INPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/input/7683/InputSettler7683.sol:InputSettler7683 \
        --rpc-url $ORIGIN_RPC_URL \
        --private-key $PRIVATE_KEY \
        --broadcast 2>&1)
    
    INPUT_SETTLER_ADDRESS=$(echo "$INPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
    if [ -z "$INPUT_SETTLER_ADDRESS" ]; then
        echo -e "${RED}❌ Failed to deploy InputSettler7683 on Origin${NC}"
        echo "$INPUT_SETTLER_OUTPUT"
        exit 1
    fi
    echo -e "${GREEN}✅ InputSettler7683 deployed on Origin: $INPUT_SETTLER_ADDRESS${NC}"

    echo -e "${YELLOW}=== DESTINATION CHAIN DEPLOYMENT ====${NC}"
    
    # Deploy token on Destination chain
    echo -e "${BLUE}🪙 Starting Destination token deployment...${NC}"
    DEST_TOKEN_ADDRESS=$(deploy_token "Destination" $DEST_RPC_URL)
    if [ -z "$DEST_TOKEN_ADDRESS" ]; then
        echo -e "${RED}❌ Failed to get Destination token address${NC}"
        exit 1
    fi
    echo -e "${GREEN}🪙 Destination token address captured: $DEST_TOKEN_ADDRESS${NC}"
    
    # Deploy Permit2 on Destination chain
    DEST_PERMIT2_ADDRESS=$(deploy_permit2 "Destination" $DEST_RPC_URL)

    # Deploy OutputSettler on Destination chain
    echo -e "${BLUE}⚖️ Deploying OutputSettler7683 on Destination chain...${NC}"
    OUTPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/output/coin/OutputSettler7683.sol:OutputInputSettler7683 \
        --rpc-url $DEST_RPC_URL \
        --private-key $PRIVATE_KEY \
        --broadcast 2>&1)
    
    OUTPUT_SETTLER_ADDRESS=$(echo "$OUTPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
    if [ -z "$OUTPUT_SETTLER_ADDRESS" ]; then
        echo -e "${RED}❌ Failed to deploy OutputSettler7683 on Destination${NC}"
        echo "$OUTPUT_SETTLER_OUTPUT"
        exit 1
    fi
    echo -e "${GREEN}✅ OutputSettler7683 deployed on Destination: $OUTPUT_SETTLER_ADDRESS${NC}"

    cd ..
    rm -f /tmp/TestToken.sol
    
    # Store contract addresses for both chains
    export ORIGIN_TOKEN_ADDRESS
    export ORIGIN_PERMIT2_ADDRESS
    export ORIGIN_COMPACT_ADDRESS
    export ORACLE_ADDRESS
    export INPUT_SETTLER_ADDRESS
    
    export DEST_TOKEN_ADDRESS
    export DEST_PERMIT2_ADDRESS
    export OUTPUT_SETTLER_ADDRESS
}

# Function to mint tokens and setup
setup_tokens() {
    echo -e "${YELLOW}💰 Minting tokens and setting up accounts on both chains...${NC}"
    
    echo -e "${YELLOW}=== ORIGIN CHAIN TOKEN SETUP ====${NC}"
    echo -e "${BLUE}🔍 Using Origin token address: $ORIGIN_TOKEN_ADDRESS${NC}"
    
    if [ -z "$ORIGIN_TOKEN_ADDRESS" ]; then
        echo -e "${RED}❌ Origin token address is empty! Cannot proceed with token setup.${NC}"
        exit 1
    fi
    
    # Mint tokens to user on Origin chain (for deposits)
    ~/.foundry/bin/cast send $ORIGIN_TOKEN_ADDRESS \
        "mint(address,uint256)" \
        $USER_ADDR \
        "100000000000000000000" \
        --rpc-url $ORIGIN_RPC_URL \
        --private-key $PRIVATE_KEY \
        > /dev/null 2>&1
    
    echo -e "${GREEN}✅ Origin chain tokens minted:${NC}"
    echo -e "   User ($USER_ADDR): 100 TEST"
    
    echo -e "${YELLOW}=== DESTINATION CHAIN TOKEN SETUP ====${NC}"
    echo -e "${BLUE}🔍 Using Destination token address: $DEST_TOKEN_ADDRESS${NC}"
    
    if [ -z "$DEST_TOKEN_ADDRESS" ]; then
        echo -e "${RED}❌ Destination token address is empty! Cannot proceed with token setup.${NC}"
        exit 1
    fi
    
    
    # Mint tokens to solver on Destination chain (for liquidity/fulfillment)
    ~/.foundry/bin/cast send $DEST_TOKEN_ADDRESS \
        "mint(address,uint256)" \
        $PUBLIC_KEY \
        "100000000000000000000" \
        --rpc-url $DEST_RPC_URL \
        --private-key $PRIVATE_KEY \
        > /dev/null 2>&1
    
    echo -e "${GREEN}✅ Destination chain tokens minted:${NC}"
    echo -e "   Solver ($PUBLIC_KEY): 100 TEST"
    
    # Approve OutputSettler to spend solver's tokens on destination chain
    echo -e "${YELLOW}💰 Approving OutputSettler to spend solver's tokens...${NC}"
    ~/.foundry/bin/cast send $DEST_TOKEN_ADDRESS \
        "approve(address,uint256)" \
        $OUTPUT_SETTLER_ADDRESS \
        "1000000000000000000000000" \
        --rpc-url $DEST_RPC_URL \
        --private-key $PRIVATE_KEY \
        > /dev/null 2>&1
    
    echo -e "${GREEN}✅ OutputSettler approved to spend solver's tokens on destination chain${NC}"
}

# Function to create configuration
create_config() {
    echo -e "${YELLOW}📝 Creating dual-chain solver configuration with templates...${NC}"
    
    mkdir -p config
    
    cat > config/demo.toml << EOF
# OIF Solver Configuration - Local Dual-Chain Setup

[solver]
id = "oif-solver-local-dual-chain"
monitoring_timeout_minutes = 5

[storage]
backend = "memory" # or "file"
[storage.config] 
# storage_path = "./data/storage" # Only relevant for "file" backend

[account]
provider = "local"
[account.config]
private_key = "$PRIVATE_KEY"

[delivery]
min_confirmations = 1
[delivery.providers.origin]
rpc_url = "$ORIGIN_RPC_URL"
private_key = "$PRIVATE_KEY"
chain_id = $ORIGIN_CHAIN_ID

[delivery.providers.destination]
rpc_url = "$DEST_RPC_URL"
private_key = "$PRIVATE_KEY"
chain_id = $DEST_CHAIN_ID

[discovery]
[discovery.sources.onchain_eip7683]
rpc_url = "$ORIGIN_RPC_URL"
settler_addresses = ["$INPUT_SETTLER_ADDRESS"]

[discovery.sources.offchain_eip7683]
api_host = "0.0.0.0"
api_port = 8081
rpc_url = "http://localhost:8545"
# auth_token = "your-secret-token"

[order]
[order.implementations.eip7683]
output_settler_address = "$OUTPUT_SETTLER_ADDRESS"
input_settler_address = "$INPUT_SETTLER_ADDRESS"
solver_address = "$PUBLIC_KEY"

[order.execution_strategy]
strategy_type = "simple"
[order.execution_strategy.config]
max_gas_price_gwei = 100

[settlement]
[settlement.implementations.eip7683]
rpc_url = "$DEST_RPC_URL"
oracle_address = "$ORACLE_ADDRESS"
dispute_period_seconds = 1

# ============================================================================
# DEMO SCRIPT CONFIGURATION
# The following sections are used by demo scripts (send_onchain_intent.sh, etc.)
# and are NOT required by the solver itself. The solver only needs the
# configurations above.
# ============================================================================

# Contract addresses for testing (used by demo scripts)
[contracts.origin]
chain_id = $ORIGIN_CHAIN_ID
rpc_url = "$ORIGIN_RPC_URL"
token = "$ORIGIN_TOKEN_ADDRESS"
input_settler = "$INPUT_SETTLER_ADDRESS"
the_compact = "$ORIGIN_COMPACT_ADDRESS"
permit2 = "$ORIGIN_PERMIT2_ADDRESS"
oracle = "$ORACLE_ADDRESS"

[contracts.destination]
chain_id = $DEST_CHAIN_ID
rpc_url = "$DEST_RPC_URL"
token = "$DEST_TOKEN_ADDRESS"
output_settler = "$OUTPUT_SETTLER_ADDRESS"
permit2 = "$DEST_PERMIT2_ADDRESS"

# Test accounts (used by demo scripts)
[accounts]
solver = "$PUBLIC_KEY"
user = "$USER_ADDR"
user_private_key = "$USER_KEY"
recipient = "$RECIPIENT_ADDR"
EOF

    cat > .env << EOF
ORIGIN_RPC_URL=$ORIGIN_RPC_URL
DEST_RPC_URL=$DEST_RPC_URL
ETH_PRIVATE_KEY=$PRIVATE_KEY
RUST_LOG=info
EOF

    echo -e "${GREEN}✅ Dual-chain configuration created${NC}"
    echo -e "   Config: config/demo.toml"
    echo -e "   Environment: .env"
}

# Function to display summary
show_summary() {
    echo -e "\n${GREEN}🎉 Dual-Chain Local Anvil Setup Complete${NC}"
    echo "=========================================="
    echo ""
    echo -e "${BLUE}🔗 Networks:${NC}"
    echo -e "   Origin Chain:      $ORIGIN_RPC_URL (Chain ID: $ORIGIN_CHAIN_ID)"
    echo -e "   Destination Chain: $DEST_RPC_URL (Chain ID: $DEST_CHAIN_ID)"
    echo ""
    echo -e "${BLUE}📋 Origin Chain Contracts:${NC}"
    echo -e "   TestToken:         $ORIGIN_TOKEN_ADDRESS"
    echo -e "   InputSettler7683:  $INPUT_SETTLER_ADDRESS"
    echo -e "   The Compact:       $ORIGIN_COMPACT_ADDRESS"
    echo -e "   Permit2:           $ORIGIN_PERMIT2_ADDRESS"
    echo -e "   AlwaysYesOracle:   $ORACLE_ADDRESS"
    echo ""
    echo -e "${BLUE}📋 Destination Chain Contracts:${NC}"
    echo -e "   TestToken:         $DEST_TOKEN_ADDRESS"
    echo -e "   OutputSettler7683: $OUTPUT_SETTLER_ADDRESS"
    echo -e "   Permit2:           $DEST_PERMIT2_ADDRESS"
    echo ""
    echo -e "${BLUE}👥 Test Accounts (on both chains):${NC}"
    echo -e "   Solver:  $PUBLIC_KEY (100 TEST + 10,000 ETH each chain)"
    echo -e "   User:    $USER_ADDR (100 TEST + 10,000 ETH each chain)"
    echo ""
    echo -e "${YELLOW}📚 Next Steps:${NC}"
    echo -e "   1. Start solver: ${BLUE}cargo run --bin solver-service -- --config config/demo.toml${NC}"
    echo -e "   2. Send (on-chain) intent:  ${BLUE}./send_onchain_intent.sh${NC} (will create cross-chain order)"
    echo -e "   3. Send (off-chain) intent:  ${BLUE}./send_offchain_intent.sh${NC} (will create cross-chain order)"
    echo ""
    echo -e "${YELLOW}🛑 To stop Anvil:${NC} kill \$(cat origin_anvil.pid) \$(cat destination_anvil.pid) or Ctrl+C"
}

# Function to cleanup
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up both chains...${NC}"
    
    # Cleanup Origin chain
    if [ -f Origin_anvil.pid ]; then
        ORIGIN_PID=$(cat Origin_anvil.pid)
        if kill -0 $ORIGIN_PID 2>/dev/null; then
            echo -e "${BLUE}🛑 Stopping Origin Anvil (PID: $ORIGIN_PID)...${NC}"
            kill $ORIGIN_PID
        fi
        rm -f Origin_anvil.pid
    fi
    
    # Cleanup Destination chain
    if [ -f Destination_anvil.pid ]; then
        DEST_PID=$(cat Destination_anvil.pid)
        if kill -0 $DEST_PID 2>/dev/null; then
            echo -e "${BLUE}🛑 Stopping Destination Anvil (PID: $DEST_PID)...${NC}"
            kill $DEST_PID
        fi
        rm -f Destination_anvil.pid
    fi
    
    # Kill any remaining anvil processes
    pkill -f "anvil.*--port.*$ORIGIN_PORT" || true
    pkill -f "anvil.*--port.*$DEST_PORT" || true
    pkill -f anvil || true
    
    echo -e "${GREEN}✅ Cleanup complete${NC}"
}

# Handle script termination
trap cleanup EXIT INT TERM

# Check if Foundry is installed
if ! command -v anvil &> /dev/null; then
    echo -e "${RED}❌ Anvil (Foundry) is not installed!${NC}"
    echo -e "${YELLOW}💡 Install with: curl -L https://foundry.paradigm.xyz | bash && foundryup${NC}"
    exit 1
fi

# Main execution
case "${1:-setup}" in
    "setup")
        start_anvil
        deploy_contracts
        setup_tokens
        create_config
        show_summary
        
        # Keep running
        echo -e "${BLUE}📡 Both Anvil chains are running. Press Ctrl+C to stop...${NC}"
        while true; do
            sleep 10
        done
        ;;
    "stop")
        cleanup
        ;;
    "status")
        origin_running=false
        dest_running=false
        
        if [ -f Origin_anvil.pid ] && kill -0 $(cat Origin_anvil.pid) 2>/dev/null; then
            echo -e "${GREEN}✅ Origin Anvil is running (PID: $(cat Origin_anvil.pid))${NC}"
            origin_running=true
        else
            echo -e "${RED}❌ Origin Anvil is not running${NC}"
        fi
        
        if [ -f Destination_anvil.pid ] && kill -0 $(cat Destination_anvil.pid) 2>/dev/null; then
            echo -e "${GREEN}✅ Destination Anvil is running (PID: $(cat Destination_anvil.pid))${NC}"
            dest_running=true
        else
            echo -e "${RED}❌ Destination Anvil is not running${NC}"
        fi
        
        if [ "$origin_running" = true ] && [ "$dest_running" = true ] && [ -f config/demo.toml ]; then
            show_summary
        fi
        ;;
    "contracts")
        if curl -s $ORIGIN_RPC_URL > /dev/null && curl -s $DEST_RPC_URL > /dev/null; then
            deploy_contracts
            setup_tokens
            create_config
            show_summary
        else
            echo -e "${RED}❌ Both Anvil chains are not running. Run './setup_local_anvil.sh' first${NC}"
        fi
        ;;
    *)
        echo "Usage: $0 [setup|stop|status|contracts]"
        echo ""
        echo "Commands:"
        echo "  setup (default) - Start dual-chain Anvil setup and deploy all contracts"
        echo "  stop            - Stop both Anvil chains and cleanup"
        echo "  status          - Check if both Anvil chains are running"
        echo "  contracts       - Only deploy contracts (if both chains are running)"
        echo ""
        echo "Dual-Chain Setup:"
        echo "  Origin Chain (port 8545):      InputSettler, Oracle, Token, TheCompact"
        echo "  Destination Chain (port 8546): OutputSettler, Token"
        exit 1
        ;;
esac