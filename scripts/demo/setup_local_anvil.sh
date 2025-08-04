#!/bin/bash

# Simple dual-chain Anvil setup script

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Chain configuration
ORIGIN_PORT=8545
DEST_PORT=8546
ORIGIN_CHAIN_ID=31337
DEST_CHAIN_ID=31338

# Account configuration
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
SOLVER_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
USER_ADDRESS="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
USER_PRIVATE_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
RECIPIENT_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

# These will be set during deployment
ORIGIN_COMPACT_ADDRESS=""
ORIGIN_PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"
DEST_PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"

echo -e "${BLUE}🔧 Simple Dual-Chain Anvil Setup${NC}"
echo "======================================"

# Step 1: Clean up
echo -e "${YELLOW}1. Cleaning up...${NC}"
pkill -9 anvil
rm -f origin_anvil.log destination_anvil.log origin.pid destination.pid
sleep 2

# Step 2: Start Anvil chains
start_anvil() {
    local name=$1
    local port=$2
    local chain_id=$3
    
    echo -e "${YELLOW}2. Starting $name chain on port $port...${NC}"
    anvil --chain-id $chain_id --port $port --block-time 2 > ${name}_anvil.log 2>&1 &
    echo $! > ${name}.pid
    sleep 3
}

start_anvil "origin" $ORIGIN_PORT $ORIGIN_CHAIN_ID
start_anvil "destination" $DEST_PORT $DEST_CHAIN_ID

# Check if both are running
if ! curl -s http://localhost:$ORIGIN_PORT > /dev/null || ! curl -s http://localhost:$DEST_PORT > /dev/null; then
    echo -e "${RED}Failed to start Anvil chains${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Both chains running${NC}"
echo

# Step 3: Deploy contracts
echo -e "${YELLOW}3. Deploying contracts...${NC}"

# Prepare contract sources
cat > /tmp/TestToken.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    string public name = "Test Token";
    string public symbol = "TEST";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
EOF

# Deploy contracts on origin chain
echo -e "${BLUE}=== Origin Chain Deployments ===${NC}"

# Deploy token
echo -n "  Deploying TestToken... "
TOKEN_OUTPUT=$(~/.foundry/bin/forge create /tmp/TestToken.sol:TestToken \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKEN_ORIGIN=$(echo "$TOKEN_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$TOKEN_ORIGIN" ]; then
    echo -e "${RED}Failed to deploy token${NC}"
    echo "Full output: $TOKEN_OUTPUT"
    exit 1
fi
echo -e "${GREEN}✓${NC} $TOKEN_ORIGIN"

# Deploy Oracle from actual contract
echo -n "  Deploying AlwaysYesOracle... "
cd oif-contracts
ORACLE_OUTPUT=$(~/.foundry/bin/forge create test/mocks/AlwaysYesOracle.sol:AlwaysYesOracle \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
ORACLE=$(echo "$ORACLE_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$ORACLE" ]; then
    echo -e "${RED}Failed to deploy oracle${NC}"
    echo "Oracle output: $ORACLE_OUTPUT"
    exit 1
fi
echo -e "${GREEN}✓${NC} $ORACLE"

# Deploy Permit2 on origin chain
deploy_permit2() {
    local chain_name=$1
    local rpc_url=$2
    local permit2_address="0x000000000022D473030F116dDEE9F6B43aC78BA3"
    
    echo -n "  Deploying Permit2 on $chain_name... "
    
    # Check if Permit2 is already deployed
    local permit2_code=$(cast code $permit2_address --rpc-url $rpc_url 2>&1)
    if [ "$permit2_code" = "0x" ] || [ -z "$permit2_code" ]; then
        # Get Permit2 bytecode from mainnet
        local mainnet_permit2_code=$(cast code $permit2_address --rpc-url https://eth.llamarpc.com 2>/dev/null | grep "^0x" | head -n1)
        
        if [ ! -z "$mainnet_permit2_code" ] && [ "$mainnet_permit2_code" != "0x" ]; then
            # Deploy using mainnet bytecode
            cast rpc anvil_setCode $permit2_address "$mainnet_permit2_code" --rpc-url $rpc_url > /dev/null 2>&1
            
            # Verify deployment
            local new_code=$(cast code $permit2_address --rpc-url $rpc_url 2>&1)
            if [ ! -z "$new_code" ] && [ "$new_code" != "0x" ]; then
                echo -e "${GREEN}✓${NC} $permit2_address"
            else
                echo -e "${RED}Failed${NC}"
                exit 1
            fi
        else
            echo -e "${RED}Failed to fetch Permit2 bytecode from mainnet${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✓${NC} $permit2_address (already deployed)"
    fi
}

# Deploy Permit2 on origin chain
deploy_permit2 "origin" "http://localhost:$ORIGIN_PORT"

# Deploy InputSettlerEscrow
echo -n "  Deploying InputSettlerEscrow... "
INPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/input/escrow/InputSettlerEscrow.sol:InputSettlerEscrow \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
INPUT_SETTLER=$(echo "$INPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$INPUT_SETTLER" ]; then
    echo -e "${RED}Failed to deploy InputSettler${NC}"
    echo "InputSettler output: $INPUT_SETTLER_OUTPUT"
    exit 1
fi
echo -e "${GREEN}✓${NC} $INPUT_SETTLER"

# Deploy OutputSettler on destination chain
echo
echo -e "${BLUE}=== Destination Chain Deployments ===${NC}"

# Deploy Permit2 on destination chain
deploy_permit2 "destination" "http://localhost:$DEST_PORT"

echo -n "  Deploying OutputSettler... "
OUTPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/output/coin/OutputSettler7683.sol:OutputInputSettlerEscrow \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
OUTPUT_SETTLER=$(echo "$OUTPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$OUTPUT_SETTLER" ]; then
    echo -e "${RED}Failed to deploy OutputSettler${NC}"
    echo "OutputSettler output: $OUTPUT_SETTLER_OUTPUT"
    exit 1
fi
echo -e "${GREEN}✓${NC} $OUTPUT_SETTLER"

cd ..

# Deploy token on destination chain
echo -n "  Deploying TestToken... "
TOKEN_DEST_OUTPUT=$(~/.foundry/bin/forge create /tmp/TestToken.sol:TestToken \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKEN_DEST=$(echo "$TOKEN_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$TOKEN_DEST" ]; then
    echo -e "${RED}Failed to deploy token on destination${NC}"
    echo "Token output: $TOKEN_DEST_OUTPUT"
    exit 1
fi
echo -e "${GREEN}✓${NC} $TOKEN_DEST"

# Step 4: Setup tokens
echo
echo -e "${YELLOW}4. Setting up tokens...${NC}"

# Mint tokens on origin chain (100 to user)
echo -n "  Minting 100 tokens to user on origin... "
cast send $TOKEN_ORIGIN "mint(address,uint256)" $USER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Mint tokens on destination chain (100 to solver)
echo -n "  Minting 100 tokens to solver on destination... "
cast send $TOKEN_DEST "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Approve OutputSettler to spend solver's tokens
echo -n "  Approving OutputSettler to spend solver's tokens... "
cast send $TOKEN_DEST "approve(address,uint256)" $OUTPUT_SETTLER 100000000000000000000 \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Approve Permit2 to spend user's tokens on origin chain
echo -n "  Approving Permit2 to spend user's tokens on origin... "
cast send $TOKEN_ORIGIN "approve(address,uint256)" $ORIGIN_PERMIT2_ADDRESS "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $USER_PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Step 5: Create config file
echo
echo -e "${YELLOW}5. Creating config file...${NC}"

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
rpc_url = "http://localhost:$ORIGIN_PORT"
private_key = "$PRIVATE_KEY"
chain_id = $ORIGIN_CHAIN_ID

[delivery.providers.destination]
rpc_url = "http://localhost:$DEST_PORT"
private_key = "$PRIVATE_KEY"
chain_id = $DEST_CHAIN_ID

[discovery]
[discovery.sources.onchain_eip7683]
rpc_url = "http://localhost:$ORIGIN_PORT"
settler_addresses = ["$INPUT_SETTLER"]

[discovery.sources.offchain_eip7683]
api_host = "127.0.0.1"
api_port = 8081
rpc_url = "http://localhost:8545"
settler_address = "$INPUT_SETTLER"
# auth_token = "your-secret-token"

[order]
[order.implementations.eip7683]
output_settler_address = "$OUTPUT_SETTLER"
input_settler_address = "$INPUT_SETTLER"
solver_address = "$SOLVER_ADDRESS"

[order.execution_strategy]
strategy_type = "simple"
[order.execution_strategy.config]
max_gas_price_gwei = 100

[settlement]
[settlement.implementations.eip7683]
rpc_url = "http://localhost:$DEST_PORT"
oracle_address = "$ORACLE"
dispute_period_seconds = 1

# API server configuration
[api]
enabled = true
host = "127.0.0.1"
port = 3000
timeout_seconds = 30
max_request_size = 1048576  # 1MB

# ============================================================================
# DEMO SCRIPT CONFIGURATION
# The following sections are used by demo scripts (send_onchain_intent.sh, etc.)
# and are NOT required by the solver itself. The solver only needs the
# configurations above.
# ============================================================================

# Contract addresses for testing (used by demo scripts)
[contracts.origin]
chain_id = $ORIGIN_CHAIN_ID
rpc_url = "http://localhost:$ORIGIN_PORT"
token = "$TOKEN_ORIGIN"
input_settler = "$INPUT_SETTLER"
the_compact = "$ORIGIN_COMPACT_ADDRESS"
permit2 = "$ORIGIN_PERMIT2_ADDRESS"
oracle = "$ORACLE"

[contracts.destination]
chain_id = $DEST_CHAIN_ID
rpc_url = "http://localhost:$DEST_PORT"
token = "$TOKEN_DEST"
output_settler = "$OUTPUT_SETTLER"
permit2 = "$DEST_PERMIT2_ADDRESS"

# Test accounts (used by demo scripts)
[accounts]
solver = "$SOLVER_ADDRESS"
user = "$USER_ADDRESS"
user_private_key = "$USER_PRIVATE_KEY"
recipient = "$RECIPIENT_ADDR"
EOF

# Done!
echo
echo -e "${GREEN}✅ Setup complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo -e "${BLUE}🔗 Networks:${NC}"
echo "  Origin:      http://localhost:$ORIGIN_PORT (chain $ORIGIN_CHAIN_ID)"
echo "  Destination: http://localhost:$DEST_PORT (chain $DEST_CHAIN_ID)"
echo
echo -e "${BLUE}📋 Contracts:${NC}"
echo "  Origin Chain:"
echo "    Token:       $TOKEN_ORIGIN"
echo "    InputSettler: $INPUT_SETTLER"
echo "    Oracle:      $ORACLE"
echo "    Permit2:     $ORIGIN_PERMIT2_ADDRESS"
echo "  Destination Chain:"
echo "    Token:       $TOKEN_DEST"
echo "    OutputSettler: $OUTPUT_SETTLER"
echo "    Permit2:     $DEST_PERMIT2_ADDRESS"
echo
echo -e "${BLUE}💰 Token Balances:${NC}"
echo "  User:   100 TEST on origin chain (Permit2 approved)"
echo "  Solver: 100 TEST on destination chain"
echo
echo -e "${BLUE}📋 Configuration:${NC}"
echo "  Config file: config/demo.toml"
echo
echo -e "${YELLOW}To start the solver:${NC}"
echo "  cargo run --bin solver-service -- --config config/demo.toml"
echo
echo -e "${YELLOW}Press Ctrl+C to stop Anvil chains${NC}"

# Keep running
while true; do
    sleep 10
done