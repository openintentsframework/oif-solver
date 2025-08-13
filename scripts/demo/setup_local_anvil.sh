#!/bin/bash

# OIF Solver Demo Environment Setup Script
# =========================================
#
# This script sets up a complete local testing environment for the OIF cross-chain solver.
# It performs the following operations:
#
# 1. Starts two Anvil instances simulating different blockchain networks:
#    - Origin chain on port 8545 (chain ID: 31337)
#    - Destination chain on port 8546 (chain ID: 31338)
#
# 2. Deploys smart contracts on both chains:
#    - ERC20 test tokens for simulating asset transfers
#    - InputSettlerEscrow on the origin chain (handles deposits)
#    - OutputSettler on the destination chain (handles fills)
#    - Mock Oracle contract for intent validation
#
# 3. Configures the test environment:
#    - Funds test accounts with ETH and tokens
#    - Sets up token approvals for the settler contracts
#    - Generates configuration file (config/demo.toml) for the solver
#
# 4. Prepares the environment for testing:
#    - Creates deterministic addresses for all participants
#    - Sets up proper permissions and allowances
#    - Ensures contracts are ready to process intents
#
# After running this script, you can:
# - Start the solver with: cargo run --bin solver -- --config config/demo.toml
# - Send onchain test intents using: ./scripts/demo/send_onchain_intent.sh
# - Send offchain test intents using: ./scripts/demo/send_offchain_intent.sh
#
# NOTE: This script has been tested on macOS systems only.

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
OIF_PINNED_COMMIT="f2a9e8ab9d652894a090814421a7acb9a0547737"

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

# Define deploy_permit2 function first
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

# Prepare contract sources for TokenA and TokenB
cat > /tmp/TokenA.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TokenA {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    string public name = "Token A";
    string public symbol = "TOKA";
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

cat > /tmp/TokenB.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TokenB {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    string public name = "Token B";
    string public symbol = "TOKB";
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

# Clone or update oif-contracts (needed for contracts)
echo -e "${BLUE}=== Setting up OIF contracts ===${NC}"

# Clone or update oif-contracts to specific commit
if [ ! -d "oif-contracts" ]; then
    echo -n "  Cloning oif-contracts... "
    git clone https://github.com/openintentsframework/oif-contracts.git > /dev/null 2>&1
    echo -e "${GREEN}✓${NC}"
fi

cd oif-contracts
echo -n "  Checking out oif-contracts commit ${OIF_PINNED_COMMIT}... "
git fetch origin > /dev/null 2>&1
git checkout ${OIF_PINNED_COMMIT} > /dev/null 2>&1
echo -e "${GREEN}✓${NC}"

# Deploy contracts in the same order on both chains for deterministic addresses
echo
echo -e "${BLUE}=== Deploying Contracts ===${NC}"

# Deploy Permit2 on both chains first
deploy_permit2 "origin" "http://localhost:$ORIGIN_PORT"
deploy_permit2 "destination" "http://localhost:$DEST_PORT"

# Deploy TokenA (Contract #1 - same address on both chains)
echo -n "  Deploying TokenA on both chains... "
TOKENA_OUTPUT=$(~/.foundry/bin/forge create /tmp/TokenA.sol:TokenA \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKENA=$(echo "$TOKENA_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$TOKENA" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

TOKENA_DEST_OUTPUT=$(~/.foundry/bin/forge create /tmp/TokenA.sol:TokenA \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKENA_DEST_CHECK=$(echo "$TOKENA_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$TOKENA" != "$TOKENA_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $TOKENA"

# Deploy TokenB (Contract #2 - same address on both chains)
echo -n "  Deploying TokenB on both chains... "
TOKENB_OUTPUT=$(~/.foundry/bin/forge create /tmp/TokenB.sol:TokenB \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKENB=$(echo "$TOKENB_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$TOKENB" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

TOKENB_DEST_OUTPUT=$(~/.foundry/bin/forge create /tmp/TokenB.sol:TokenB \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKENB_DEST_CHECK=$(echo "$TOKENB_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$TOKENB" != "$TOKENB_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $TOKENB"

# Deploy InputSettlerEscrow (Contract #3 - same address on both chains)
echo -n "  Deploying InputSettlerEscrow on both chains... "
INPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/input/escrow/InputSettlerEscrow.sol:InputSettlerEscrow \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
INPUT_SETTLER=$(echo "$INPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$INPUT_SETTLER" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

INPUT_SETTLER_DEST_OUTPUT=$(~/.foundry/bin/forge create src/input/escrow/InputSettlerEscrow.sol:InputSettlerEscrow \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
INPUT_SETTLER_DEST_CHECK=$(echo "$INPUT_SETTLER_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$INPUT_SETTLER" != "$INPUT_SETTLER_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $INPUT_SETTLER"

# Deploy OutputSettler (Contract #4 - same address on both chains)
echo -n "  Deploying OutputSettler on both chains... "
OUTPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/output/coin/OutputSettler7683.sol:OutputInputSettlerEscrow \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
OUTPUT_SETTLER=$(echo "$OUTPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$OUTPUT_SETTLER" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

OUTPUT_SETTLER_DEST_OUTPUT=$(~/.foundry/bin/forge create src/output/coin/OutputSettler7683.sol:OutputInputSettlerEscrow \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
OUTPUT_SETTLER_DEST_CHECK=$(echo "$OUTPUT_SETTLER_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$OUTPUT_SETTLER" != "$OUTPUT_SETTLER_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $OUTPUT_SETTLER"

# Deploy Oracle on both chains (Contract #5 - same address on both chains)
echo -n "  Deploying AlwaysYesOracle on both chains... "
ORACLE_OUTPUT=$(~/.foundry/bin/forge create test/mocks/AlwaysYesOracle.sol:AlwaysYesOracle \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
ORACLE=$(echo "$ORACLE_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$ORACLE" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

ORACLE_DEST_OUTPUT=$(~/.foundry/bin/forge create test/mocks/AlwaysYesOracle.sol:AlwaysYesOracle \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
ORACLE_DEST_CHECK=$(echo "$ORACLE_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$ORACLE" != "$ORACLE_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $ORACLE"

cd ..

# Step 4: Setup tokens
echo
echo -e "${YELLOW}4. Setting up tokens...${NC}"

# Mint TokenA on origin chain (100 to user)
echo -n "  Minting 100 TokenA to user on origin... "
cast send $TOKENA "mint(address,uint256)" $USER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Mint TokenA on destination chain (100 to solver)
echo -n "  Minting 100 TokenA to solver on destination... "
cast send $TOKENA "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Also mint TokenA to solver on origin chain for bidirectional testing
echo -n "  Minting 100 TokenA to solver on origin... "
cast send $TOKENA "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Mint TokenB on origin chain (100 to user)
echo -n "  Minting 100 TokenB to user on origin... "
cast send $TOKENB "mint(address,uint256)" $USER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Mint TokenB on destination chain (100 to solver)
echo -n "  Minting 100 TokenB to solver on destination... "
cast send $TOKENB "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Also mint TokenB to solver on origin chain for bidirectional testing
echo -n "  Minting 100 TokenB to solver on origin... "
cast send $TOKENB "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Approve Permit2 to spend user's TokenA on origin chain
echo -n "  Approving Permit2 to spend user's TokenA on origin... "
cast send $TOKENA "approve(address,uint256)" $ORIGIN_PERMIT2_ADDRESS "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $USER_PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Approve Permit2 to spend user's TokenB on origin chain
echo -n "  Approving Permit2 to spend user's TokenB on origin... "
cast send $TOKENB "approve(address,uint256)" $ORIGIN_PERMIT2_ADDRESS "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $USER_PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Step 5: Create config file
echo
echo -e "${YELLOW}5. Creating config file...${NC}"

mkdir -p config

cat > config/demo.toml << EOF
# OIF Solver Configuration

[solver]
id = "oif-solver-demo"
monitoring_timeout_minutes = 5

# ============================================================================
# NETWORKS - Central configuration for all chains
# ============================================================================
[networks.$ORIGIN_CHAIN_ID]
rpc_url = "http://localhost:$ORIGIN_PORT"
input_settler_address = "$INPUT_SETTLER"
output_settler_address = "$OUTPUT_SETTLER"
[[networks.$ORIGIN_CHAIN_ID.tokens]]
address = "$TOKENA"
symbol = "TOKA"
decimals = 18
[[networks.$ORIGIN_CHAIN_ID.tokens]]
address = "$TOKENB"
symbol = "TOKB"
decimals = 18

[networks.$DEST_CHAIN_ID]
rpc_url = "http://localhost:$DEST_PORT"
input_settler_address = "$INPUT_SETTLER"
output_settler_address = "$OUTPUT_SETTLER"
[[networks.$DEST_CHAIN_ID.tokens]]
address = "$TOKENA"
symbol = "TOKA"
decimals = 18
[[networks.$DEST_CHAIN_ID.tokens]]
address = "$TOKENB"
symbol = "TOKB"
decimals = 18

# ============================================================================
# STORAGE
# ============================================================================
[storage]
primary = "file"
cleanup_interval_seconds = 3600

[storage.implementations.memory]
# Memory storage has no configuration

[storage.implementations.file]
storage_path = "./data/storage"
ttl_orders = 0                  # Permanent
ttl_intents = 86400             # 24 hours
ttl_order_by_tx_hash = 86400    # 24 hours

# ============================================================================
# ACCOUNT
# ============================================================================
[account]
provider = "local"
[account.config]
private_key = "\${ETH_PRIVATE_KEY:-$PRIVATE_KEY}"

# ============================================================================
# DELIVERY - References networks by ID
# ============================================================================
[delivery]
min_confirmations = 1

[delivery.providers.origin]
network_id = $ORIGIN_CHAIN_ID  # References networks.$ORIGIN_CHAIN_ID for RPC URL and chain ID
# private_key omitted - uses account.config.private_key by default

[delivery.providers.destination]
network_id = $DEST_CHAIN_ID  # References networks.$DEST_CHAIN_ID
# private_key omitted - uses account.config.private_key by default

# Example: Override for specific provider if needed
# [delivery.providers.special]
# network_id = 1
# private_key = "0x..."  # Explicit override for this provider

# ============================================================================
# DISCOVERY - References networks for chain-specific sources
# ============================================================================
[discovery]

[discovery.sources.onchain_eip7683]
network_id = $ORIGIN_CHAIN_ID  # Required: specifies which chain to monitor

[discovery.sources.offchain_eip7683]
api_host = "127.0.0.1"
api_port = 8081
network_ids = [$ORIGIN_CHAIN_ID]  # Optional: declares multi-chain support
# auth_token = "your-secret-token"

# ============================================================================
# ORDER
# ============================================================================
[order]
[order.implementations.eip7683]
# Uses networks config for all chain-specific settings

[order.execution_strategy]
strategy_type = "simple"
[order.execution_strategy.config]
max_gas_price_gwei = 100

# ============================================================================
# SETTLEMENT - References networks for chain config
# ============================================================================
[settlement]
[settlement.domain]
# Domain configuration for EIP-712 signatures in quotes
chain_id = 1  # Ethereum mainnet for signature domain
address = "$INPUT_SETTLER"

[settlement.implementations.eip7683]
network_ids = [$ORIGIN_CHAIN_ID, $DEST_CHAIN_ID]  # Monitor multiple chains for oracle verification
oracle_addresses = { $ORIGIN_CHAIN_ID = "$ORACLE", $DEST_CHAIN_ID = "$ORACLE" }
dispute_period_seconds = 1

# ============================================================================
# API SERVER
# ============================================================================
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
tokenA = "$TOKENA"
tokenB = "$TOKENB"
permit2 = "$ORIGIN_PERMIT2_ADDRESS"

[contracts.destination]
tokenA = "$TOKENA"
tokenB = "$TOKENB"
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
echo -e "${BLUE}📋 Contracts (same addresses on both chains):${NC}"
echo "  TokenA:        $TOKENA"
echo "  TokenB:        $TOKENB"
echo "  InputSettler:  $INPUT_SETTLER"
echo "  OutputSettler: $OUTPUT_SETTLER"
echo "  Oracle:        $ORACLE"
echo "  Permit2:       $ORIGIN_PERMIT2_ADDRESS"
echo
echo -e "${BLUE}💰 Token Balances:${NC}"
echo "  User:   100 TOKA and 100 TOKB on origin chain (Permit2 approved)"
echo "  Solver: 100 TOKA and 100 TOKB on both chains"
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