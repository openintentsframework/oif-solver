#!/bin/bash

# OIF Solver Testnet Environment Setup Script
# ===========================================
#
# This script sets up a complete testnet testing environment for the OIF cross-chain solver.
# It performs the following operations:
#
# 1. Uses SOLVER_ADDRESS and USER_ADDRESS defined below
# 2. Deploys smart contracts on both testnets:
#    - InputSettlerEscrow on origin chain
#    - OutputSettlerSimple on destination chain
#    - Mock Oracle contract for intent validation
#
# 3. Configures the test environment for USDC transfers:
#    - Uses USDC on both chains (requires token balances)
#    - Generates modular configuration files for the solver
#
# Usage: ./setup_testnet.sh --origin <chain> --dest <chain> [options]
#   Available chains: base-sepolia, arbitrum-sepolia, optimism-sepolia, ethereum-sepolia
#   
#   Examples:
#     ./setup_testnet.sh --origin base-sepolia --dest arbitrum-sepolia
#     ./setup_testnet.sh --origin ethereum-sepolia --dest optimism-sepolia
#     ./setup_testnet.sh --help
#
# After running this script, you can:
# - Start the solver with: cargo run --bin solver -- --config config/testnet.toml
# - Send onchain test intents using: ./scripts/demo/send_onchain_intent.sh
# - Send offchain test intents using: ./scripts/demo/send_offchain_intent.sh

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
ORIGIN_CHAIN=""
DEST_CHAIN=""
CHAINS_CONFIG="$(dirname "$0")/testnet_chains.json"

# ============================================================================
# COMMAND LINE ARGUMENT PARSING
# ============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --origin)
                ORIGIN_CHAIN="$2"
                shift 2
                ;;
            --dest|--destination)
                DEST_CHAIN="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --list-chains)
                list_available_chains
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

show_help() {
    echo -e "${BLUE}OIF Solver Testnet Setup Script${NC}"
    echo "===================================="
    echo
    echo "Usage: $0 --origin <chain> --dest <chain> [options]"
    echo
    echo "Required Arguments:"
    echo "  --origin <chain>     Origin chain for cross-chain transfers"
    echo "  --dest <chain>       Destination chain for cross-chain transfers"
    echo
    echo "Options:"
    echo "  --help, -h           Show this help message"
    echo "  --list-chains        List all available testnet chains"
    echo
    echo "Examples:"
    echo "  $0 --origin base-sepolia --dest arbitrum-sepolia"
    echo "  $0 --origin ethereum-sepolia --dest optimism-sepolia"
    echo "  $0 --list-chains"
    echo
}

list_available_chains() {
    echo -e "${BLUE}Available Testnet Chains:${NC}"
    echo "========================"
    jq -r 'keys[] as $k | "\($k): \(.[$k].name) (Chain ID: \(.[$k].chain_id))"' "$CHAINS_CONFIG"
}

# ============================================================================
# CHAIN CONFIGURATION FUNCTIONS
# ============================================================================
get_chain_config() {
    local chain_name=$1
    local config_key=$2
    
    if [ ! -f "$CHAINS_CONFIG" ]; then
        echo -e "${RED}❌ Chain configuration file not found: $CHAINS_CONFIG${NC}"
        exit 1
    fi
    
    local result=$(jq -r ".\"$chain_name\".\"$config_key\" // empty" "$CHAINS_CONFIG" 2>/dev/null)
    
    if [ -z "$result" ] || [ "$result" = "null" ]; then
        echo -e "${RED}❌ Configuration not found for chain '$chain_name' key '$config_key'${NC}"
        exit 1
    fi
    
    echo "$result"
}

validate_chain_exists() {
    local chain_name=$1
    
    if ! jq -e ".\"$chain_name\"" "$CHAINS_CONFIG" >/dev/null 2>&1; then
        echo -e "${RED}❌ Unknown chain: $chain_name${NC}"
        echo "Available chains:"
        jq -r 'keys[]' "$CHAINS_CONFIG" | sed 's/^/  - /'
        exit 1
    fi
}

# ============================================================================
# ADDRESSES - PASTE YOUR ADDRESSES HERE
# ============================================================================
SOLVER_ADDRESS="0xdf2ef67c96DdC136A8447F9eca1959B85C210218"  # Your solver address here
SOLVER_PRIVATE_KEY="${SOLVER_PRIVATE_KEY}" # Set via environment variable
USER_ADDRESS="0x487C810990E17594A2Caa022a1E132c7B94F832f"    # Your user address here
USER_PRIVATE_KEY="${USER_PRIVATE_KEY}" # Set via environment variable
DEST_RECIPIENT_ADDR="0x487C810990E17594A2Caa022a1E132c7B94F832f" # address of the destination recipient where the tokens will be sent to

# Load environment variables from .env file
load_env_file() {
    local env_file=".env"
    
    if [ ! -f "$env_file" ]; then
        echo -e "${RED}❌ Error: .env file not found${NC}"
        echo
        echo -e "${YELLOW}Please create a .env file with your deployment private key:${NC}"
        echo "  DEPLOYMENT_PRIVATE_KEY=0x_your_64_character_hex_key_here"
        echo
        echo -e "${YELLOW}Get your private key from :${NC}"
        echo "  Account Details > Export Private Key"
        echo "  WARNING: Only use testnet accounts, NEVER mainnet keys!"
        exit 1
    fi
    
    # Load only DEPLOYMENT_PRIVATE_KEY from .env file
    DEPLOYMENT_PRIVATE_KEY=$(grep "^DEPLOYMENT_PRIVATE_KEY=" "$env_file" | cut -d'=' -f2- | sed 's/^["'\'']//' | sed 's/["'\'']$//')
    
    if [ -z "$DEPLOYMENT_PRIVATE_KEY" ]; then
        echo -e "${RED}❌ Error: DEPLOYMENT_PRIVATE_KEY not found in .env file${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Loaded DEPLOYMENT_PRIVATE_KEY from .env"
}

# Validate addresses
validate_addresses() {
    local errors=()
    
    # Check if SOLVER_ADDRESS is set
    if [ -z "$SOLVER_ADDRESS" ]; then
        errors+=("SOLVER_ADDRESS not set - please paste your solver address at the top of this script")
    elif [[ ! "$SOLVER_ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
        errors+=("SOLVER_ADDRESS has invalid format - should be 0x followed by 40 hex characters")
    fi
    
    # Check if USER_ADDRESS is set
    if [ -z "$USER_ADDRESS" ]; then
        errors+=("USER_ADDRESS not set - please paste your user address at the top of this script")
    elif [[ ! "$USER_ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
        errors+=("USER_ADDRESS has invalid format - should be 0x followed by 40 hex characters")
    fi
    
    if [ ${#errors[@]} -ne 0 ]; then
        echo -e "${RED}Configuration errors found:${NC}"
        for error in "${errors[@]}"; do
            echo "  ❌ $error"
        done
        echo
        echo -e "${YELLOW}Please update the addresses at the top of this script:${NC}"
        echo "  SOLVER_ADDRESS=\"0x...\""
        echo "  USER_ADDRESS=\"0x...\""
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Addresses validated"
}

# Validate configuration
validate_config() {
    local errors=()
    
    # Check if DEPLOYMENT_PRIVATE_KEY is set
    if [ -z "$DEPLOYMENT_PRIVATE_KEY" ]; then
        errors+=("DEPLOYMENT_PRIVATE_KEY not found - please add it to your .env file")
    elif [[ ! "$DEPLOYMENT_PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
        errors+=("DEPLOYMENT_PRIVATE_KEY has invalid format - should be 0x followed by 64 hex characters")
    fi
    
    if [ ${#errors[@]} -ne 0 ]; then
        echo -e "${RED}Configuration errors found:${NC}"
        for error in "${errors[@]}"; do
            echo "  ❌ $error"
        done
        echo
        echo -e "${YELLOW}Please update your .env file with the correct values.${NC}"
        exit 1
    fi
}

# Parse command line arguments
parse_args "$@"

# Validate required arguments
if [ -z "$ORIGIN_CHAIN" ] || [ -z "$DEST_CHAIN" ]; then
    echo -e "${RED}❌ Missing required arguments${NC}"
    echo "Usage: $0 --origin <chain> --dest <chain>"
    echo "Use --help for more information"
    exit 1
fi

# Validate chains exist in configuration
validate_chain_exists "$ORIGIN_CHAIN"
validate_chain_exists "$DEST_CHAIN"

# Load chain configurations
ORIGIN_CHAIN_ID=$(get_chain_config "$ORIGIN_CHAIN" "chain_id")
ORIGIN_CHAIN_NAME=$(get_chain_config "$ORIGIN_CHAIN" "name")
ORIGIN_RPC_URL=$(get_chain_config "$ORIGIN_CHAIN" "rpc_url")
ORIGIN_USDC_ADDRESS=$(get_chain_config "$ORIGIN_CHAIN" "usdc_address")
ORIGIN_EXPLORER_URL=$(get_chain_config "$ORIGIN_CHAIN" "explorer_url")
ORIGIN_BRIDGE_INFO=$(get_chain_config "$ORIGIN_CHAIN" "bridge_info")

DEST_CHAIN_ID=$(get_chain_config "$DEST_CHAIN" "chain_id")
DEST_CHAIN_NAME=$(get_chain_config "$DEST_CHAIN" "name")
DEST_RPC_URL=$(get_chain_config "$DEST_CHAIN" "rpc_url")
DEST_USDC_ADDRESS=$(get_chain_config "$DEST_CHAIN" "usdc_address")
DEST_EXPLORER_URL=$(get_chain_config "$DEST_CHAIN" "explorer_url")
DEST_BRIDGE_INFO=$(get_chain_config "$DEST_CHAIN" "bridge_info")

echo -e "${BLUE}🔧 Testnet USDC Setup ($ORIGIN_CHAIN_NAME → $DEST_CHAIN_NAME)${NC}"
echo "======================================================="

# Validate addresses first
validate_addresses

# Load environment variables from .env file
load_env_file

# Validate configuration
validate_config

# Account configuration
DEPLOYMENT_KEY="$DEPLOYMENT_PRIVATE_KEY"
DEPLOYER_ADDRESS=$(cast wallet address --private-key $DEPLOYMENT_KEY)

# USDC Token addresses
ORIGIN_TOKEN="$ORIGIN_USDC_ADDRESS"
DEST_TOKEN="$DEST_USDC_ADDRESS"

# Contract addresses
ORIGIN_COMPACT_ADDRESS=""
ORIGIN_PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"
DEST_PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"
OIF_PINNED_COMMIT="eafdaa8"  # release-v0.1-rc.0: updates for release candidate

echo
echo -e "${GREEN}✅ Configuration validated${NC}"
echo "  Origin Chain:      $ORIGIN_CHAIN_NAME (Chain ID: $ORIGIN_CHAIN_ID)"
echo "  Destination Chain: $DEST_CHAIN_NAME (Chain ID: $DEST_CHAIN_ID)"
echo "  Deployer Address:  $DEPLOYER_ADDRESS"
echo "  Solver Address:    $SOLVER_ADDRESS"
echo "  Asset:             USDC on both chains"
echo "  Origin USDC:       $ORIGIN_USDC_ADDRESS"
echo "  Destination USDC:  $DEST_USDC_ADDRESS"
echo

# Verify network connectivity
echo -e "${YELLOW}1. Verifying network connectivity...${NC}"
echo "  Debug: ORIGIN_RPC_URL = $ORIGIN_RPC_URL"
echo "  Debug: DEST_RPC_URL = $DEST_RPC_URL"
echo -n "  Testing $ORIGIN_CHAIN_NAME RPC... "

# Test if cast command exists
if ! command -v cast &> /dev/null; then
    echo -e "${RED}Failed${NC}"
    echo "Error: 'cast' command not found. Please install Foundry: https://getfoundry.sh/"
    exit 1
fi

# Test the RPC connection with more verbose output
if cast chain-id --rpc-url "$ORIGIN_RPC_URL" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}Failed${NC}"
    echo "Debug: Trying to connect to: $ORIGIN_RPC_URL"
    echo "Debug: Cast command output:"
    cast chain-id --rpc-url "$ORIGIN_RPC_URL" 2>&1 || true
    echo "Please check your $ORIGIN_CHAIN_NAME RPC URL configuration"
    exit 1
fi

echo -n "  Testing $DEST_CHAIN_NAME RPC... "
if cast chain-id --rpc-url "$DEST_RPC_URL" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}Failed${NC}"
    echo "Please check your $DEST_CHAIN_NAME RPC URL configuration"
    exit 1
fi

# Check deployer balances (ETH for gas + USDC for testing)
echo -e "${YELLOW}2. Checking deployer balances...${NC}"
DEPLOYER_ORIGIN_BALANCE=$(cast balance $DEPLOYER_ADDRESS --rpc-url "$ORIGIN_RPC_URL" --ether 2>/dev/null || echo "0")
DEPLOYER_DEST_BALANCE=$(cast balance $DEPLOYER_ADDRESS --rpc-url "$DEST_RPC_URL" --ether 2>/dev/null || echo "0")

# Check USDC balances
DEPLOYER_ORIGIN_USDC_RAW=$(cast call $ORIGIN_USDC_ADDRESS "balanceOf(address)(uint256)" $DEPLOYER_ADDRESS --rpc-url "$ORIGIN_RPC_URL" 2>/dev/null || echo "0")
DEPLOYER_ORIGIN_USDC=$(echo "scale=2; $DEPLOYER_ORIGIN_USDC_RAW / 1000000" | bc 2>/dev/null || echo "0")
DEPLOYER_DEST_USDC_RAW=$(cast call $DEST_USDC_ADDRESS "balanceOf(address)(uint256)" $DEPLOYER_ADDRESS --rpc-url "$DEST_RPC_URL" 2>/dev/null || echo "0")
DEPLOYER_DEST_USDC=$(echo "scale=2; $DEPLOYER_DEST_USDC_RAW / 1000000" | bc 2>/dev/null || echo "0")

echo "  Deployer $ORIGIN_CHAIN_NAME ETH:     ${DEPLOYER_ORIGIN_BALANCE} ETH"
echo "  Deployer $DEST_CHAIN_NAME ETH: ${DEPLOYER_DEST_BALANCE} ETH"
echo "  Deployer $ORIGIN_CHAIN_NAME USDC:    ${DEPLOYER_ORIGIN_USDC} USDC"
echo "  Deployer $DEST_CHAIN_NAME USDC: ${DEPLOYER_DEST_USDC} USDC"

# Check solver balances
echo -e "${YELLOW}3. Checking solver balances...${NC}"
SOLVER_ORIGIN_BALANCE=$(cast balance $SOLVER_ADDRESS --rpc-url "$ORIGIN_RPC_URL" --ether 2>/dev/null || echo "0")
SOLVER_DEST_BALANCE=$(cast balance $SOLVER_ADDRESS --rpc-url "$DEST_RPC_URL" --ether 2>/dev/null || echo "0")

# Check solver USDC balances
SOLVER_ORIGIN_USDC_RAW=$(cast call $ORIGIN_USDC_ADDRESS "balanceOf(address)(uint256)" $SOLVER_ADDRESS --rpc-url "$ORIGIN_RPC_URL" 2>/dev/null || echo "0")
SOLVER_ORIGIN_USDC=$(echo "scale=2; $SOLVER_ORIGIN_USDC_RAW / 1000000" | bc 2>/dev/null || echo "0")
SOLVER_DEST_USDC_RAW=$(cast call $DEST_USDC_ADDRESS "balanceOf(address)(uint256)" $SOLVER_ADDRESS --rpc-url "$DEST_RPC_URL" 2>/dev/null || echo "0")
SOLVER_DEST_USDC=$(echo "scale=2; $SOLVER_DEST_USDC_RAW / 1000000" | bc 2>/dev/null || echo "0")

echo "  Solver $ORIGIN_CHAIN_NAME ETH:       ${SOLVER_ORIGIN_BALANCE} ETH"
echo "  Solver $DEST_CHAIN_NAME ETH:   ${SOLVER_DEST_BALANCE} ETH"
echo "  Solver $ORIGIN_CHAIN_NAME USDC:      ${SOLVER_ORIGIN_USDC} USDC"
echo "  Solver $DEST_CHAIN_NAME USDC:  ${SOLVER_DEST_USDC} USDC"

# Check if solver has sufficient balances for operation
MIN_SOLVER_USDC="1"  # Reduced from 10 to 1 since we're only sending 1 USDC
if (( $(echo "$SOLVER_DEST_USDC < $MIN_SOLVER_USDC" | bc -l) )); then
    echo -e "${YELLOW}⚠️  Solver needs USDC on $DEST_CHAIN_NAME to fulfill orders!${NC}"
    echo "   Solver address: $SOLVER_ADDRESS"
    echo "   Recommended: at least $MIN_SOLVER_USDC USDC for testing"
    echo "   Send USDC to this address before starting the solver"
    echo
fi

echo -e "${GREEN}✓${NC} Sufficient deployer balances for deployment"

# Step 4: Deploy contracts
echo
echo -e "${YELLOW}4. Deploying contracts...${NC}"

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

# Deploy contracts on origin chain using deployer key
echo -e "${BLUE}=== $ORIGIN_CHAIN_NAME Deployments ===${NC}"

# Deploy Oracle from actual contract
echo -n "  Deploying AlwaysYesOracle... "
ORACLE_OUTPUT=$(~/.foundry/bin/forge create test/mocks/AlwaysYesOracle.sol:AlwaysYesOracle \
    --rpc-url "$ORIGIN_RPC_URL" \
    --private-key $DEPLOYMENT_KEY \
    --broadcast 2>&1)
ORACLE=$(echo "$ORACLE_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$ORACLE" ]; then
    echo -e "${RED}Failed to deploy oracle${NC}"
    echo "Oracle output: $ORACLE_OUTPUT"
    exit 1
fi
echo -e "${GREEN}✓${NC} $ORACLE"

# Deploy InputSettlerEscrow
echo -n "  Deploying InputSettlerEscrow... "
INPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/input/escrow/InputSettlerEscrow.sol:InputSettlerEscrow \
    --rpc-url "$ORIGIN_RPC_URL" \
    --private-key $DEPLOYMENT_KEY \
    --broadcast 2>&1)
INPUT_SETTLER=$(echo "$INPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$INPUT_SETTLER" ]; then
    echo -e "${RED}Failed to deploy InputSettler${NC}"
    echo "InputSettler output: $INPUT_SETTLER_OUTPUT"
    exit 1
fi
echo -e "${GREEN}✓${NC} $INPUT_SETTLER"

# Deploy OutputSettler on destination chain using deployer key
echo
echo -e "${BLUE}=== $DEST_CHAIN_NAME Deployments ===${NC}"

echo -n "  Deploying OutputSettler... "
OUTPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/output/simple/OutputSettlerSimple.sol:OutputSettlerSimple \
    --rpc-url "$DEST_RPC_URL" \
    --private-key $DEPLOYMENT_KEY \
    --broadcast 2>&1)
OUTPUT_SETTLER=$(echo "$OUTPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$OUTPUT_SETTLER" ]; then
    echo -e "${RED}Failed to deploy OutputSettler${NC}"
    echo "OutputSettler output: $OUTPUT_SETTLER_OUTPUT"
    exit 1
fi
echo -e "${GREEN}✓${NC} $OUTPUT_SETTLER"

cd ..

# Step 5: Create modular config files
echo
echo -e "${YELLOW}5. Creating modular config files...${NC}"

mkdir -p config/testnet

# Create main config file with includes
cat > config/testnet.toml << EOF
# OIF Solver Configuration - Testnet USDC Setup

include = [
    "testnet/networks.toml",
    "testnet/api.toml"
]

[solver]
id = "oif-solver-testnet-usdc"
monitoring_timeout_minutes = 5

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
primary = "local"

[account.implementations.local]
private_key = "$SOLVER_PRIVATE_KEY"

# ============================================================================
# DELIVERY
# ============================================================================
[delivery]
min_confirmations = 3  # Higher confirmations for testnets

[delivery.implementations.evm_alloy]
network_ids = [$ORIGIN_CHAIN_ID, $DEST_CHAIN_ID]

# ============================================================================
# DISCOVERY
# ============================================================================
[discovery]

[discovery.implementations.onchain_eip7683]
network_ids = [$ORIGIN_CHAIN_ID, $DEST_CHAIN_ID]

[discovery.implementations.offchain_eip7683]
api_host = "127.0.0.1"
api_port = 8081
network_ids = [$ORIGIN_CHAIN_ID]

# ============================================================================
# ORDER
# ============================================================================
[order]

[order.implementations.eip7683]

[order.strategy]
primary = "simple"

[order.strategy.implementations.simple]
max_gas_price_gwei = 100

# ============================================================================
# PRICING
# ============================================================================
[pricing]
primary = "coingecko"

[pricing.implementations.coingecko]
cache_duration_seconds = 60
rate_limit_delay_ms = 1200

# ============================================================================
# SETTLEMENT
# ============================================================================
[settlement]

[settlement.domain]
chain_id = 1
address = "$INPUT_SETTLER"

[settlement.implementations.direct]
order = "eipXXXX"
network_ids = [$ORIGIN_CHAIN_ID, $DEST_CHAIN_ID]
dispute_period_seconds = 60
oracle_selection_strategy = "First"

[settlement.implementations.direct.oracles]
input = { $ORIGIN_CHAIN_ID = ["$ORACLE"], $DEST_CHAIN_ID = ["$ORACLE"] }
output = { $ORIGIN_CHAIN_ID = ["$ORACLE"], $DEST_CHAIN_ID = ["$ORACLE"] }

[settlement.implementations.direct.routes]
$ORIGIN_CHAIN_ID = [$DEST_CHAIN_ID]
$DEST_CHAIN_ID = [$ORIGIN_CHAIN_ID]
EOF

cat >> config/testnet.toml << EOF

# ============================================================================
# HYPERLANE SETTLEMENT (For Holesky <-> Optimism Sepolia)
# ============================================================================
[settlement.implementations.hyperlane]
order = "eip7683"
network_ids = [17000, 11155420]
default_gas_limit = 500000
message_timeout_seconds = 600
finalization_required = true

# Oracle addresses - YOU MUST DEPLOY these HyperlaneOracle contracts
[settlement.implementations.hyperlane.oracles]
EOF

echo "input = { 17000 = [\"0x0b88D54A39F330Dd7e773af4806BDC490c79cAB6\"],  11155420 = [\"0x0b88D54A39F330Dd7e773af4806BDC490c79cAB6\"] }" >> config/testnet.toml
echo "output = { 17000 = [\"0x0b88D54A39F330Dd7e773af4806BDC490c79cAB6\"],  11155420 = [\"0x0b88D54A39F330Dd7e773af4806BDC490c79cAB6\"] }" >> config/testnet.toml

cat >> config/testnet.toml << EOF

[settlement.implementations.hyperlane.routes]
17000 = [11155420]
# 11155420 = [17000]

# Official Hyperlane Mailbox addresses
[settlement.implementations.hyperlane.mailboxes]
17000 = "0x46f7C5D896bbeC89bE1B19e4485e59b4Be49e9Cc"
11155420 = "0x6966b0E55883d49BFB24539356a2f8A673E02039"

# Official Hyperlane IGP addresses
[settlement.implementations.hyperlane.igp_addresses]
17000 = "0x5CBf4e70448Ed46c2616b04e9ebc72D29FF0cfA9"
11155420 = "0x28B02B97a850872C4D33C3E024fab6499ad96564"
EOF

cat >> config/testnet.toml << EOF

# ============================================================================
# DEMO SCRIPT CONFIGURATION
# The following sections are used by demo scripts (send_onchain_intent.sh, etc.)
# and are NOT required by the solver itself. The solver only needs the
# configurations above.
# ============================================================================

# Contract addresses for testing (used by demo scripts)
[contracts.origin]
USDC = "$ORIGIN_USDC_ADDRESS"
permit2 = "$ORIGIN_PERMIT2_ADDRESS"

[contracts.destination]
USDC = "$DEST_USDC_ADDRESS"
permit2 = "$DEST_PERMIT2_ADDRESS"

# Test accounts (used by demo scripts)
[accounts]
solver = "$SOLVER_ADDRESS"
user = "$USER_ADDRESS"
user_private_key = "$USER_PRIVATE_KEY"
recipient = "$DEST_RECIPIENT_ADDR"
EOF

# Create networks.toml
cat > config/testnet/networks.toml << EOF
# Network Configuration - Testnet Setup
# Defines all supported blockchain networks and their tokens

[networks.$ORIGIN_CHAIN_ID]
input_settler_address = "$INPUT_SETTLER"
output_settler_address = "0x0000000000000000000000000000000000000000"

# RPC endpoints with both HTTP and WebSocket URLs for each network
[[networks.$ORIGIN_CHAIN_ID.rpc_urls]]
http = "$ORIGIN_RPC_URL"

[[networks.$ORIGIN_CHAIN_ID.tokens]]
address = "$ORIGIN_USDC_ADDRESS"
symbol = "USDC"
decimals = 6

[networks.$DEST_CHAIN_ID]
input_settler_address = "0x0000000000000000000000000000000000000000"
output_settler_address = "$OUTPUT_SETTLER"

# RPC endpoints with both HTTP and WebSocket URLs for each network
[[networks.$DEST_CHAIN_ID.rpc_urls]]
http = "$DEST_RPC_URL"

[[networks.$DEST_CHAIN_ID.tokens]]
address = "$DEST_USDC_ADDRESS"
symbol = "USDC"
decimals = 6
EOF

# Create api.toml
cat > config/testnet/api.toml << EOF
# API Server Configuration - Testnet Setup
# Configures the HTTP API for receiving off-chain intents

[api]
enabled = true
host = "127.0.0.1"
port = 3000
timeout_seconds = 30
max_request_size = 1048576 # 1MB

[api.implementations]
discovery = "offchain_eip7683"

# JWT Authentication Configuration
[api.auth]
enabled = false
jwt_secret = "${JWT_SECRET:-MySuperDuperSecureSecret123!}"
access_token_expiry_hours = 1
refresh_token_expiry_hours = 720                           # 30 days
issuer = "oif-solver-testnet"

# Quote Configuration
[api.quote]
# Quote validity duration in seconds
# Default is 20 seconds. Customize as needed:
validity_seconds = 60 # 1 minute validity

EOF

# Done!
echo
echo -e "${GREEN}✅ Setup complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo -e "${BLUE}🔗 Networks:${NC}"
echo "  Origin:      $ORIGIN_CHAIN_NAME (Chain ID: $ORIGIN_CHAIN_ID)"
echo "  Destination: $DEST_CHAIN_NAME (Chain ID: $DEST_CHAIN_ID)"
echo
echo -e "${BLUE}🌐 RPC Endpoints:${NC}"
echo "  $ORIGIN_CHAIN_NAME:     $ORIGIN_RPC_URL"
echo "  $DEST_CHAIN_NAME: $DEST_RPC_URL"
echo
echo -e "${BLUE}💎 Asset:${NC}"
echo "  USDC on both chains"
echo "  Origin USDC:      $ORIGIN_USDC_ADDRESS"
echo "  Destination USDC: $DEST_USDC_ADDRESS"
echo
echo -e "${BLUE}📋 Contracts:${NC}"
echo "  $ORIGIN_CHAIN_NAME:"
echo "    InputSettler: $INPUT_SETTLER"
echo "    Oracle:       $ORACLE"
echo "    USDC Token:   $ORIGIN_USDC_ADDRESS"
echo "  $DEST_CHAIN_NAME:"
echo "    OutputSettler: $OUTPUT_SETTLER"
echo "    USDC Token:    $DEST_USDC_ADDRESS"
echo
echo -e "${BLUE}👥 Addresses:${NC}"
echo "  Deployer: $DEPLOYER_ADDRESS"
echo "  Solver (Defined):  $SOLVER_ADDRESS"
echo "  User (Defined):   $USER_ADDRESS"
echo
echo -e "${BLUE}💰 Current Balances:${NC}"
echo "  Deployer $ORIGIN_CHAIN_NAME ETH:     ${DEPLOYER_ORIGIN_BALANCE} ETH"
echo "  Deployer $DEST_CHAIN_NAME ETH: ${DEPLOYER_DEST_BALANCE} ETH"
echo "  Deployer $ORIGIN_CHAIN_NAME USDC:    ${DEPLOYER_ORIGIN_USDC} USDC"
echo "  Deployer $DEST_CHAIN_NAME USDC: ${DEPLOYER_DEST_USDC} USDC"
echo "  Solver $ORIGIN_CHAIN_NAME ETH:       ${SOLVER_ORIGIN_BALANCE} ETH"
echo "  Solver $DEST_CHAIN_NAME ETH:   ${SOLVER_DEST_BALANCE} ETH"
echo "  Solver $ORIGIN_CHAIN_NAME USDC:      ${SOLVER_ORIGIN_USDC} USDC"
echo "  Solver $DEST_CHAIN_NAME USDC:  ${SOLVER_DEST_USDC} USDC"
echo
echo -e "${BLUE}📋 Files Created:${NC}"
echo "  Main Config:    config/testnet.toml"
echo "  Networks:       config/testnet/networks.toml" 
echo "  API:            config/testnet/api.toml"
echo

echo -e "${YELLOW}To start the solver:${NC}"
echo "  cargo run --bin solver -- --config config/testnet.toml"
echo

echo -e "${BLUE}💡 Next Steps:${NC}"
echo "  1. Fund the solver address with USDC on $DEST_CHAIN_NAME:"
echo "     Address: $SOLVER_ADDRESS"
echo "     Recommended: at least $MIN_SOLVER_USDC USDC for testing"
echo "  2. Ensure you have USDC on $ORIGIN_CHAIN_NAME for test transactions (need >1 USDC)"
echo "  3. VERIFY the USDC token addresses on both chains"
echo "     Check $ORIGIN_EXPLORER_URL and $DEST_EXPLORER_URL"

# Add Hyperlane-specific instructions if applicable
if [[ "$ORIGIN_CHAIN_ID" == "17000" || "$DEST_CHAIN_ID" == "17000" || "$ORIGIN_CHAIN_ID" == "11155420" || "$DEST_CHAIN_ID" == "11155420" ]]; then
    echo
    echo -e "${YELLOW}⚠️  Hyperlane Settlement Available:${NC}"
    echo "  For Holesky <-> Optimism Sepolia routes, you can use Hyperlane cross-chain messaging!"
    echo "  To enable it, you must:"
    echo "  1. Deploy HyperlaneOracle contracts on both chains"
    echo "     Contract: oif-contracts/src/integrations/oracles/hyperlane/HyperlaneOracle.sol"
    echo "  2. Update the oracle addresses in config/testnet.toml"
    echo "     Replace 0xYourHyperlaneOracleHolesky and 0xYourHyperlaneOracleOpSepolia"
    echo "  3. Ensure solver has ETH on destination chain for IGP payments"
fi

echo "  4. Start the solver service"
echo
echo -e "${GREEN}🎉 Testnet setup completed!${NC}"