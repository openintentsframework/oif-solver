#!/bin/bash

# OIF Solver Testnet Setup Script (v2)
# =====================================
# Refactored version using JSON configuration and modular design
#
# Usage: ./setup_testnet.sh --origin <chain> --dest <chain> [options]
#   --origin <chain>     Origin chain for cross-chain transfers
#   --dest <chain>       Destination chain for cross-chain transfers
#   --config <file>      Custom configuration file (default: testnet-config.json)
#   --no-deploy          Skip contract deployment
#   --dry-run            Show what would be done without making changes
#   --init               Generate example configuration files
#   --help               Show this help message

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Load library functions
source "$SCRIPT_DIR/lib/config_loader.sh"
source "$SCRIPT_DIR/lib/validators.sh"
source "$SCRIPT_DIR/lib/deployers.sh"

# Default values
ORIGIN_CHAIN=""
DEST_CHAIN=""
CONFIG_FILE="$SCRIPT_DIR/testnet-config.json"
DEPLOY_CONTRACTS=true
DRY_RUN=false

# Parse command line arguments
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
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --no-deploy)
                DEPLOY_CONTRACTS=false
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --init)
                init_config_files
                exit 0
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --list-chains)
                list_available_chains_cmd
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

# Show help message
show_help() {
    echo -e "${BLUE}OIF Solver Testnet Setup Script (v2)${NC}"
    echo "====================================="
    echo
    echo "Usage: $0 --origin <chain> --dest <chain> [options]"
    echo
    echo "Required Arguments:"
    echo "  --origin <chain>     Origin chain for cross-chain transfers"
    echo "  --dest <chain>       Destination chain for cross-chain transfers"
    echo
    echo "Options:"
    echo "  --config <file>      Use custom configuration file"
    echo "  --no-deploy          Skip contract deployment"
    echo "  --dry-run            Show what would be done without making changes"
    echo "  --init               Generate example configuration files"
    echo "  --list-chains        List all available testnet chains"
    echo "  --help, -h           Show this help message"
    echo
    echo "Examples:"
    echo "  $0 --origin base-sepolia --dest arbitrum-sepolia"
    echo "  $0 --origin ethereum-holesky --dest optimism-sepolia"
    echo "  $0 --init  # Generate example config files"
    echo
    echo "Configuration:"
    echo "  1. Copy .env.example to .env and add your private keys"
    echo "  2. Edit testnet-config.json to customize settings"
    echo "  3. Run this script with your chosen chains"
}

# Initialize configuration files
init_config_files() {
    echo -e "${YELLOW}Initializing configuration files...${NC}"
    
    # Check if .env exists
    if [ ! -f "$PROJECT_ROOT/.env" ]; then
        if [ -f "$PROJECT_ROOT/.env.example" ]; then
            cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
            echo -e "${GREEN}✓${NC} Created .env from .env.example"
            echo -e "${YELLOW}  ⚠️  Please edit .env and add your private keys${NC}"
        fi
    else
        echo -e "${BLUE}ℹ${NC} .env already exists"
    fi
    
    # Check if testnet-config.json exists
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}❌ testnet-config.json not found${NC}"
        echo "  Please ensure testnet-config.json exists in $SCRIPT_DIR"
    else
        echo -e "${BLUE}ℹ${NC} testnet-config.json exists"
    fi
    
    echo
    echo -e "${GREEN}Next steps:${NC}"
    echo "  1. Edit .env and add your private keys"
    echo "  2. Review and customize testnet-config.json"
    echo "  3. Run: $0 --origin <chain> --dest <chain>"
}

# List available chains (now uses library function)
list_available_chains_cmd() {
    load_chains_config >/dev/null 2>&1
    echo -e "${BLUE}Available Testnet Chains:${NC}"
    echo "========================"
    
    local chains=$(list_available_chains)
    if [ $? -eq 0 ]; then
        for chain in $chains; do
            local name=$(get_chain_data "$chain" "name")
            local chain_id=$(get_chain_data "$chain" "chain_id")
            echo "$chain: $name (Chain ID: $chain_id)"
        done
    else
        echo -e "${RED}Could not load chain data${NC}"
    fi
}

# Prepare private keys (ensure 0x prefix for forge)
prepare_private_keys() {
    # Add 0x prefix if not present
    if [[ ! "$DEPLOYMENT_PRIVATE_KEY" =~ ^0x ]]; then
        export DEPLOYMENT_PRIVATE_KEY="0x$DEPLOYMENT_PRIVATE_KEY"
    fi
    if [[ ! "$SOLVER_PRIVATE_KEY" =~ ^0x ]]; then
        export SOLVER_PRIVATE_KEY="0x$SOLVER_PRIVATE_KEY"
    fi
    if [ -n "$USER_PRIVATE_KEY" ] && [[ ! "$USER_PRIVATE_KEY" =~ ^0x ]]; then
        export USER_PRIVATE_KEY="0x$USER_PRIVATE_KEY"
    fi
}

# Generate solver configuration files
generate_solver_configs() {
    local origin_id="$1"
    local dest_id="$2"
    local origin_rpc="$3"
    local dest_rpc="$4"
    
    echo -e "${YELLOW}Generating solver configuration files...${NC}"
    
    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would create config/testnet.toml"
        echo "  [DRY RUN] Would create config/testnet/networks.toml"
        echo "  [DRY RUN] Would create config/testnet/api.toml"
        echo "  [DRY RUN] Would create config/testnet/gas.toml"
        return 0
    fi
    
    mkdir -p "$PROJECT_ROOT/config/testnet"
    
    # Generate main config file
    generate_main_config "$origin_id" "$dest_id"
    
    # Generate networks config
    generate_networks_config "$origin_id" "$dest_id" "$origin_rpc" "$dest_rpc"
    
    # Generate API config
    generate_api_config
    
    # Generate gas config
    generate_gas_config
    
    echo -e "${GREEN}✅ Configuration files generated${NC}"
}

# Generate main config file
generate_main_config() {
    local origin_id="$1"
    local dest_id="$2"
    
    cat > "$PROJECT_ROOT/config/testnet.toml" << EOF
# OIF Solver Configuration - Generated by setup_testnet.sh
# Origin Chain ID: $origin_id
# Destination Chain ID: $dest_id

include = [
    "testnet/networks.toml",
    "testnet/api.toml",
    "testnet/gas.toml"
]

[solver]
id = "$(get_config ".solver_parameters.id" "oif-solver-testnet")"
monitoring_timeout_minutes = $(get_config ".solver_parameters.monitoring_timeout_minutes" "5")
min_profitability_pct = $(get_config ".solver_parameters.min_profitability_pct" "1.0")

# ============================================================================
# STORAGE
# ============================================================================
[storage]
primary = "$(get_config ".storage.primary" "file")"
cleanup_interval_seconds = $(get_config ".solver_parameters.cleanup_interval_seconds" "3600")

[storage.implementations.memory]
# Memory storage has no configuration

[storage.implementations.file]
storage_path = "$(get_config ".storage.file.storage_path" "./data/storage")"
ttl_orders = $(get_config ".storage.file.ttl_orders" "0")
ttl_intents = $(get_config ".storage.file.ttl_intents" "86400")
ttl_order_by_tx_hash = $(get_config ".storage.file.ttl_order_by_tx_hash" "86400")

# ============================================================================
# ACCOUNT
# ============================================================================
[account]
primary = "local"

[account.implementations.local]
private_key = "\${SOLVER_PRIVATE_KEY}"

# ============================================================================
# DELIVERY
# ============================================================================
[delivery]
min_confirmations = $(get_config ".solver_parameters.min_confirmations" "3")

[delivery.implementations.evm_alloy]
network_ids = [$origin_id, $dest_id]

# ============================================================================
# DISCOVERY
# ============================================================================
[discovery]

[discovery.implementations.onchain_eip7683]
network_ids = [$origin_id, $dest_id]
polling_interval_secs = $(get_config ".discovery.onchain.polling_interval_secs" "0")

[discovery.implementations.offchain_eip7683]
api_host = "$(get_config ".api.discovery_api.host" "127.0.0.1")"
api_port = $(get_config ".api.discovery_api.port" "8081")
network_ids = [$origin_id, $dest_id]

# ============================================================================
# ORDER
# ============================================================================
[order]

[order.implementations.eip7683]

[order.strategy]
primary = "simple"

[order.strategy.implementations.simple]
max_gas_price_gwei = $(get_config ".solver_parameters.max_gas_price_gwei" "100")

# ============================================================================
# PRICING
# ============================================================================
[pricing]
primary = "$(get_config ".pricing.primary" "coingecko")"

[pricing.implementations.coingecko]
cache_duration_seconds = $(get_config ".pricing.coingecko.cache_duration_seconds" "60")
rate_limit_delay_ms = $(get_config ".pricing.coingecko.rate_limit_delay_ms" "1200")

# ============================================================================
# SETTLEMENT
# ============================================================================
[settlement]

[settlement.domain]
chain_id = $origin_id
address = "${INPUT_SETTLER_ADDRESS_ORIGIN:-0x0000000000000000000000000000000000000000}"

[settlement.implementations.direct]
order = "$(get_config ".settlement.direct.order_type" "eipXXXX")"
network_ids = [$origin_id, $dest_id]
dispute_period_seconds = $(get_config ".settlement.direct.dispute_period_seconds" "60")
oracle_selection_strategy = "$(get_config ".settlement.direct.oracle_selection_strategy" "First")"

[settlement.implementations.direct.oracles]
input = { $origin_id = ["${ORACLE_ADDRESS_ORIGIN:-0x0}"], $dest_id = ["${ORACLE_ADDRESS_DEST:-0x0}"] }
output = { $origin_id = ["${ORACLE_ADDRESS_ORIGIN:-0x0}"], $dest_id = ["${ORACLE_ADDRESS_DEST:-0x0}"] }

[settlement.implementations.direct.routes]
# Bidirectional routes - both chains can send to each other
$origin_id = [$dest_id]
$dest_id = [$origin_id]
EOF

    # Add configurations for all enabled settlement methods
    append_enabled_settlements "$origin_id" "$dest_id"
}

# Generate networks configuration
generate_networks_config() {
    local origin_id="$1"
    local dest_id="$2"
    local origin_rpc="$3"
    local dest_rpc="$4"
    
    cat > "$PROJECT_ROOT/config/testnet/networks.toml" << EOF
# Network Configuration - Generated by setup_testnet.sh

[networks.$origin_id]
input_settler_address = "${INPUT_SETTLER_ADDRESS_ORIGIN:-0x0000000000000000000000000000000000000000}"
output_settler_address = "${OUTPUT_SETTLER_ADDRESS_ORIGIN:-0x0000000000000000000000000000000000000000}"

[[networks.$origin_id.rpc_urls]]
http = "$origin_rpc"

[[networks.$origin_id.tokens]]
address = "$(get_chain_data "$ORIGIN_CHAIN" "usdc_address")"
symbol = "USDC"
decimals = 6

[networks.$dest_id]
input_settler_address = "${INPUT_SETTLER_ADDRESS_DEST:-0x0000000000000000000000000000000000000000}"
output_settler_address = "${OUTPUT_SETTLER_ADDRESS_DEST:-0x0000000000000000000000000000000000000000}"

[[networks.$dest_id.rpc_urls]]
http = "$dest_rpc"

[[networks.$dest_id.tokens]]
address = "$(get_chain_data "$DEST_CHAIN" "usdc_address")"
symbol = "USDC"
decimals = 6
EOF
}

# Generate API configuration
generate_api_config() {
    cat > "$PROJECT_ROOT/config/testnet/api.toml" << EOF
# API Configuration - Generated by setup_testnet.sh

[api]
enabled = $(get_config ".api.solver_api.enabled" "true")
host = "$(get_config ".api.solver_api.host" "127.0.0.1")"
port = $(get_config ".api.solver_api.port" "3000")
timeout_seconds = $(get_config ".api.solver_api.timeout_seconds" "30")
max_request_size = $(get_config ".api.solver_api.max_request_size" "1048576")

[api.implementations]
discovery = "offchain_eip7683"

[api.auth]
enabled = $(get_config ".api.auth.enabled" "false")
jwt_secret = "\${JWT_SECRET:-$(get_config ".api.auth.jwt_secret_env" "DefaultSecret123")}"
access_token_expiry_hours = $(get_config ".api.auth.access_token_expiry_hours" "1")
refresh_token_expiry_hours = $(get_config ".api.auth.refresh_token_expiry_hours" "720")
issuer = "$(get_config ".api.auth.issuer" "oif-solver-testnet")"

[api.quote]
validity_seconds = $(get_config ".api.quote.validity_seconds" "60")
EOF
}

# Generate gas configuration
generate_gas_config() {
    cat > "$PROJECT_ROOT/config/testnet/gas.toml" << EOF
# Gas Configuration - Generated by setup_testnet.sh

[gas]

[gas.flows.compact_resource_lock]
open = $(get_config ".gas_estimates.compact_resource_lock.open" "0")
fill = $(get_config ".gas_estimates.compact_resource_lock.fill" "77298")
claim = $(get_config ".gas_estimates.compact_resource_lock.claim" "122793")

[gas.flows.permit2_escrow]
open = $(get_config ".gas_estimates.permit2_escrow.open" "146306")
fill = $(get_config ".gas_estimates.permit2_escrow.fill" "77298")
claim = $(get_config ".gas_estimates.permit2_escrow.claim" "60084")

[gas.flows.eip3009_escrow]
open = $(get_config ".gas_estimates.eip3009_escrow.open" "130254")
fill = $(get_config ".gas_estimates.eip3009_escrow.fill" "77298")
claim = $(get_config ".gas_estimates.eip3009_escrow.claim" "60084")
EOF
}

# Append all enabled settlement configurations
append_enabled_settlements() {
    local origin_id="$1"
    local dest_id="$2"
    
    # Iterate through all settlement implementations
    local num_implementations=$(get_config ".settlement.implementations | length" "0")
    
    for ((i=0; i<$num_implementations; i++)); do
        local enabled=$(get_config ".settlement.implementations[$i].enabled" "false")
        local type=$(get_config ".settlement.implementations[$i].type" "unknown")
        
        if [ "$enabled" != "true" ]; then
            continue
        fi
        
        # Check if this implementation supports the chain pair
        if is_route_supported "$i" "$ORIGIN_CHAIN" "$DEST_CHAIN"; then
            echo "  Adding $type settlement configuration..."
            append_settlement_config "$i" "$type" "$origin_id" "$dest_id"
        fi
    done
}

# Check if a specific implementation supports a route
is_route_supported() {
    local impl_index="$1"
    local origin="$2"
    local dest="$3"
    
    local origin_chain_id=$(get_chain_data "$origin" "chain_id")
    local dest_chain_id=$(get_chain_data "$dest" "chain_id")
    
    # Check if both chains exist in this implementation
    local origin_exists=$(jq -r --arg chain_id "$origin_chain_id" \
        ".settlement.implementations[$impl_index].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .key" \
        "$CONFIG_FILE" 2>/dev/null)
    
    local dest_exists=$(jq -r --arg chain_id "$dest_chain_id" \
        ".settlement.implementations[$impl_index].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .key" \
        "$CONFIG_FILE" 2>/dev/null)
    
    if [ -n "$origin_exists" ] && [ -n "$dest_exists" ]; then
        # Check routes configuration
        local all_to_all=$(get_config ".settlement.implementations[$impl_index].routes.all_to_all" "false")
        
        if [ "$all_to_all" = "true" ]; then
            return 0
        fi
        
        # Check specific pairs
        local num_pairs=$(get_config ".settlement.implementations[$impl_index].routes.pairs | length" "0")
        for ((j=0; j<$num_pairs; j++)); do
            local pair_origin=$(get_config ".settlement.implementations[$impl_index].routes.pairs[$j][0]")
            local pair_dest=$(get_config ".settlement.implementations[$impl_index].routes.pairs[$j][1]")
            
            if [ "$origin" = "$pair_origin" ] && [ "$dest" = "$pair_dest" ]; then
                return 0
            fi
        done
    fi
    
    return 1
}


# Append configuration for a specific settlement method
append_settlement_config() {
    local impl_index="$1"
    local type="$2"
    local origin_id="$3"
    local dest_id="$4"
    
    # Handle each settlement type
    case "$type" in
        "hyperlane")
            append_hyperlane_settlement "$impl_index" "$origin_id" "$dest_id"
            ;;
        "direct")
            # Direct settlement is already added in the base config
            echo "    Direct settlement already configured"
            ;;
        *)
            echo "    Warning: Unknown settlement type '$type', skipping..."
            ;;
    esac
}

# Append Hyperlane settlement configuration
append_hyperlane_settlement() {
    local impl_index="$1"
    local origin_id="$2"
    local dest_id="$3"
    
    # Get oracle addresses from the generalized config
    local origin_oracle=$(jq -r --arg chain_id "$origin_id" \
        ".settlement.implementations[$impl_index].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .value.oracle" \
        "$CONFIG_FILE")
    
    local dest_oracle=$(jq -r --arg chain_id "$dest_id" \
        ".settlement.implementations[$impl_index].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .value.oracle" \
        "$CONFIG_FILE")
    
    # Get Hyperlane-specific config
    local origin_mailbox=$(jq -r --arg chain_id "$origin_id" \
        ".settlement.implementations[$impl_index].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .value.mailbox" \
        "$CONFIG_FILE")
    
    local dest_mailbox=$(jq -r --arg chain_id "$dest_id" \
        ".settlement.implementations[$impl_index].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .value.mailbox" \
        "$CONFIG_FILE")
    
    local origin_igp=$(jq -r --arg chain_id "$origin_id" \
        ".settlement.implementations[$impl_index].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .value.igp" \
        "$CONFIG_FILE")
    
    local dest_igp=$(jq -r --arg chain_id "$dest_id" \
        ".settlement.implementations[$impl_index].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .value.igp" \
        "$CONFIG_FILE")
    
    cat >> "$PROJECT_ROOT/config/testnet.toml" << EOF

# ============================================================================
# HYPERLANE SETTLEMENT
# ============================================================================
[settlement.implementations.hyperlane]
order = "$(get_config ".settlement.implementations[$impl_index].order_type" "eip7683")"
network_ids = [$origin_id, $dest_id]
default_gas_limit = $(get_config ".settlement.implementations[$impl_index].parameters.default_gas_limit" "500000")
message_timeout_seconds = $(get_config ".settlement.implementations[$impl_index].parameters.message_timeout_seconds" "600")
finalization_required = $(get_config ".settlement.implementations[$impl_index].parameters.finalization_required" "true")

[settlement.implementations.hyperlane.oracles]
input = { $origin_id = ["$origin_oracle"], $dest_id = ["$dest_oracle"] }
output = { $origin_id = ["$origin_oracle"], $dest_id = ["$dest_oracle"] }

[settlement.implementations.hyperlane.routes]
# Bidirectional routes - both chains can send to each other
$origin_id = [$dest_id]
$dest_id = [$origin_id]

[settlement.implementations.hyperlane.mailboxes]
$origin_id = "$origin_mailbox"
$dest_id = "$dest_mailbox"

[settlement.implementations.hyperlane.igp_addresses]
$origin_id = "$origin_igp"
$dest_id = "$dest_igp"
EOF
}

# Show summary
show_summary() {
    local origin_id="$1"
    local dest_id="$2"
    local origin_name="$3"
    local dest_name="$4"
    
    echo
    echo -e "${GREEN}✅ Setup complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    
    echo -e "${BLUE}🔗 Networks:${NC}"
    echo "  Origin:      $origin_name (Chain ID: $origin_id)"
    echo "  Destination: $dest_name (Chain ID: $dest_id)"
    echo
    
    if [ "$DEPLOY_CONTRACTS" = true ] && [ "$DRY_RUN" = false ]; then
        echo -e "${BLUE}📋 Deployed Contracts:${NC}"
        echo "  Origin Chain:"
        echo "    Oracle:        ${ORACLE_ADDRESS_ORIGIN:-Not deployed}"
        echo "    InputSettler:  ${INPUT_SETTLER_ADDRESS_ORIGIN:-Not deployed}"
        echo "    OutputSettler: ${OUTPUT_SETTLER_ADDRESS_ORIGIN:-Not deployed}"
        echo "  Destination Chain:"
        echo "    Oracle:        ${ORACLE_ADDRESS_DEST:-Not deployed}"
        echo "    InputSettler:  ${INPUT_SETTLER_ADDRESS_DEST:-Not deployed}"
        echo "    OutputSettler: ${OUTPUT_SETTLER_ADDRESS_DEST:-Not deployed}"
        echo
    fi
    
    echo -e "${BLUE}📋 Configuration Files:${NC}"
    echo "  Main:     config/testnet.toml"
    echo "  Networks: config/testnet/networks.toml"
    echo "  API:      config/testnet/api.toml"
    echo "  Gas:      config/testnet/gas.toml"
    echo
    
    echo -e "${YELLOW}To start the solver:${NC}"
    echo "  1. Ensure environment variables are loaded:"
    echo "     source .env"
    echo "  2. Run the solver:"
    echo "     cargo run --bin solver -- --config config/testnet.toml"
    echo
    
    # Show enabled settlement methods
    local enabled_settlements=$(get_enabled_settlements "$ORIGIN_CHAIN" "$DEST_CHAIN")
    if [ -n "$enabled_settlements" ]; then
        echo -e "${BLUE}🔄 Enabled Settlement Methods:${NC}"
        for method in $enabled_settlements; do
            echo "  - $method"
        done
        echo
    fi
}

# Main function
main() {
    echo -e "${BLUE}🔧 OIF Solver Testnet Setup (v2)${NC}"
    echo "========================================"
    echo
    
    # Parse arguments
    parse_args "$@"
    
    # Validate required arguments
    if [ -z "$ORIGIN_CHAIN" ] || [ -z "$DEST_CHAIN" ]; then
        echo -e "${RED}❌ Missing required arguments${NC}"
        echo "Usage: $0 --origin <chain> --dest <chain>"
        echo "Use --help for more information"
        exit 1
    fi
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Load environment and configuration
    echo -e "${YELLOW}Loading configuration...${NC}"
    if ! load_env_file; then
        exit 1
    fi
    
    if ! load_json_config "$CONFIG_FILE"; then
        exit 1
    fi
    
    if ! load_chains_config; then
        exit 1
    fi
    
    # Load configuration values
    load_addresses
    load_solver_params
    load_infrastructure
    
    # Prepare private keys
    prepare_private_keys
    
    # Validate setup
    if ! validate_setup; then
        exit 1
    fi
    
    # Get chain configurations
    ORIGIN_CHAIN_ID=$(get_chain_data "$ORIGIN_CHAIN" "chain_id")
    ORIGIN_CHAIN_NAME=$(get_chain_data "$ORIGIN_CHAIN" "name")
    ORIGIN_RPC_URL=$(get_chain_data "$ORIGIN_CHAIN" "rpc_url")
    
    DEST_CHAIN_ID=$(get_chain_data "$DEST_CHAIN" "chain_id")
    DEST_CHAIN_NAME=$(get_chain_data "$DEST_CHAIN" "name")
    DEST_RPC_URL=$(get_chain_data "$DEST_CHAIN" "rpc_url")
    
    echo
    echo "  Origin:      $ORIGIN_CHAIN_NAME (ID: $ORIGIN_CHAIN_ID)"
    echo "  Destination: $DEST_CHAIN_NAME (ID: $DEST_CHAIN_ID)"
    echo
    
    # Validate RPC connections
    echo -e "${YELLOW}Validating network connectivity...${NC}"
    if ! validate_rpc_connection "$ORIGIN_RPC_URL" "$ORIGIN_CHAIN_NAME"; then
        exit 1
    fi
    if ! validate_rpc_connection "$DEST_RPC_URL" "$DEST_CHAIN_NAME"; then
        exit 1
    fi
    
    # Get deployer address
    DEPLOYER_ADDRESS=$(cast wallet address --private-key "$DEPLOYMENT_PRIVATE_KEY" 2>/dev/null)
    echo
    echo "  Deployer: $DEPLOYER_ADDRESS"
    echo "  Solver:   $SOLVER_ADDRESS"
    echo
    
    # Deploy contracts if enabled
    if [ "$DEPLOY_CONTRACTS" = true ]; then
        if [ "$DRY_RUN" = true ]; then
            echo -e "${YELLOW}[DRY RUN] Would deploy contracts${NC}"
        else
            if ! deploy_all_contracts "$ORIGIN_RPC_URL" "$DEST_RPC_URL" "$DEPLOYMENT_PRIVATE_KEY"; then
                echo -e "${RED}Contract deployment failed${NC}"
                exit 1
            fi
        fi
    else
        echo -e "${YELLOW}Skipping contract deployment (--no-deploy)${NC}"
    fi
    
    # Generate configuration files
    generate_solver_configs "$ORIGIN_CHAIN_ID" "$DEST_CHAIN_ID" "$ORIGIN_RPC_URL" "$DEST_RPC_URL"
    
    # Show summary
    show_summary "$ORIGIN_CHAIN_ID" "$DEST_CHAIN_ID" "$ORIGIN_CHAIN_NAME" "$DEST_CHAIN_NAME"
}

# Run main function
main "$@"