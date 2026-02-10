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
        echo "  [DRY RUN] Would create config/testnet.json"
        echo "  [DRY RUN] Would create config/testnet/networks.json"
        echo "  [DRY RUN] Would create config/testnet/api.json"
        echo "  [DRY RUN] Would create config/testnet/gas.json"
        return 0
    fi
    
    mkdir -p "$PROJECT_ROOT/config/testnet"
    
    # Generate base config and then append enabled settlement implementations.
    generate_main_config "$origin_id" "$dest_id" "$origin_rpc" "$dest_rpc"
    append_enabled_settlements "$origin_id" "$dest_id"
    finalize_order_implementations

    # Generate section snapshots for convenience.
    generate_networks_config "$origin_id" "$dest_id" "$origin_rpc" "$dest_rpc"
    generate_api_config
    generate_gas_config
    
    echo -e "${GREEN}✅ Configuration files generated${NC}"
}

# Generate main config file
generate_main_config() {
    local origin_id="$1"
    local dest_id="$2"
    local origin_rpc="$3"
    local dest_rpc="$4"
    local solver_id=$(get_config ".solver_parameters.id" "oif-solver-testnet")
    local monitoring_timeout_minutes=$(get_config ".solver_parameters.monitoring_timeout_minutes" "5")
    local monitoring_timeout_seconds=$((monitoring_timeout_minutes * 60))
    local min_profitability_pct=$(get_config ".solver_parameters.min_profitability_pct" "1.0")
    local cleanup_interval_seconds=$(get_config ".solver_parameters.cleanup_interval_seconds" "3600")
    local min_confirmations=$(get_config ".solver_parameters.min_confirmations" "3")
    local max_gas_price_gwei=$(get_config ".solver_parameters.max_gas_price_gwei" "100")

    local storage_primary=$(get_config ".storage.primary" "file")
    local storage_path=$(get_config ".storage.file.storage_path" "./data/storage")
    local ttl_orders=$(get_config ".storage.file.ttl_orders" "0")
    local ttl_intents=$(get_config ".storage.file.ttl_intents" "86400")
    local ttl_order_by_tx_hash=$(get_config ".storage.file.ttl_order_by_tx_hash" "86400")

    local onchain_polling=$(get_config ".discovery.onchain.polling_interval_secs" "0")
    local discovery_api_host=$(get_config ".api.discovery_api.host" "127.0.0.1")
    local discovery_api_port=$(get_config ".api.discovery_api.port" "8081")

    local pricing_primary=$(get_config ".pricing.primary" "coingecko")
    local coingecko_cache=$(get_config ".pricing.coingecko.cache_duration_seconds" "60")
    local coingecko_delay=$(get_config ".pricing.coingecko.rate_limit_delay_ms" "1200")
    local coingecko_api_key_env=$(get_config ".pricing.coingecko.api_key_env" "COINGECKO_API_KEY")
    local coingecko_api_key_placeholder="\${${coingecko_api_key_env}:-}"

    local api_enabled=$(get_config ".api.solver_api.enabled" "true")
    local api_host=$(get_config ".api.solver_api.host" "127.0.0.1")
    local api_port=$(get_config ".api.solver_api.port" "3000")
    local api_timeout=$(get_config ".api.solver_api.timeout_seconds" "30")
    local api_max_request_size=$(get_config ".api.solver_api.max_request_size" "1048576")
    local auth_enabled=$(get_config ".api.auth.enabled" "false")
    local auth_access_expiry=$(get_config ".api.auth.access_token_expiry_hours" "1")
    local auth_refresh_expiry=$(get_config ".api.auth.refresh_token_expiry_hours" "720")
    local auth_issuer=$(get_config ".api.auth.issuer" "oif-solver-testnet")
    local auth_secret_env=$(get_config ".api.auth.jwt_secret_env" "JWT_SECRET")
    local auth_jwt_secret_placeholder="\${${auth_secret_env}:-DefaultSecret123}"
    local quote_validity=$(get_config ".api.quote.validity_seconds" "60")

    local origin_input_settler="${INPUT_SETTLER_ADDRESS_ORIGIN:-0x0000000000000000000000000000000000000000}"
    local origin_output_settler="${OUTPUT_SETTLER_ADDRESS_ORIGIN:-0x0000000000000000000000000000000000000000}"
    local dest_input_settler="${INPUT_SETTLER_ADDRESS_DEST:-0x0000000000000000000000000000000000000000}"
    local dest_output_settler="${OUTPUT_SETTLER_ADDRESS_DEST:-0x0000000000000000000000000000000000000000}"
    local origin_token_address=$(get_chain_data "$ORIGIN_CHAIN" "usdc_address")
    local dest_token_address=$(get_chain_data "$DEST_CHAIN" "usdc_address")

    jq -n \
        --arg solver_id "$solver_id" \
        --arg min_profitability_pct "$min_profitability_pct" \
        --argjson monitoring_timeout_seconds "$monitoring_timeout_seconds" \
        --arg storage_primary "$storage_primary" \
        --arg storage_path "$storage_path" \
        --argjson cleanup_interval_seconds "$cleanup_interval_seconds" \
        --argjson ttl_orders "$ttl_orders" \
        --argjson ttl_intents "$ttl_intents" \
        --argjson ttl_order_by_tx_hash "$ttl_order_by_tx_hash" \
        --argjson min_confirmations "$min_confirmations" \
        --argjson origin_id "$origin_id" \
        --argjson dest_id "$dest_id" \
        --arg origin_id_key "$origin_id" \
        --arg dest_id_key "$dest_id" \
        --arg origin_rpc "$origin_rpc" \
        --arg dest_rpc "$dest_rpc" \
        --arg origin_input_settler "$origin_input_settler" \
        --arg origin_output_settler "$origin_output_settler" \
        --arg dest_input_settler "$dest_input_settler" \
        --arg dest_output_settler "$dest_output_settler" \
        --arg origin_token_address "$origin_token_address" \
        --arg dest_token_address "$dest_token_address" \
        --argjson onchain_polling "$onchain_polling" \
        --arg discovery_api_host "$discovery_api_host" \
        --argjson discovery_api_port "$discovery_api_port" \
        --argjson max_gas_price_gwei "$max_gas_price_gwei" \
        --arg pricing_primary "$pricing_primary" \
        --argjson coingecko_cache "$coingecko_cache" \
        --argjson coingecko_delay "$coingecko_delay" \
        --arg coingecko_api_key "$coingecko_api_key_placeholder" \
        --argjson api_enabled "$api_enabled" \
        --arg api_host "$api_host" \
        --argjson api_port "$api_port" \
        --argjson api_timeout "$api_timeout" \
        --argjson api_max_request_size "$api_max_request_size" \
        --argjson auth_enabled "$auth_enabled" \
        --arg auth_jwt_secret "$auth_jwt_secret_placeholder" \
        --argjson auth_access_expiry "$auth_access_expiry" \
        --argjson auth_refresh_expiry "$auth_refresh_expiry" \
        --arg auth_issuer "$auth_issuer" \
        --argjson quote_validity "$quote_validity" \
        --arg solver_private_key '${SOLVER_PRIVATE_KEY}' \
        --argjson gas_resource_lock_open "$(get_config ".gas_estimates.resource_lock.open" "0")" \
        --argjson gas_resource_lock_fill "$(get_config ".gas_estimates.resource_lock.fill" "77298")" \
        --argjson gas_resource_lock_claim "$(get_config ".gas_estimates.resource_lock.claim" "122793")" \
        --argjson gas_permit2_open "$(get_config ".gas_estimates.permit2_escrow.open" "146306")" \
        --argjson gas_permit2_fill "$(get_config ".gas_estimates.permit2_escrow.fill" "77298")" \
        --argjson gas_permit2_claim "$(get_config ".gas_estimates.permit2_escrow.claim" "60084")" \
        --argjson gas_eip3009_open "$(get_config ".gas_estimates.eip3009_escrow.open" "130254")" \
        --argjson gas_eip3009_fill "$(get_config ".gas_estimates.eip3009_escrow.fill" "77298")" \
        --argjson gas_eip3009_claim "$(get_config ".gas_estimates.eip3009_escrow.claim" "60084")" \
        '{
            solver: {
                id: $solver_id,
                min_profitability_pct: $min_profitability_pct,
                monitoring_timeout_seconds: $monitoring_timeout_seconds
            },
            networks: {
                ($origin_id_key): {
                    input_settler_address: $origin_input_settler,
                    output_settler_address: $origin_output_settler,
                    rpc_urls: [{http: $origin_rpc}],
                    tokens: [{address: $origin_token_address, symbol: "USDC", decimals: 6}]
                },
                ($dest_id_key): {
                    input_settler_address: $dest_input_settler,
                    output_settler_address: $dest_output_settler,
                    rpc_urls: [{http: $dest_rpc}],
                    tokens: [{address: $dest_token_address, symbol: "USDC", decimals: 6}]
                }
            },
            storage: {
                primary: $storage_primary,
                cleanup_interval_seconds: $cleanup_interval_seconds,
                implementations: {
                    memory: {},
                    file: {
                        storage_path: $storage_path,
                        ttl_orders: $ttl_orders,
                        ttl_intents: $ttl_intents,
                        ttl_order_by_tx_hash: $ttl_order_by_tx_hash
                    }
                }
            },
            delivery: {
                min_confirmations: $min_confirmations,
                implementations: {
                    evm_alloy: {
                        network_ids: [$origin_id, $dest_id]
                    }
                }
            },
            account: {
                primary: "local",
                implementations: {
                    local: {
                        private_key: $solver_private_key
                    }
                }
            },
            discovery: {
                implementations: {
                    onchain_eip7683: {
                        network_ids: [$origin_id, $dest_id],
                        polling_interval_secs: $onchain_polling
                    },
                    offchain_eip7683: {
                        api_host: $discovery_api_host,
                        api_port: $discovery_api_port,
                        network_ids: [$origin_id, $dest_id]
                    }
                }
            },
            order: {
                implementations: {},
                strategy: {
                    primary: "simple",
                    implementations: {
                        simple: {
                            max_gas_price_gwei: $max_gas_price_gwei
                        }
                    }
                }
            },
            settlement: {
                settlement_poll_interval_seconds: 3,
                implementations: {}
            },
            pricing: {
                primary: $pricing_primary,
                implementations: {
                    coingecko: {
                        cache_duration_seconds: $coingecko_cache,
                        rate_limit_delay_ms: $coingecko_delay,
                        api_key: $coingecko_api_key
                    }
                }
            },
            api: {
                enabled: $api_enabled,
                host: $api_host,
                port: $api_port,
                timeout_seconds: $api_timeout,
                max_request_size: $api_max_request_size,
                implementations: {
                    discovery: "offchain_eip7683"
                },
                auth: {
                    enabled: $auth_enabled,
                    jwt_secret: $auth_jwt_secret,
                    access_token_expiry_hours: $auth_access_expiry,
                    refresh_token_expiry_hours: $auth_refresh_expiry,
                    issuer: $auth_issuer
                },
                quote: {
                    validity_seconds: $quote_validity
                }
            },
            gas: {
                flows: {
                    resource_lock: {
                        open: $gas_resource_lock_open,
                        fill: $gas_resource_lock_fill,
                        claim: $gas_resource_lock_claim
                    },
                    permit2_escrow: {
                        open: $gas_permit2_open,
                        fill: $gas_permit2_fill,
                        claim: $gas_permit2_claim
                    },
                    eip3009_escrow: {
                        open: $gas_eip3009_open,
                        fill: $gas_eip3009_fill,
                        claim: $gas_eip3009_claim
                    }
                }
            }
        }' > "$PROJECT_ROOT/config/testnet.json"
}

# Generate networks configuration
generate_networks_config() {
    jq '{networks: .networks}' "$PROJECT_ROOT/config/testnet.json" > "$PROJECT_ROOT/config/testnet/networks.json"
}

# Generate API configuration
generate_api_config() {
    jq '{api: .api}' "$PROJECT_ROOT/config/testnet.json" > "$PROJECT_ROOT/config/testnet/api.json"
}

# Generate gas configuration
generate_gas_config() {
    jq '{gas: .gas}' "$PROJECT_ROOT/config/testnet.json" > "$PROJECT_ROOT/config/testnet/gas.json"
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

finalize_order_implementations() {
    local impl_count
    impl_count=$(jq -r '.settlement.implementations | length' "$PROJECT_ROOT/config/testnet.json")

    if [ "$impl_count" -eq 0 ]; then
        echo -e "${RED}❌ No settlement implementations enabled for route ${ORIGIN_CHAIN} -> ${DEST_CHAIN}${NC}"
        exit 1
    fi

    local temp_file
    temp_file=$(mktemp)
    jq '
        .order.implementations = (
            .settlement.implementations
            | to_entries
            | reduce .[] as $impl ({}; .[$impl.value.order] = {})
        )
    ' "$PROJECT_ROOT/config/testnet.json" > "$temp_file"
    mv "$temp_file" "$PROJECT_ROOT/config/testnet.json"
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
            append_direct_settlement "$impl_index" "$origin_id" "$dest_id"
            ;;
        *)
            echo "    Warning: Unknown settlement type '$type', skipping..."
            ;;
    esac
}

append_direct_settlement() {
    local impl_index="$1"
    local origin_id="$2"
    local dest_id="$3"
    local order_type=$(get_config ".settlement.implementations[$impl_index].order_type" "eipXXXX")
    local dispute_period_seconds=$(get_config ".settlement.implementations[$impl_index].parameters.dispute_period_seconds" "60")
    local oracle_selection_strategy=$(get_config ".settlement.implementations[$impl_index].parameters.oracle_selection_strategy" "First")

    local origin_oracle_from_config
    local dest_oracle_from_config
    origin_oracle_from_config=$(jq -r --arg origin_chain "$ORIGIN_CHAIN" ".settlement.implementations[$impl_index].chains[\$origin_chain].oracle // \"0x0000000000000000000000000000000000000000\"" "$CONFIG_FILE")
    dest_oracle_from_config=$(jq -r --arg dest_chain "$DEST_CHAIN" ".settlement.implementations[$impl_index].chains[\$dest_chain].oracle // \"0x0000000000000000000000000000000000000000\"" "$CONFIG_FILE")

    local origin_oracle="${ORACLE_ADDRESS_ORIGIN:-$origin_oracle_from_config}"
    local dest_oracle="${ORACLE_ADDRESS_DEST:-$dest_oracle_from_config}"

    local temp_file
    temp_file=$(mktemp)
    jq \
        --arg order_type "$order_type" \
        --argjson origin_id "$origin_id" \
        --argjson dest_id "$dest_id" \
        --arg origin_oracle "$origin_oracle" \
        --arg dest_oracle "$dest_oracle" \
        --arg oracle_selection_strategy "$oracle_selection_strategy" \
        --argjson dispute_period_seconds "$dispute_period_seconds" \
        '
        .settlement.implementations.direct = {
            order: $order_type,
            network_ids: [$origin_id, $dest_id],
            dispute_period_seconds: $dispute_period_seconds,
            oracle_selection_strategy: $oracle_selection_strategy,
            oracles: {
                input: {
                    ($origin_id | tostring): [$origin_oracle],
                    ($dest_id | tostring): [$dest_oracle]
                },
                output: {
                    ($origin_id | tostring): [$origin_oracle],
                    ($dest_id | tostring): [$dest_oracle]
                }
            },
            routes: {
                ($origin_id | tostring): [$dest_id],
                ($dest_id | tostring): [$origin_id]
            }
        }
        ' "$PROJECT_ROOT/config/testnet.json" > "$temp_file"
    mv "$temp_file" "$PROJECT_ROOT/config/testnet.json"
}

# Append Hyperlane settlement configuration
append_hyperlane_settlement() {
    local impl_index="$1"
    local origin_id="$2"
    local dest_id="$3"

    local order_type=$(get_config ".settlement.implementations[$impl_index].order_type" "eip7683")
    local default_gas_limit=$(get_config ".settlement.implementations[$impl_index].parameters.default_gas_limit" "500000")
    local message_timeout_seconds=$(get_config ".settlement.implementations[$impl_index].parameters.message_timeout_seconds" "600")
    local finalization_required=$(get_config ".settlement.implementations[$impl_index].parameters.finalization_required" "true")

    local origin_oracle
    local dest_oracle
    local origin_mailbox
    local dest_mailbox
    local origin_igp
    local dest_igp
    origin_oracle=$(jq -r --arg origin_chain "$ORIGIN_CHAIN" ".settlement.implementations[$impl_index].chains[\$origin_chain].oracle // \"0x0000000000000000000000000000000000000000\"" "$CONFIG_FILE")
    dest_oracle=$(jq -r --arg dest_chain "$DEST_CHAIN" ".settlement.implementations[$impl_index].chains[\$dest_chain].oracle // \"0x0000000000000000000000000000000000000000\"" "$CONFIG_FILE")
    origin_mailbox=$(jq -r --arg origin_chain "$ORIGIN_CHAIN" ".settlement.implementations[$impl_index].chains[\$origin_chain].mailbox // \"0x0000000000000000000000000000000000000000\"" "$CONFIG_FILE")
    dest_mailbox=$(jq -r --arg dest_chain "$DEST_CHAIN" ".settlement.implementations[$impl_index].chains[\$dest_chain].mailbox // \"0x0000000000000000000000000000000000000000\"" "$CONFIG_FILE")
    origin_igp=$(jq -r --arg origin_chain "$ORIGIN_CHAIN" ".settlement.implementations[$impl_index].chains[\$origin_chain].igp // \"0x0000000000000000000000000000000000000000\"" "$CONFIG_FILE")
    dest_igp=$(jq -r --arg dest_chain "$DEST_CHAIN" ".settlement.implementations[$impl_index].chains[\$dest_chain].igp // \"0x0000000000000000000000000000000000000000\"" "$CONFIG_FILE")

    local temp_file
    temp_file=$(mktemp)
    jq \
        --arg order_type "$order_type" \
        --argjson origin_id "$origin_id" \
        --argjson dest_id "$dest_id" \
        --arg origin_oracle "$origin_oracle" \
        --arg dest_oracle "$dest_oracle" \
        --arg origin_mailbox "$origin_mailbox" \
        --arg dest_mailbox "$dest_mailbox" \
        --arg origin_igp "$origin_igp" \
        --arg dest_igp "$dest_igp" \
        --argjson default_gas_limit "$default_gas_limit" \
        --argjson message_timeout_seconds "$message_timeout_seconds" \
        --argjson finalization_required "$finalization_required" \
        '
        .settlement.implementations.hyperlane = {
            order: $order_type,
            network_ids: [$origin_id, $dest_id],
            default_gas_limit: $default_gas_limit,
            message_timeout_seconds: $message_timeout_seconds,
            finalization_required: $finalization_required,
            oracles: {
                input: {
                    ($origin_id | tostring): [$origin_oracle],
                    ($dest_id | tostring): [$dest_oracle]
                },
                output: {
                    ($origin_id | tostring): [$origin_oracle],
                    ($dest_id | tostring): [$dest_oracle]
                }
            },
            routes: {
                ($origin_id | tostring): [$dest_id],
                ($dest_id | tostring): [$origin_id]
            },
            mailboxes: {
                ($origin_id | tostring): $origin_mailbox,
                ($dest_id | tostring): $dest_mailbox
            },
            igp_addresses: {
                ($origin_id | tostring): $origin_igp,
                ($dest_id | tostring): $dest_igp
            }
        }
        ' "$PROJECT_ROOT/config/testnet.json" > "$temp_file"
    mv "$temp_file" "$PROJECT_ROOT/config/testnet.json"
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
    echo "  Main:     config/testnet.json"
    echo "  Networks: config/testnet/networks.json"
    echo "  API:      config/testnet/api.json"
    echo "  Gas:      config/testnet/gas.json"
    echo
    
    echo -e "${YELLOW}To start the solver:${NC}"
    echo "  1. Ensure environment variables are loaded:"
    echo "     source .env"
    echo "  2. Run the solver:"
    echo "     cargo run --bin solver -- --config config/testnet.json"
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
