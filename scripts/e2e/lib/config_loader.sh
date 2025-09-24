#!/bin/bash
# Configuration loading and parsing functions

# Load environment variables from .env file
load_env_file() {
    local env_file="${1:-.env}"
    
    if [ ! -f "$env_file" ]; then
        echo -e "${RED}❌ Error: .env file not found${NC}"
        echo
        echo -e "${YELLOW}Please create a .env file:${NC}"
        echo "  cp .env.example .env"
        echo "  # Then edit .env with your private keys"
        return 1
    fi
    
    # Export all variables from .env file
    set -a
    source "$env_file"
    set +a
    
    echo -e "${GREEN}✓${NC} Loaded environment variables from $env_file"
    return 0
}

# Load JSON configuration file
load_json_config() {
    local config_file="${1:-scripts/e2e/testnet-config.json}"
    
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}❌ Error: Configuration file not found: $config_file${NC}"
        return 1
    fi
    
    # Validate JSON syntax
    if ! jq empty "$config_file" 2>/dev/null; then
        echo -e "${RED}❌ Error: Invalid JSON in $config_file${NC}"
        jq empty "$config_file"
        return 1
    fi
    
    # Export config file path for use in other functions
    export CONFIG_FILE="$config_file"
    
    # Display relative path if it starts with full project path
    local display_path="$config_file"
    if [[ "$config_file" == /* ]]; then
        # Get relative path from project root if possible
        local rel_path="${config_file#$PWD/}"
        if [ "$rel_path" != "$config_file" ]; then
            display_path="$rel_path"
        fi
    fi
    
    echo -e "${GREEN}✓${NC} Loaded configuration from $display_path"
    return 0
}

# Load chain data from testnet_chains.json
load_chains_config() {
    local chains_file="${1:-scripts/e2e/testnet_chains.json}"
    
    if [ ! -f "$chains_file" ]; then
        echo -e "${RED}❌ Error: Chains file not found: $chains_file${NC}"
        return 1
    fi
    
    # Validate JSON syntax
    if ! jq empty "$chains_file" 2>/dev/null; then
        echo -e "${RED}❌ Error: Invalid JSON in $chains_file${NC}"
        jq empty "$chains_file"
        return 1
    fi
    
    # Export chains file path for use in other functions
    export CHAINS_FILE="$chains_file"
    
    # Display relative path consistently
    local display_path="$chains_file"
    if [[ "$chains_file" == /* ]]; then
        # Get relative path from project root if possible
        local rel_path="${chains_file#$PWD/}"
        if [ "$rel_path" != "$chains_file" ]; then
            display_path="$rel_path"
        fi
    fi
    
    echo -e "${GREEN}✓${NC} Loaded chain data from $display_path"
    return 0
}

# Get chain data (RPC URL, USDC address, etc.)
get_chain_data() {
    local chain="$1"
    local field="$2"
    local default="${3:-}"
    
    if [ -z "$CHAINS_FILE" ]; then
        # Try to load if not already loaded
        load_chains_config >/dev/null 2>&1
    fi
    
    if [ -z "$CHAINS_FILE" ] || [ ! -f "$CHAINS_FILE" ]; then
        echo "$default"
        return 1
    fi
    
    local value=$(jq -r ".\"$chain\".$field // empty" "$CHAINS_FILE" 2>/dev/null)
    
    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "$default"
    else
        echo "$value"
    fi
}

# List all available chains
list_available_chains() {
    if [ -z "$CHAINS_FILE" ]; then
        load_chains_config >/dev/null 2>&1
    fi
    
    if [ -z "$CHAINS_FILE" ] || [ ! -f "$CHAINS_FILE" ]; then
        echo -e "${RED}Error: Chain data not loaded${NC}" >&2
        return 1
    fi
    
    jq -r 'keys[]' "$CHAINS_FILE" 2>/dev/null
}

# Get value from JSON config (with optional default)
get_config() {
    local path="$1"
    local default="${2:-}"
    
    if [ -z "$CONFIG_FILE" ]; then
        echo -e "${RED}Error: Configuration not loaded${NC}" >&2
        echo "$default"
        return 1
    fi
    
    local value=$(jq -r "$path // empty" "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "$default"
    else
        echo "$value"
    fi
}

# Get required value from JSON config (exits if not found)
get_required_config() {
    local path="$1"
    local description="${2:-configuration value}"
    
    local value=$(get_config "$path")
    
    if [ -z "$value" ]; then
        echo -e "${RED}❌ Error: Required $description not found in config${NC}" >&2
        echo "  Missing: $path" >&2
        exit 1
    fi
    
    echo "$value"
}

# Check if a feature is enabled in config
is_enabled() {
    local path="$1"
    local value=$(get_config "$path" "false")
    
    if [ "$value" = "true" ] || [ "$value" = "1" ]; then
        return 0
    else
        return 1
    fi
}

# Load addresses from config
load_addresses() {
    SOLVER_ADDRESS=$(get_config ".accounts.solver.address")
    USER_ADDRESS=$(get_config ".accounts.user.address")
    RECIPIENT_ADDRESS=$(get_config ".accounts.recipient.address" "$USER_ADDRESS")
    
    # Export for use in other scripts
    export SOLVER_ADDRESS USER_ADDRESS RECIPIENT_ADDRESS
}

# Load solver parameters from config
load_solver_params() {
    SOLVER_ID=$(get_config ".solver_parameters.id" "oif-solver-testnet")
    MIN_PROFITABILITY=$(get_config ".solver_parameters.min_profitability_pct" "1.0")
    MONITORING_TIMEOUT=$(get_config ".solver_parameters.monitoring_timeout_minutes" "5")
    MAX_GAS_PRICE=$(get_config ".solver_parameters.max_gas_price_gwei" "100")
    MIN_CONFIRMATIONS=$(get_config ".solver_parameters.min_confirmations" "3")
    
    # For display purposes only (not a solver config field)
    MIN_SOLVER_BALANCE="1"
    
    export SOLVER_ID MIN_PROFITABILITY MONITORING_TIMEOUT MAX_GAS_PRICE MIN_CONFIRMATIONS MIN_SOLVER_BALANCE
}

# Load infrastructure config
load_infrastructure() {
    PERMIT2_ADDRESS=$(get_required_config ".infrastructure.permit2_address" "Permit2 address")
    OIF_CONTRACTS_COMMIT=$(get_config ".infrastructure.oif_contracts_commit" "main")
    OIF_CONTRACTS_REPO=$(get_config ".infrastructure.oif_contracts_repo" \
        "https://github.com/openintentsframework/oif-contracts.git")
    
    export PERMIT2_ADDRESS OIF_CONTRACTS_COMMIT OIF_CONTRACTS_REPO
}

# Check if a settlement method supports given chain pair (generalized format)
is_settlement_supported() {
    local origin="$1"
    local dest="$2"
    
    # Iterate through all settlement implementations
    local num_implementations=$(get_config ".settlement.implementations | length" "0")
    
    for ((i=0; i<$num_implementations; i++)); do
        local enabled=$(get_config ".settlement.implementations[$i].enabled" "false")
        
        if [ "$enabled" != "true" ]; then
            continue
        fi
        
        # Check if both chains exist in this implementation
        local origin_chain_id=$(get_chain_data "$origin" "chain_id")
        local dest_chain_id=$(get_chain_data "$dest" "chain_id")
        
        local origin_exists=$(jq -r --arg chain_id "$origin_chain_id" \
            ".settlement.implementations[$i].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .key" \
            "$CONFIG_FILE" 2>/dev/null)
        
        local dest_exists=$(jq -r --arg chain_id "$dest_chain_id" \
            ".settlement.implementations[$i].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .key" \
            "$CONFIG_FILE" 2>/dev/null)
        
        if [ -n "$origin_exists" ] && [ -n "$dest_exists" ]; then
            # Check routes configuration
            local all_to_all=$(get_config ".settlement.implementations[$i].routes.all_to_all" "false")
            
            if [ "$all_to_all" = "true" ]; then
                return 0
            fi
            
            # Check specific pairs
            local num_pairs=$(get_config ".settlement.implementations[$i].routes.pairs | length" "0")
            for ((j=0; j<$num_pairs; j++)); do
                local pair_origin=$(get_config ".settlement.implementations[$i].routes.pairs[$j][0]")
                local pair_dest=$(get_config ".settlement.implementations[$i].routes.pairs[$j][1]")
                
                if [ "$origin" = "$pair_origin" ] && [ "$dest" = "$pair_dest" ]; then
                    return 0
                fi
            done
        fi
    done
    
    return 1
}

# Get settlement implementation for a chain pair
get_settlement_implementation() {
    local origin="$1"
    local dest="$2"
    
    # Iterate through all settlement implementations
    local num_implementations=$(get_config ".settlement.implementations | length" "0")
    
    for ((i=0; i<$num_implementations; i++)); do
        local enabled=$(get_config ".settlement.implementations[$i].enabled" "false")
        
        if [ "$enabled" != "true" ]; then
            continue
        fi
        
        local origin_chain_id=$(get_chain_data "$origin" "chain_id")
        local dest_chain_id=$(get_chain_data "$dest" "chain_id")
        
        local origin_exists=$(jq -r --arg chain_id "$origin_chain_id" \
            ".settlement.implementations[$i].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .key" \
            "$CONFIG_FILE" 2>/dev/null)
        
        local dest_exists=$(jq -r --arg chain_id "$dest_chain_id" \
            ".settlement.implementations[$i].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .key" \
            "$CONFIG_FILE" 2>/dev/null)
        
        if [ -n "$origin_exists" ] && [ -n "$dest_exists" ]; then
            # Check routes configuration
            local all_to_all=$(get_config ".settlement.implementations[$i].routes.all_to_all" "false")
            
            if [ "$all_to_all" = "true" ]; then
                echo "$i"
                return 0
            fi
            
            # Check specific pairs
            local num_pairs=$(get_config ".settlement.implementations[$i].routes.pairs | length" "0")
            for ((j=0; j<$num_pairs; j++)); do
                local pair_origin=$(get_config ".settlement.implementations[$i].routes.pairs[$j][0]")
                local pair_dest=$(get_config ".settlement.implementations[$i].routes.pairs[$j][1]")
                
                if [ "$origin" = "$pair_origin" ] && [ "$dest" = "$pair_dest" ]; then
                    echo "$i"
                    return 0
                fi
            done
        fi
    done
    
    return 1
}

# Get all enabled settlement methods for a chain pair
get_enabled_settlements() {
    local origin="$1"
    local dest="$2"
    local enabled_methods=()
    
    # Iterate through all settlement implementations
    local num_implementations=$(get_config ".settlement.implementations | length" "0")
    
    for ((i=0; i<$num_implementations; i++)); do
        local enabled=$(get_config ".settlement.implementations[$i].enabled" "false")
        local type=$(get_config ".settlement.implementations[$i].type" "unknown")
        
        if [ "$enabled" != "true" ]; then
            continue
        fi
        
        # Check if this implementation supports the chain pair
        local origin_chain_id=$(get_chain_data "$origin" "chain_id")
        local dest_chain_id=$(get_chain_data "$dest" "chain_id")
        
        local origin_exists=$(jq -r --arg chain_id "$origin_chain_id" \
            ".settlement.implementations[$i].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .key" \
            "$CONFIG_FILE" 2>/dev/null)
        
        local dest_exists=$(jq -r --arg chain_id "$dest_chain_id" \
            ".settlement.implementations[$i].chains | to_entries[] | select(.value.chain_id == (\$chain_id | tonumber)) | .key" \
            "$CONFIG_FILE" 2>/dev/null)
        
        if [ -n "$origin_exists" ] && [ -n "$dest_exists" ]; then
            # Check routes configuration
            local all_to_all=$(get_config ".settlement.implementations[$i].routes.all_to_all" "false")
            
            if [ "$all_to_all" = "true" ]; then
                enabled_methods+=("$type")
            else
                # Check specific pairs
                local num_pairs=$(get_config ".settlement.implementations[$i].routes.pairs | length" "0")
                for ((j=0; j<$num_pairs; j++)); do
                    local pair_origin=$(get_config ".settlement.implementations[$i].routes.pairs[$j][0]")
                    local pair_dest=$(get_config ".settlement.implementations[$i].routes.pairs[$j][1]")
                    
                    if [ "$origin" = "$pair_origin" ] && [ "$dest" = "$pair_dest" ]; then
                        enabled_methods+=("$type")
                        break
                    fi
                done
            fi
        fi
    done
    
    # Return as space-separated list
    echo "${enabled_methods[@]}"
}

# Get settlement configuration (generic - for new format)
get_settlement_config() {
    local impl_index="$1"
    local field="$2"
    local default="${3:-}"
    
    get_config ".settlement.implementations[$impl_index].$field" "$default"
}

# Get settlement config by type
get_settlement_config_by_type() {
    local type="$1"
    local field="$2"
    local default="${3:-}"
    
    # Find the implementation with this type
    local num_implementations=$(get_config ".settlement.implementations | length" "0")
    
    for ((i=0; i<$num_implementations; i++)); do
        local impl_type=$(get_config ".settlement.implementations[$i].type")
        if [ "$impl_type" = "$type" ]; then
            get_config ".settlement.implementations[$i].$field" "$default"
            return 0
        fi
    done
    
    echo "$default"
}