#!/usr/bin/env bash
#
# ==============================================================================
# Configuration Module - TOML Config Management
# ==============================================================================
#
# This module manages configuration loading, validation, and access for the
# OIF demo environment. It handles TOML parsing, network configurations,
# account management, and token mappings.
#
# Key Features:
# - TOML configuration parsing and validation
# - Network and chain configuration management  
# - Account and key management
# - Token registry and lookups
# - Configuration export for child processes
#
# Configuration Structure:
# - Networks: Chain IDs, RPC URLs, settler addresses
# - Accounts: Private keys and addresses
# - Tokens: Token addresses and symbols per network
# - API: Solver API endpoints
#
# ==============================================================================

# Configuration module - manages TOML configuration dynamically

# Global associative arrays for config storage
declare -gA CONFIG_MAIN
declare -gA CONFIG_NETWORKS
declare -gA CONFIG_TOKENS
declare -gA CONFIG_CONTRACTS
declare -gA CONFIG_ACCOUNTS
declare -gA CONFIG_COMPACT
declare -gA CONFIG_API
declare -gA CONFIG_GAS

# Array to store discovered chain IDs
declare -ga CHAIN_IDS=()

# Configuration file paths
CONFIG_DIR="${SCRIPT_DIR}/config"
CONFIG_FILE=""
CONFIG_LOADED=false

# Check if configuration is loaded
config_is_loaded() {
    [ "$CONFIG_LOADED" = true ]
}

# Parse TOML value (simplified parser)
parse_toml_value() {
    local file="$1"
    local section="$2"
    local key="$3"
    
    # Use grep and sed to extract value
    grep -A 100 "^\[$section\]" "$file" 2>/dev/null | \
        grep "^$key" | \
        head -n 1 | \
        sed 's/.*= *//' | \
        sed 's/"//g' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Parse TOML array
parse_toml_array() {
    local file="$1"
    local section="$2"
    local key="$3"
    
    # Handle multi-line arrays
    awk "/^${key} = \[/,/\]/" "$file" | \
        grep -v "^${key}" | \
        grep -v "^\]" | \
        sed 's/^[[:space:]]*"//g' | \
        sed 's/"[[:space:]]*,*[[:space:]]*$//g' | \
        grep -v '^$'
}

# Get all network sections from TOML
get_network_sections() {
    local file="$1"
    # Match [networks.XXXXX] where XXXXX is the chain ID
    grep '^\[networks\.' "$file" | sed 's/\[networks\.\([^]]*\)\]/\1/' | sort -u
}

# Load configuration from TOML files
config_load() {
    local config_file="${1:-${CONFIG_DIR}/demo.toml}"
    
    if [ ! -f "$config_file" ]; then
        print_error "Configuration file not found: $config_file"
        return 1
    fi
    
    CONFIG_FILE="$config_file"
    print_debug "Loading configuration from: $config_file"
    
    # Load main config values
    CONFIG_MAIN[solver_id]=$(parse_toml_value "$config_file" "solver" "id")
    CONFIG_MAIN[monitoring_timeout]=$(parse_toml_value "$config_file" "solver" "monitoring_timeout_minutes")
    CONFIG_MAIN[storage_primary]=$(parse_toml_value "$config_file" "storage" "primary")
    CONFIG_MAIN[storage_path]=$(parse_toml_value "$config_file" "storage.implementations.file" "storage_path")
    
    # Process includes
    local includes=$(parse_toml_array "$config_file" "" "include")
    local config_dir=$(dirname "$config_file")
    
    for include in $includes; do
        local include_file="${config_dir}/${include}"
        if [ -f "$include_file" ]; then
            print_debug "Processing include: $include_file"
            config_load_include "$include_file"
        else
            print_warning "Include file not found: $include_file"
        fi
    done
    
    # Load environment variables if present
    config_load_env
    
    CONFIG_LOADED=true
    
    # Validate configuration
    if ! config_validate; then
        CONFIG_LOADED=false
        return 1
    fi
    
    return 0
}

# Load included configuration files
config_load_include() {
    local include_file="$1"
    local filename=$(basename "$include_file")
    
    case "$filename" in
        networks.toml)
            config_load_networks "$include_file"
            ;;
        api.toml)
            config_load_api "$include_file"
            ;;
        contracts.toml)
            config_load_contracts "$include_file"
            ;;
        cli.toml)
            config_load_accounts "$include_file"
            ;;
        gas.toml)
            config_load_gas "$include_file"
            ;;
        *)
            print_warning "Unknown include file: $filename"
            ;;
    esac
}

# Dynamically load network configuration
config_load_networks() {
    local file="$1"
    
    # Discover all chain IDs in the config
    CHAIN_IDS=($(get_network_sections "$file"))
    
    if [ ${#CHAIN_IDS[@]} -eq 0 ]; then
        print_error "No networks found in $file"
        return 1
    fi
    
    print_debug "Found chains: ${CHAIN_IDS[*]}"
    
    # Load each network's configuration
    for chain_id in "${CHAIN_IDS[@]}"; do
        local section="networks.$chain_id"
        
        # Load RPC URLs
        local rpc_http=$(grep -A2 "\[\[$section.rpc_urls\]\]" "$file" | grep "http =" | head -n1 | sed 's/.*= *//' | tr -d '"')
        local rpc_ws=$(grep -A2 "\[\[$section.rpc_urls\]\]" "$file" | grep "ws =" | head -n1 | sed 's/.*= *//' | tr -d '"')
        
        CONFIG_NETWORKS[${chain_id}_rpc_url]="${rpc_http:-http://localhost:8545}"
        CONFIG_NETWORKS[${chain_id}_ws_url]="${rpc_ws:-ws://localhost:8545}"
        
        # Load contract addresses dynamically
        local contracts=(
            "input_settler_address"
            "input_settler_compact_address"
            "the_compact_address"
            "allocator_address"
            "output_settler_address"
            "input_oracle_address"
            "output_oracle_address"
        )
        
        for contract in "${contracts[@]}"; do
            local value=$(parse_toml_value "$file" "$section" "$contract")
            if [ -n "$value" ]; then
                CONFIG_NETWORKS[${chain_id}_${contract}]="$value"
            fi
        done
        
        # Load tokens dynamically
        local token_count=0
        local token_sections=$(grep -c "\[\[$section.tokens\]\]" "$file" 2>/dev/null || echo 0)
        
        if [ "$token_sections" -gt 0 ]; then
            local token_addresses=($(grep -A1 "\[\[$section.tokens\]\]" "$file" | grep "address =" | sed 's/.*= *//' | tr -d '"'))
            local token_symbols=($(grep -A2 "\[\[$section.tokens\]\]" "$file" | grep "symbol =" | sed 's/.*= *//' | tr -d '"'))
            local token_decimals=($(grep -A3 "\[\[$section.tokens\]\]" "$file" | grep "decimals =" | sed 's/.*= *//' | tr -d '"'))
            
            for i in "${!token_addresses[@]}"; do
                CONFIG_TOKENS[${chain_id}_token_${i}_address]="${token_addresses[$i]}"
                CONFIG_TOKENS[${chain_id}_token_${i}_symbol]="${token_symbols[$i]:-TOKEN$i}"
                CONFIG_TOKENS[${chain_id}_token_${i}_decimals]="${token_decimals[$i]:-18}"
                token_count=$((token_count + 1))
            done
        fi
        
        CONFIG_NETWORKS[${chain_id}_token_count]="$token_count"
        
        print_debug "Loaded chain $chain_id with $token_count tokens"
    done
}

# Load API configuration
config_load_api() {
    local file="$1"
    
    CONFIG_API[host]=$(parse_toml_value "$file" "api" "host")
    CONFIG_API[port]=$(parse_toml_value "$file" "api" "port")
    
    if [ -n "${CONFIG_API[host]}" ] && [ -n "${CONFIG_API[port]}" ]; then
        CONFIG_API[url]="http://${CONFIG_API[host]}:${CONFIG_API[port]}"
    fi
}

# Load CLI configuration (accounts and compact settings)
config_load_accounts() {
    local file="$1"
    
    # Load all account-related keys from cli.toml
    CONFIG_ACCOUNTS[user_address]=$(parse_toml_value "$file" "accounts" "user_address")
    CONFIG_ACCOUNTS[user_private_key]=$(parse_toml_value "$file" "accounts" "user_private_key")
    CONFIG_ACCOUNTS[solver_address]=$(parse_toml_value "$file" "accounts" "solver_address")
    CONFIG_ACCOUNTS[recipient_address]=$(parse_toml_value "$file" "accounts" "recipient_address")
    
    # Get solver private key from the main config's account.implementations.local section
    if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        local solver_private_key=$(parse_toml_value "$CONFIG_FILE" "account.implementations.local" "private_key")
        # Handle environment variable substitution
        if [[ "$solver_private_key" =~ \$\{([^}]+)\} ]]; then
            local env_expr="${BASH_REMATCH[1]}"
            if [[ "$env_expr" =~ ^([^:]+):-(.*) ]]; then
                local env_var="${BASH_REMATCH[1]}"
                local default_val="${BASH_REMATCH[2]}"
                solver_private_key="${!env_var:-$default_val}"
            else
                solver_private_key="${!env_expr:-}"
            fi
        fi
        CONFIG_ACCOUNTS[solver_private_key]="$solver_private_key"
    fi
}

# Load gas configuration
config_load_gas() {
    local file="$1"
    
    # Gas config is primarily for reference/documentation
    # Store values if needed for display purposes
    CONFIG_GAS["permit2_open"]=$(parse_toml_value "$file" "gas.flows.permit2_escrow" "open")
    CONFIG_GAS["permit2_fill"]=$(parse_toml_value "$file" "gas.flows.permit2_escrow" "fill")
    CONFIG_GAS["permit2_claim"]=$(parse_toml_value "$file" "gas.flows.permit2_escrow" "claim")
    CONFIG_GAS["compact_open"]=$(parse_toml_value "$file" "gas.flows.compact_resource_lock" "open")
    CONFIG_GAS["compact_fill"]=$(parse_toml_value "$file" "gas.flows.compact_resource_lock" "fill")
    CONFIG_GAS["compact_claim"]=$(parse_toml_value "$file" "gas.flows.compact_resource_lock" "claim")
    
    print_debug "Loaded gas configuration from $file"
}

# Load environment variables
config_load_env() {
    # Override with environment variables if set
    [ -n "${USER_ADDRESS:-}" ] && CONFIG_ACCOUNTS[user_address]="$USER_ADDRESS"
    [ -n "${USER_PRIVATE_KEY:-}" ] && CONFIG_ACCOUNTS[user_private_key]="$USER_PRIVATE_KEY"
    [ -n "${SOLVER_ADDRESS:-}" ] && CONFIG_ACCOUNTS[solver_address]="$SOLVER_ADDRESS"
    [ -n "${SOLVER_PRIVATE_KEY:-}" ] && CONFIG_ACCOUNTS[solver_private_key]="$SOLVER_PRIVATE_KEY"
    [ -n "${RECIPIENT_ADDRESS:-}" ] && CONFIG_ACCOUNTS[recipient_address]="$RECIPIENT_ADDRESS"
    [ -n "${ETH_PRIVATE_KEY:-}" ] && CONFIG_ACCOUNTS[solver_private_key]="$ETH_PRIVATE_KEY"
}

# Get specific config value
config_get() {
    local section="$1"
    local key="$2"
    local default="${3:-}"
    
    if [ ! "$CONFIG_LOADED" = true ]; then
        config_load
    fi
    
    local full_key="${section}_${key}"
    
    case "$section" in
        main|solver|storage)
            echo "${CONFIG_MAIN[$full_key]:-$default}"
            ;;
        network|networks)
            echo "${CONFIG_NETWORKS[$full_key]:-$default}"
            ;;
        api)
            echo "${CONFIG_API[$key]:-$default}"
            ;;
        account|accounts)
            echo "${CONFIG_ACCOUNTS[$key]:-$default}"
            ;;
        *)
            echo "$default"
            ;;
    esac
}

# Get network-specific config
config_get_network() {
    local chain_id="$1"
    local property="$2"
    local default="${3:-}"
    
    # Don't try to auto-load config to avoid infinite loops
    if [ ! "$CONFIG_LOADED" = true ]; then
        echo "$default"
        return 1
    fi
    
    local key="${chain_id}_${property}"
    echo "${CONFIG_NETWORKS[$key]:-$default}"
}

# Get all configured network IDs
config_get_network_ids() {
    echo "${CHAIN_IDS[@]}"
}

# Get token information
config_get_token() {
    local chain_id="$1"
    local token_index="$2"
    local property="${3:-address}"
    
    if [ ! "$CONFIG_LOADED" = true ]; then
        config_load
    fi
    
    local key="${chain_id}_token_${token_index}_${property}"
    echo "${CONFIG_TOKENS[$key]:-}"
}

# Get token by symbol
config_get_token_by_symbol() {
    local chain_id="$1"
    local symbol="$2"
    local property="${3:-address}"
    
    local token_count=$(config_get_network "$chain_id" "token_count" 0)
    
    for ((i=0; i<token_count; i++)); do
        local token_symbol="${CONFIG_TOKENS[${chain_id}_token_${i}_symbol]:-}"
        if [ "$token_symbol" = "$symbol" ]; then
            echo "${CONFIG_TOKENS[${chain_id}_token_${i}_${property}]:-}"
            return 0
        fi
    done
    
    return 1
}

# Get account information
config_get_account() {
    local account_type="$1"
    local property="${2:-address}"
    
    # Don't try to auto-load config to avoid infinite loops
    if [ ! "$CONFIG_LOADED" = true ]; then
        return 1
    fi
    
    local key="${account_type}_${property}"
    echo "${CONFIG_ACCOUNTS[$key]:-}"
}

# Get list of configured chains
config_get_chains() {
    # Don't try to auto-load config to avoid infinite loops
    if [ ! "$CONFIG_LOADED" = true ]; then
        return 1
    fi
    
    echo "${CHAIN_IDS[@]}"
}

# Get list of tokens for a chain
config_get_tokens() {
    local chain_id="$1"
    local token_count=$(config_get_network "$chain_id" "token_count" 0)
    
    for ((i=0; i<token_count; i++)); do
        echo "${CONFIG_TOKENS[${chain_id}_token_${i}_address]:-}"
    done
}

# Get oracle address from settlement configuration
config_get_compact() {
    local property="$1"
    
    if [ ! "$CONFIG_LOADED" = true ]; then
        return 1
    fi
    
    echo "${CONFIG_COMPACT[$property]:-}"
}

config_get_oracle() {
    local chain_id="$1"
    local oracle_type="${2:-input}"  # input or output
    
    if [ ! "$CONFIG_LOADED" = true ]; then
        return 1
    fi
    
    # Parse the oracle configuration from the main config file
    # Format: input = { 31337 = ["0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"], ... }
    if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        local oracle_line=$(grep -A10 "\\[settlement.implementations.direct.oracles\\]" "$CONFIG_FILE" | \
                           grep "^${oracle_type} = " | head -n1)
        
        if [ -n "$oracle_line" ]; then
            # Extract the first oracle address for the specified chain
            # This is a simplified parser - assumes format: chain = ["address"]
            echo "$oracle_line" | sed -n "s/.*${chain_id} = \\[\"\\([^\"]*\\)\".*/\\1/p"
        fi
    fi
}

# Get origin and destination chains
config_get_origin_chain() {
    # Return first chain as origin by convention
    echo "${CHAIN_IDS[0]:-}"
}

config_get_destination_chain() {
    # Return second chain as destination by convention
    echo "${CHAIN_IDS[1]:-}"
}

# Validate configuration
config_validate() {
    local valid=true
    
    # Check required main config
    if [ -z "${CONFIG_MAIN[solver_id]:-}" ]; then
        print_error "Missing required config: solver.id"
        valid=false
    fi
    
    # Check that we have at least one network
    if [ ${#CHAIN_IDS[@]} -eq 0 ]; then
        print_error "No networks configured"
        valid=false
    fi
    
    # Check each configured network
    for chain_id in "${CHAIN_IDS[@]}"; do
        local rpc_url="${CONFIG_NETWORKS[${chain_id}_rpc_url]:-}"
        if [ -z "$rpc_url" ]; then
            print_error "Missing RPC URL for chain $chain_id"
            valid=false
        fi
        
        # Check for at least one settler contract
        local has_settler=false
        for settler in input_settler_address output_settler_address input_settler_compact_address; do
            if [ -n "${CONFIG_NETWORKS[${chain_id}_${settler}]:-}" ]; then
                has_settler=true
                break
            fi
        done
        
        if [ "$has_settler" = false ]; then
            print_warning "No settler contracts configured for chain $chain_id"
        fi
        
        # Check for tokens
        local token_count="${CONFIG_NETWORKS[${chain_id}_token_count]:-0}"
        if [ "$token_count" -eq 0 ]; then
            print_warning "No tokens configured for chain $chain_id"
        fi
    done
    
    # Check API config
    if [ -z "${CONFIG_API[host]:-}" ] || [ -z "${CONFIG_API[port]:-}" ]; then
        print_error "Missing API configuration (host/port)"
        valid=false
    fi
    
    # Check for at least basic accounts from env if not in config
    if [ -z "${CONFIG_ACCOUNTS[user_address]:-}" ] && [ -z "${USER_ADDRESS:-}" ]; then
        print_warning "No user account configured (set USER_ADDRESS env var)"
    fi
    
    if [ -z "${CONFIG_ACCOUNTS[solver_address]:-}" ] && [ -z "${SOLVER_ADDRESS:-}" ]; then
        print_warning "No solver account configured (set SOLVER_ADDRESS env var)"
    fi
    
    if [ "$valid" = false ]; then
        print_error "Configuration validation failed. Please check your config files."
        return 1
    fi
    
    return 0
}

# Show configuration summary
config_show_summary() {
    print_header "Configuration Summary"
    
    echo "Solver ID: ${CONFIG_MAIN[solver_id]:-N/A}"
    echo ""
    
    echo "Networks:"
    for chain_id in "${CHAIN_IDS[@]}"; do
        echo "  Chain $chain_id:"
        echo "    RPC: $(config_get_network $chain_id rpc_url)"
        
        # Show configured contracts
        for contract in input_settler_address input_settler_compact_address output_settler_address the_compact_address; do
            local addr=$(config_get_network $chain_id $contract)
            if [ -n "$addr" ]; then
                local name=$(echo $contract | sed 's/_address$//' | sed 's/_/ /g')
                echo "    ${name^}: $addr"
            fi
        done
        
        # Show tokens
        local token_count=$(config_get_network $chain_id token_count 0)
        if [ "$token_count" -gt 0 ]; then
            echo "    Tokens:"
            for ((i=0; i<token_count; i++)); do
                local symbol="${CONFIG_TOKENS[${chain_id}_token_${i}_symbol]:-}"
                local addr="${CONFIG_TOKENS[${chain_id}_token_${i}_address]:-}"
                echo "      $symbol: $addr"
            done
        fi
        echo ""
    done
    
    echo "Accounts:"
    # Show all configured accounts
    local account_names=($(echo "${!CONFIG_ACCOUNTS[@]}" | tr ' ' '\n' | sed 's/_address$//' | sed 's/_private_key$//' | sort -u))
    for account in "${account_names[@]}"; do
        local addr="${CONFIG_ACCOUNTS[${account}_address]:-}"
        if [ -n "$addr" ]; then
            echo "  ${account^}: $addr"
        fi
    done
    
    # Show env var accounts if not in config
    if [ -z "${CONFIG_ACCOUNTS[user_address]:-}" ] && [ -n "${USER_ADDRESS:-}" ]; then
        echo "  User (env): $USER_ADDRESS"
    fi
    if [ -z "${CONFIG_ACCOUNTS[solver_address]:-}" ] && [ -n "${SOLVER_ADDRESS:-}" ]; then
        echo "  Solver (env): $SOLVER_ADDRESS"
    fi
    echo ""
    
    echo "API:"
    echo "  URL: ${CONFIG_API[url]:-N/A}"
    
    print_separator
}

# Export configuration to environment variables
config_export() {
    # Export accounts
    for key in "${!CONFIG_ACCOUNTS[@]}"; do
        export "${key^^}=${CONFIG_ACCOUNTS[$key]}"
    done
    
    # Export commonly used addresses for first two chains (origin/dest pattern)
    local origin_chain="${CHAIN_IDS[0]:-}"
    local dest_chain="${CHAIN_IDS[1]:-}"
    
    if [ -n "$origin_chain" ]; then
        export ORIGIN_CHAIN_ID="$origin_chain"
        export INPUT_SETTLER_ADDRESS=$(config_get_network $origin_chain input_settler_address)
        export INPUT_SETTLER_COMPACT_ADDRESS=$(config_get_network $origin_chain input_settler_compact_address)
        export THE_COMPACT_ADDRESS=$(config_get_network $origin_chain the_compact_address)
    fi
    
    if [ -n "$dest_chain" ]; then
        export DEST_CHAIN_ID="$dest_chain"
        export OUTPUT_SETTLER_ADDRESS=$(config_get_network $dest_chain output_settler_address)
    fi
    
    # Export API config
    export API_URL="${CONFIG_API[url]:-}"
}

# Export functions
export -f config_load
export -f config_get
export -f config_get_network
export -f config_get_token
export -f config_get_token_by_symbol
export -f config_get_account
export -f config_get_chains
export -f config_validate
export -f config_export
export -f config_is_loaded
export -f config_get_network_ids
export -f config_get_compact
export -f config_get_oracle