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

# Configuration storage using regular variables

# Array to store discovered chain IDs
CHAIN_IDS=()

# Helper functions for config storage (simulating associative arrays)
config_set() {
    local category="$1"
    local key="$2"
    local value="$3"
    # Convert to uppercase using tr
    local category_upper=$(echo "$category" | tr '[:lower:]' '[:upper:]')
    local var_name="CONFIG_${category_upper}_${key}"
    # Use eval to set the variable dynamically
    eval "${var_name}='${value}'"
}

config_get_var() {
    local category="$1"
    local key="$2"
    # Convert to uppercase using tr
    local category_upper=$(echo "$category" | tr '[:lower:]' '[:upper:]')
    local var_name="CONFIG_${category_upper}_${key}"
    # Use eval to get the variable value
    eval "echo \"\$${var_name}\""
}

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
    config_set "main" "solver_id" "$(parse_toml_value "$config_file" "solver" "id")"
    config_set "main" "monitoring_timeout" "$(parse_toml_value "$config_file" "solver" "monitoring_timeout_minutes")"
    config_set "main" "storage_primary" "$(parse_toml_value "$config_file" "storage" "primary")"
    config_set "main" "storage_path" "$(parse_toml_value "$config_file" "storage.implementations.file" "storage_path")"
    
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
    
    print_debug "Found chains: ${CHAIN_IDS[*]:-}"
    
    # Load each network's configuration
    for chain_id in "${CHAIN_IDS[@]}"; do
        local section="networks.$chain_id"
        
        # Load RPC URLs
        local rpc_http=$(grep -A2 "\[\[$section.rpc_urls\]\]" "$file" | grep "http =" | head -n1 | sed 's/.*= *//' | tr -d '"')
        local rpc_ws=$(grep -A2 "\[\[$section.rpc_urls\]\]" "$file" | grep "ws =" | head -n1 | sed 's/.*= *//' | tr -d '"')
        
        config_set "networks" "${chain_id}_rpc_url" "${rpc_http:-http://localhost:8545}"
        config_set "networks" "${chain_id}_ws_url" "${rpc_ws:-ws://localhost:8545}"
        
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
                config_set "networks" "${chain_id}_${contract}" "$value"
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
                config_set "tokens" "${chain_id}_token_${i}_address" "${token_addresses[$i]}"
                config_set "tokens" "${chain_id}_token_${i}_symbol" "${token_symbols[$i]:-TOKEN$i}"
                config_set "tokens" "${chain_id}_token_${i}_decimals" "${token_decimals[$i]:-18}"
                token_count=$((token_count + 1))
            done
        fi
        
        config_set "networks" "${chain_id}_token_count" "$token_count"
        
        print_debug "Loaded chain $chain_id with $token_count tokens"
    done
}

# Load API configuration
config_load_api() {
    local file="$1"
    
    config_set "api" "host" "$(parse_toml_value "$file" "api" "host")"
    config_set "api" "port" "$(parse_toml_value "$file" "api" "port")"
    
    # Load JWT auth configuration
    config_set "api" "auth_enabled" "$(parse_toml_value "$file" "api.auth" "enabled")"
    config_set "api" "auth_jwt_secret" "$(parse_toml_value "$file" "api.auth" "jwt_secret")"
    config_set "api" "auth_token_expiry_hours" "$(parse_toml_value "$file" "api.auth" "token_expiry_hours")"
    config_set "api" "auth_issuer" "$(parse_toml_value "$file" "api.auth" "issuer")"
    
    local host=$(config_get_var "api" "host")
    local port=$(config_get_var "api" "port")
    if [ -n "$host" ] && [ -n "$port" ]; then
        config_set "api" "url" "http://${host}:${port}"
    fi
}

# Load CLI configuration (accounts and compact settings)
config_load_accounts() {
    local file="$1"
    
    # Load all account-related keys from cli.toml
    config_set "accounts" "user_address" "$(parse_toml_value "$file" "accounts" "user_address")"
    config_set "accounts" "user_private_key" "$(parse_toml_value "$file" "accounts" "user_private_key")"
    config_set "accounts" "solver_address" "$(parse_toml_value "$file" "accounts" "solver_address")"
    config_set "accounts" "recipient_address" "$(parse_toml_value "$file" "accounts" "recipient_address")"
    
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
        config_set "accounts" "solver_private_key" "$solver_private_key"
    fi
}

# Load gas configuration
config_load_gas() {
    local file="$1"
    
    # Gas config is primarily for reference/documentation
    # Store values if needed for display purposes
    config_set "gas" "permit2_open" "$(parse_toml_value "$file" "gas.flows.permit2_escrow" "open")"
    config_set "gas" "permit2_fill" "$(parse_toml_value "$file" "gas.flows.permit2_escrow" "fill")"
    config_set "gas" "permit2_claim" "$(parse_toml_value "$file" "gas.flows.permit2_escrow" "claim")"
    config_set "gas" "compact_open" "$(parse_toml_value "$file" "gas.flows.compact_resource_lock" "open")"
    config_set "gas" "compact_fill" "$(parse_toml_value "$file" "gas.flows.compact_resource_lock" "fill")"
    config_set "gas" "compact_claim" "$(parse_toml_value "$file" "gas.flows.compact_resource_lock" "claim")"
    
    print_debug "Loaded gas configuration from $file"
}

# Load environment variables
config_load_env() {
    # Override with environment variables if set
    [ -n "${USER_ADDRESS:-}" ] && config_set "accounts" "user_address" "$USER_ADDRESS"
    [ -n "${USER_PRIVATE_KEY:-}" ] && config_set "accounts" "user_private_key" "$USER_PRIVATE_KEY"
    [ -n "${SOLVER_ADDRESS:-}" ] && config_set "accounts" "solver_address" "$SOLVER_ADDRESS"
    [ -n "${SOLVER_PRIVATE_KEY:-}" ] && config_set "accounts" "solver_private_key" "$SOLVER_PRIVATE_KEY"
    [ -n "${RECIPIENT_ADDRESS:-}" ] && config_set "accounts" "recipient_address" "$RECIPIENT_ADDRESS"
    [ -n "${ETH_PRIVATE_KEY:-}" ] && config_set "accounts" "solver_private_key" "$ETH_PRIVATE_KEY"
}

# Get specific config value
config_get() {
    local section="$1"
    local key="$2"
    local default="${3:-}"
    
    if [ ! "$CONFIG_LOADED" = true ]; then
        config_load
    fi
    
    case "$section" in
        main|solver|storage)
            local value=$(config_get_var "main" "$key")
            echo "${value:-$default}"
            ;;
        network|networks)
            local value=$(config_get_var "networks" "$key")
            echo "${value:-$default}"
            ;;
        api | api.auth)
            # Handle both api and api.auth sections
            if [ "$section" = "api.auth" ]; then
                # For api.auth, prefix the key with auth_
                local value=$(config_get_var "api" "auth_${key}")
                echo "${value:-$default}"
            else
                local value=$(config_get_var "api" "$key")
                echo "${value:-$default}"
            fi
            ;;
        account|accounts)
            local value=$(config_get_var "accounts" "$key")
            echo "${value:-$default}"
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
    local value=$(config_get_var "networks" "$key")
    echo "${value:-$default}"
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
    config_get_var "tokens" "$key"
}

# Get token by symbol
config_get_token_by_symbol() {
    local chain_id="$1"
    local symbol="$2"
    local property="${3:-address}"
    
    local token_count=$(config_get_network "$chain_id" "token_count" 0)
    
    for ((i=0; i<token_count; i++)); do
        local token_symbol=$(config_get_var "tokens" "${chain_id}_token_${i}_symbol")
        if [ "$token_symbol" = "$symbol" ]; then
            config_get_var "tokens" "${chain_id}_token_${i}_${property}"
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
    config_get_var "accounts" "$key"
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
        config_get_var "tokens" "${chain_id}_token_${i}_address"
    done
}

# Get oracle address from settlement configuration
config_get_compact() {
    local property="$1"
    
    if [ ! "$CONFIG_LOADED" = true ]; then
        return 1
    fi
    
    config_get_var "compact" "$property"
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
    if [ -z "$(config_get_var "main" "solver_id")" ]; then
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
        local rpc_url=$(config_get_var "networks" "${chain_id}_rpc_url")
        if [ -z "$rpc_url" ]; then
            print_error "Missing RPC URL for chain $chain_id"
            valid=false
        fi
        
        # Check for at least one settler contract
        local has_settler=false
        for settler in input_settler_address output_settler_address input_settler_compact_address; do
            local settler_addr=$(config_get_var "networks" "${chain_id}_${settler}")
            if [ -n "$settler_addr" ]; then
                has_settler=true
                break
            fi
        done
        
        if [ "$has_settler" = false ]; then
            print_warning "No settler contracts configured for chain $chain_id"
        fi
        
        # Check for tokens
        local token_count=$(config_get_var "networks" "${chain_id}_token_count")
        if [ "${token_count:-0}" -eq 0 ]; then
            print_warning "No tokens configured for chain $chain_id"
        fi
    done
    
    # Check API config
    local api_host=$(config_get_var "api" "host")
    local api_port=$(config_get_var "api" "port")
    if [ -z "$api_host" ] || [ -z "$api_port" ]; then
        print_error "Missing API configuration (host/port)"
        valid=false
    fi
    
    # Check for at least basic accounts from env if not in config
    local user_address=$(config_get_var "accounts" "user_address")
    if [ -z "$user_address" ] && [ -z "${USER_ADDRESS:-}" ]; then
        print_warning "No user account configured (set USER_ADDRESS env var)"
    fi
    
    local solver_address=$(config_get_var "accounts" "solver_address")
    if [ -z "$solver_address" ] && [ -z "${SOLVER_ADDRESS:-}" ]; then
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
    
    local solver_id=$(config_get_var "main" "solver_id")
    echo "Solver ID: ${solver_id:-N/A}"
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
                # Replace ${name^} with manual capitalization
                local first_char=$(echo "$name" | cut -c1 | tr '[:lower:]' '[:upper:]')
                local rest_chars=$(echo "$name" | cut -c2-)
                echo "    ${first_char}${rest_chars}: $addr"
            fi
        done
        
        # Show tokens
        local token_count=$(config_get_network $chain_id token_count 0)
        if [ "$token_count" -gt 0 ]; then
            echo "    Tokens:"
            for ((i=0; i<token_count; i++)); do
                local symbol=$(config_get_var "tokens" "${chain_id}_token_${i}_symbol")
                local addr=$(config_get_var "tokens" "${chain_id}_token_${i}_address")
                echo "      $symbol: $addr"
            done
        fi
        echo ""
    done
    
    echo "Accounts:"
    # Show all configured accounts (hardcoded list since we don't have associative arrays)
    local account_types="user solver recipient"
    for account in $account_types; do
        local addr=$(config_get_var "accounts" "${account}_address")
        if [ -n "$addr" ]; then
            # Replace ${account^} with manual capitalization
            local first_char=$(echo "$account" | cut -c1 | tr '[:lower:]' '[:upper:]')
            local rest_chars=$(echo "$account" | cut -c2-)
            echo "  ${first_char}${rest_chars}: $addr"
        fi
    done
    
    # Show env var accounts if not in config
    local user_addr=$(config_get_var "accounts" "user_address")
    if [ -z "$user_addr" ] && [ -n "${USER_ADDRESS:-}" ]; then
        echo "  User (env): $USER_ADDRESS"
    fi
    local solver_addr=$(config_get_var "accounts" "solver_address")
    if [ -z "$solver_addr" ] && [ -n "${SOLVER_ADDRESS:-}" ]; then
        echo "  Solver (env): $SOLVER_ADDRESS"
    fi
    echo ""
    
    echo "API:"
    local api_url=$(config_get_var "api" "url")
    echo "  URL: ${api_url:-N/A}"
    
    print_separator
}

# Export configuration to environment variables
config_export() {
    # Export accounts (hardcoded list since we don't have associative arrays)
    local account_vars="user_address user_private_key solver_address solver_private_key recipient_address"
    for key in $account_vars; do
        local value=$(config_get_var "accounts" "$key")
        if [ -n "$value" ]; then
            # Replace ${key^^} with tr for
            local key_upper=$(echo "$key" | tr '[:lower:]' '[:upper:]')
            export "${key_upper}=${value}"
        fi
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
    local api_url=$(config_get_var "api" "url")
    export API_URL="${api_url:-}"
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