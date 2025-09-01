#!/usr/bin/env bash
#
# ==============================================================================
# Forge Module - Foundry Tool Integration
# ==============================================================================
#
# This module provides wrapper functions for Foundry tools (forge, cast, anvil)
# with proper error handling, path detection, and output parsing.
#
# Key Features:
# - Automatic Foundry tool path detection
# - Contract compilation and deployment
# - Transaction sending and monitoring
# - Contract verification
# - ABI encoding/decoding utilities
# - Gas estimation and optimization
#
# Tool Wrappers:
# - forge: Smart contract compilation and testing
# - cast: Blockchain interactions and queries
# - anvil: Local Ethereum node management
#
# Path Detection:
# - Searches common installation locations
# - Supports custom Foundry installations
# - Falls back to system PATH
#
# Dependencies:
# - Foundry suite (forge, cast, anvil)
# - git: For submodule management
#
# Usage:
#   deploy_contract $chain_id $contract_name $args
#   run_cast call $contract $method $args
#   check_forge_installation
#
# ==============================================================================

# -----------------------------------------------------------------------------
# Tool Path Detection
# -----------------------------------------------------------------------------
# Helper to detect forge tool location
get_forge_path() {
    local forge_path=""
    
    # Try common locations
    if command -v forge &> /dev/null; then
        forge_path="forge"
    elif [ -f "$HOME/.foundry/bin/forge" ]; then
        forge_path="$HOME/.foundry/bin/forge"
    elif [ -f "$(which foundryup 2>/dev/null)" ]; then
        # If foundryup exists, try to use it to find forge
        source <(foundryup --help | grep 'export' 2>/dev/null || true)
        if command -v forge &> /dev/null; then
            forge_path="forge"
        fi
    fi
    
    echo "$forge_path"
}

get_cast_path() {
    local cast_path=""
    
    # Try common locations
    if command -v cast &> /dev/null; then
        cast_path="cast"
    elif [ -f "$HOME/.foundry/bin/cast" ]; then
        cast_path="$HOME/.foundry/bin/cast"
    elif [ -f "$(which foundryup 2>/dev/null)" ]; then
        # If foundryup exists, try to use it to find cast
        source <(foundryup --help | grep 'export' 2>/dev/null || true)
        if command -v cast &> /dev/null; then
            cast_path="cast"
        fi
    fi
    
    echo "$cast_path"
}

# Check if foundry tools are available
check_foundry() {
    local forge_path=$(get_forge_path)
    local cast_path=$(get_cast_path)
    
    if [ -z "$forge_path" ] || [ -z "$cast_path" ]; then
        print_error "Foundry tools not found!"
        print_info "Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
        return 1
    fi
    
    return 0
}

# Safe forge wrapper with error handling
forge_cmd() {
    local cmd="$1"
    shift
    
    local forge_path=$(get_forge_path)
    if [ -z "$forge_path" ]; then
        handle_error "FORGE_MISSING" "Forge command not found"
        return 1
    fi
    
    print_debug "Running forge $cmd with args: $*"
    
    local output
    local exit_code
    
    output=$("$forge_path" "$cmd" "$@" 2>&1)
    exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        print_error "Forge command failed: forge $cmd"
        print_error "Output: $output"
        return $exit_code
    fi
    
    echo "$output"
    return 0
}

# Safe cast wrapper with error handling
cast_cmd() {
    local cmd="$1"
    shift
    
    local cast_path=$(get_cast_path)
    if [ -z "$cast_path" ]; then
        handle_error "CAST_MISSING" "Cast command not found"
        return 1
    fi
    
    print_debug "Running cast $cmd with args: $*"
    
    local output
    local exit_code
    
    output=$("$cast_path" "$cmd" "$@" 2>&1)
    exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        print_error "Cast command failed: cast $cmd"
        print_error "Output: $output"
        return $exit_code
    fi
    
    echo "$output"
    return 0
}

# Contract deployment with validation
forge_deploy() {
    local contract_path="$1"
    local contract_name="$2"
    local rpc_url="$3"
    local private_key="$4"
    shift 4
    local constructor_args=("$@")
    
    print_info "Deploying $contract_name..." >&2
    print_debug "Contract: $contract_path" >&2
    print_debug "RPC: $rpc_url" >&2
    print_debug "Args: ${constructor_args[*]}" >&2
    
    local forge_args=("create" "$contract_path:$contract_name")
    forge_args+=("--rpc-url" "$rpc_url")
    forge_args+=("--private-key" "$private_key")
    forge_args+=("--broadcast")
    
    # Add constructor arguments if provided
    if [ ${#constructor_args[@]} -gt 0 ]; then
        forge_args+=("--constructor-args" "${constructor_args[@]}")
    fi
    
    local output
    output=$(forge_cmd "${forge_args[@]}")
    local exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        print_error "Failed to deploy $contract_name" >&2
        return $exit_code
    fi
    
    # Extract deployed address
    local deployed_addr=$(echo "$output" | grep "Deployed to:" | awk '{print $3}' | head -n1)
    if [ -z "$deployed_addr" ]; then
        print_error "Could not extract deployed address from forge output" >&2
        print_debug "Forge output: $output" >&2
        return 1
    fi
    
    if ! validate_address "$deployed_addr"; then
        print_error "Invalid deployed address: $deployed_addr" >&2
        return 1
    fi
    
    print_success "$contract_name deployed to $deployed_addr" >&2
    echo "$deployed_addr"
    return 0
}

# Get contract bytecode
forge_get_bytecode() {
    local contract_path="$1"
    local contract_name="$2"
    
    print_debug "Getting bytecode for $contract_path:$contract_name" >&2
    
    forge_cmd "inspect" "$contract_path:$contract_name" "bytecode"
}

# Build project
forge_build() {
    local project_dir="${1:-.}"
    
    print_info "Building forge project..."
    
    if [ ! -f "$project_dir/foundry.toml" ]; then
        print_warning "No foundry.toml found in $project_dir"
    fi
    
    cd "$project_dir" || return 1
    forge_cmd "build"
}

# Install dependencies
forge_install() {
    local project_dir="${1:-.}"
    
    print_info "Installing forge dependencies..."
    
    cd "$project_dir" || return 1
    forge_cmd "install"
}

# Contract interaction via cast
cast_call() {
    local contract="$1"
    local function_sig="$2"
    local rpc_url="$3"
    shift 3
    local args=("$@")
    
    if ! validate_address "$contract"; then
        print_error "Invalid contract address: $contract"
        return 1
    fi
    
    print_debug "Calling $function_sig on $contract"
    
    local cast_args=("call" "$contract" "$function_sig")
    cast_args+=("--rpc-url" "$rpc_url")
    
    # Add function arguments if provided
    if [ ${#args[@]} -gt 0 ]; then
        cast_args+=("${args[@]}")
    fi
    
    cast_cmd "${cast_args[@]}"
}

# Send transaction via cast
cast_send() {
    local contract="$1"
    local function_sig="$2"
    local rpc_url="$3"
    local private_key="$4"
    shift 4
    local args=("$@")
    
    if ! validate_address "$contract"; then
        print_error "Invalid contract address: $contract"
        return 1
    fi
    
    print_debug "Sending transaction to $contract: $function_sig"
    
    local cast_args=("send" "$contract" "$function_sig")
    cast_args+=("--rpc-url" "$rpc_url")
    cast_args+=("--private-key" "$private_key")
    
    # Add function arguments if provided
    if [ ${#args[@]} -gt 0 ]; then
        cast_args+=("${args[@]}")
    fi
    
    cast_cmd "${cast_args[@]}"
}

# Get balance
cast_balance() {
    local address="$1"
    local rpc_url="$2"
    local token="${3:-}"
    
    if ! validate_address "$address"; then
        print_error "Invalid address: $address"
        return 1
    fi
    
    if [ -n "$token" ]; then
        if ! validate_address "$token"; then
            print_error "Invalid token address: $token"
            return 1
        fi
        # ERC-20 balance
        cast_call "$token" "balanceOf(address)(uint256)" "$rpc_url" "$address"
    else
        # ETH balance
        cast_cmd "balance" "$address" "--rpc-url" "$rpc_url"
    fi
}

# Convert values
cast_to_wei() {
    local ether_amount="$1"
    cast_cmd "to-wei" "$ether_amount" "ether"
}

cast_from_wei() {
    local wei_amount="$1"
    cast_cmd "from-wei" "$wei_amount" "ether"
}

cast_to_dec() {
    local hex_value="$1"
    cast_cmd "to-dec" "$hex_value"
}

cast_to_hex() {
    local dec_value="$1"
    cast_cmd "to-hex" "$dec_value"
}

# Encode data
cast_abi_encode() {
    local function_sig="$1"
    shift
    local args=("$@")
    
    cast_cmd "abi-encode" "$function_sig" "${args[@]}"
}

# Compute keccak256 hash
cast_keccak() {
    local data="$1"
    cast_cmd "keccak" "$data"
}

# Sign message
cast_sign() {
    local private_key="$1"
    local message="$2"
    local no_hash="${3:-false}"
    
    local cast_args=("wallet" "sign")
    cast_args+=("--private-key" "$private_key")
    
    if [ "$no_hash" = "true" ]; then
        cast_args+=("--no-hash")
    fi
    
    cast_args+=("$message")
    
    print_debug "Running cast wallet sign with no_hash=$no_hash"
    cast_cmd "${cast_args[@]}"
}

# Get transaction receipt
cast_receipt() {
    local tx_hash="$1"
    local rpc_url="$2"
    local format="${3:-json}"
    
    local cast_args=("receipt" "$tx_hash")
    cast_args+=("--rpc-url" "$rpc_url")
    
    if [ "$format" = "json" ]; then
        cast_args+=("--json")
    fi
    
    cast_cmd "${cast_args[@]}"
}

# Get chain ID
cast_chain_id() {
    local rpc_url="$1"
    cast_cmd "chain-id" "--rpc-url" "$rpc_url"
}

# Get block number
cast_block_number() {
    local rpc_url="$1"
    cast_cmd "block-number" "--rpc-url" "$rpc_url"
}

# Get gas price
cast_gas_price() {
    local rpc_url="$1"
    cast_cmd "gas-price" "--rpc-url" "$rpc_url"
}

# Get contract code
cast_code() {
    local address="$1"
    local rpc_url="$2"
    
    if ! validate_address "$address"; then
        print_error "Invalid address: $address"
        return 1
    fi
    
    cast_cmd "code" "$address" "--rpc-url" "$rpc_url"
}

# Wait for transaction
cast_wait_for_tx() {
    local tx_hash="$1"
    local rpc_url="$2"
    local confirmations="${3:-1}"
    local timeout="${4:-60}"
    
    print_info "Waiting for transaction confirmation..."
    print_debug "TX Hash: $tx_hash"
    print_debug "Confirmations: $confirmations"
    print_debug "Timeout: ${timeout}s"
    
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        local receipt
        receipt=$(cast_receipt "$tx_hash" "$rpc_url" 2>/dev/null || echo "")
        
        if [ -n "$receipt" ]; then
            local status=$(echo "$receipt" | jq -r '.status // empty' 2>/dev/null || echo "")
            
            if [ "$status" = "0x1" ] || [ "$status" = "1" ]; then
                print_success "Transaction confirmed"
                echo "$receipt"
                return 0
            elif [ "$status" = "0x0" ] || [ "$status" = "0" ]; then
                print_error "Transaction failed"
                echo "$receipt"
                return 1
            fi
        fi
        
        sleep 2
        elapsed=$((elapsed + 2))
    done
    
    print_error "Transaction timeout after ${timeout}s"
    return 1
}

# RPC call
cast_rpc() {
    local method="$1"
    local rpc_url="$2"
    shift 2
    local params=("$@")
    
    local cast_args=("rpc" "--rpc-url" "$rpc_url" "$method")
    
    if [ ${#params[@]} -gt 0 ]; then
        cast_args+=("${params[@]}")
    fi
    
    cast_cmd "${cast_args[@]}"
}

# Export functions
export -f check_foundry
export -f forge_cmd
export -f cast_cmd
export -f forge_deploy
export -f forge_build
export -f forge_install
export -f cast_call
export -f cast_send
export -f cast_balance
export -f cast_to_wei
export -f cast_from_wei
export -f cast_sign
export -f cast_receipt
export -f cast_wait_for_tx