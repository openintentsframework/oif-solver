#!/bin/bash
# Account configuration loader for demo and test scripts
# 
# This script provides account information that was previously
# stored in the solver config but is only needed for demo/test scripts.
#
# Usage: source scripts/e2e/lib/accounts.sh

# Load account addresses from testnet-config.json
load_account_config() {
    local config_file="${1:-scripts/e2e/testnet-config.json}"
    
    if [ ! -f "$config_file" ]; then
        echo "Warning: Account config not found: $config_file" >&2
        return 1
    fi
    
    # Export account addresses
    export SOLVER_ADDRESS=$(jq -r '.accounts.solver.address // empty' "$config_file")
    export USER_ADDRESS=$(jq -r '.accounts.user.address // empty' "$config_file")
    export RECIPIENT_ADDRESS=$(jq -r '.accounts.recipient.address // .accounts.user.address // empty' "$config_file")
    
    # Token and infrastructure addresses
    export PERMIT2_ADDRESS=$(jq -r '.infrastructure.permit2_address // "0x000000000022D473030F116dDEE9F6B43aC78BA3"' "$config_file")
    
    return 0
}

# Get token address for a specific chain
get_token_address() {
    local chain="$1"
    local token="${2:-usdc}"
    local chains_file="${3:-scripts/e2e/testnet_chains.json}"
    
    if [ ! -f "$chains_file" ]; then
        echo "" >&2
        return 1
    fi
    
    case "$token" in
        "usdc"|"USDC")
            jq -r ".\"$chain\".usdc_address // empty" "$chains_file"
            ;;
        *)
            echo "Unknown token: $token" >&2
            return 1
            ;;
    esac
}

# Validate required environment variables for demo scripts
validate_demo_environment() {
    local missing=()
    
    # Check for required private key
    if [ -z "$USER_PRIVATE_KEY" ]; then
        missing+=("USER_PRIVATE_KEY")
    fi
    
    # Check for addresses (can come from config or env)
    if [ -z "$USER_ADDRESS" ]; then
        missing+=("USER_ADDRESS")
    fi
    
    if [ -z "$RECIPIENT_ADDRESS" ]; then
        missing+=("RECIPIENT_ADDRESS") 
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Error: Missing required environment variables:" >&2
        for var in "${missing[@]}"; do
            echo "  - $var" >&2
        done
        echo "" >&2
        echo "Please set these in your .env file or export them before running demo scripts." >&2
        return 1
    fi
    
    return 0
}

# Auto-load configuration if sourced
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    # Script is being sourced
    load_account_config
fi