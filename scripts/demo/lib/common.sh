#!/usr/bin/env bash
#
# ==============================================================================
# Common Module - Shared Utilities and Helper Functions
# ==============================================================================
#
# This module provides common utility functions used across all demo scripts,
# including validation, formatting, and environment checks.
#
# Key Functions:
# - JSON validation and parsing
# - Number formatting and validation
# - Hex string manipulation
# - Timestamp utilities
# - Environment validation
#
# ==============================================================================

# Common utilities module - shared functions used across all modules

# Global constants
OIF_CONTRACTS_COMMIT="eafdaa8"  # release-v0.1-rc.0: updates for release candidate

# Address manipulation functions
address_to_bytes32() {
    local address="$1"
    # Remove 0x prefix if present, then pad to 32 bytes
    address="${address#0x}"
    echo "0x000000000000000000000000${address}"
}

bytes32_to_address() {
    local bytes32="$1"
    # Extract last 20 bytes (40 hex chars)
    echo "0x${bytes32:26}"
}

# UII address conversion (ERC-7930)
to_uii_address() {
    local chain_id="$1"
    local address="$2"
    
    # Remove 0x prefix from address
    address="${address#0x}"
    
    # Map chain ID to chain reference (2 bytes hex)
    local chain_ref
    case "$chain_id" in
        31337) chain_ref="7a69" ;;  # Local testnet 1
        31338) chain_ref="7a6a" ;;  # Local testnet 2
        1) chain_ref="0001" ;;      # Ethereum mainnet
        10) chain_ref="000a" ;;     # Optimism
        8453) chain_ref="2105" ;;   # Base
        42161) chain_ref="a4b1" ;;  # Arbitrum
        *) chain_ref=$(printf "%04x" "$chain_id") ;;
    esac
    
    # Format: 0x01 (namespace) + 00000214 (EVM coin type) + chainRef + address
    echo "0x0100000214${chain_ref}${address}"
}

from_uii_address() {
    local uii="$1"
    
    # UII format: 0x + 01 + 00000214 + chainRef + address
    # Positions:   0-1  2-3   4-11      12-15     16-55
    
    # Extract chain reference (positions 12-15)
    local chain_ref="${uii:12:4}"
    
    # Map chain reference to chain ID
    local chain_id
    case "$chain_ref" in
        "7a69") chain_id=31337 ;;
        "7a6a") chain_id=31338 ;;
        "0001") chain_id=1 ;;
        "000a") chain_id=10 ;;
        "2105") chain_id=8453 ;;
        "a4b1") chain_id=42161 ;;
        *) chain_id=$((16#$chain_ref)) ;;
    esac
    
    # Extract address (positions 16+, last 40 chars)
    local address="0x${uii:16}"
    
    echo "$chain_id $address"
}

# Time utilities
get_deadline() {
    local offset="${1:-300}"  # Default 5 minutes
    echo $(($(date +%s) + offset))
}

get_timestamp() {
    date +%s
}

get_timestamp_ms() {
    # Use perl for millisecond precision
    perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000'
}

# Math utilities
wei_to_ether() {
    local wei="$1"
    echo "scale=18; $wei / 1000000000000000000" | bc -l
}

ether_to_wei() {
    local ether="$1"
    echo "scale=0; $ether * 1000000000000000000 / 1" | bc
}

format_balance() {
    local wei="$1"
    printf "%8.4f" $(echo "scale=4; $wei / 1000000000000000000" | bc -l)
}

# Validation functions
validate_address() {
    local address="$1"
    [[ "$address" =~ ^0x[0-9a-fA-F]{40}$ ]]
}

validate_chain_id() {
    local chain_id="$1"
    [[ "$chain_id" =~ ^[0-9]+$ ]] && [ "$chain_id" -gt 0 ]
}

validate_amount() {
    local amount="$1"
    # Check if it's a valid number (integer or decimal)
    [[ "$amount" =~ ^[0-9]+(\.[0-9]+)?$ ]]
}

validate_bytes32() {
    local value="$1"
    [[ "$value" =~ ^0x[0-9a-fA-F]{64}$ ]]
}

# Nonce generation
generate_nonce() {
    # Use milliseconds to avoid collisions
    get_timestamp_ms
}

generate_nonce_random() {
    # Alternative: use random number
    echo $((RANDOM * 100000 + RANDOM))
}

# Hex manipulation
remove_0x_prefix() {
    local value="$1"
    echo "${value#0x}"
}

add_0x_prefix() {
    local value="$1"
    if [[ "$value" == 0x* ]]; then
        echo "$value"
    else
        echo "0x$value"
    fi
}

pad_hex_to_bytes32() {
    local value="$1"
    value="${value#0x}"
    # Pad with zeros to 64 chars (32 bytes)
    printf "0x%064s" "$value" | tr ' ' '0'
}

# JSON utilities
json_get() {
    local json="$1"
    local path="$2"
    echo "$json" | jq -r "$path"
}

json_set() {
    local json="$1"
    local path="$2"
    local value="$3"
    echo "$json" | jq "$path = $value"
}

# File utilities
ensure_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        touch "$file"
    fi
}

ensure_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
    fi
}

# Process management
is_process_running() {
    local pid="$1"
    kill -0 "$pid" 2>/dev/null
}

wait_for_port() {
    local port="$1"
    local timeout="${2:-30}"
    local elapsed=0
    
    while ! nc -z localhost "$port" 2>/dev/null; do
        if [ $elapsed -ge $timeout ]; then
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    
    return 0
}

# Error handling
handle_error() {
    local error_code="$1"
    local error_message="$2"
    local context="${3:-}"
    
    case "$error_code" in
        CONFIG_*)
            print_error "Configuration error: $error_message"
            print_info "Run 'oif-demo init' to fix configuration"
            ;;
        NETWORK_*)
            print_error "Network error: $error_message"
            if [ -n "$context" ]; then
                print_info "Context: $context"
            fi
            ;;
        CONTRACT_*)
            print_error "Contract error: $error_message"
            ;;
        API_*)
            print_error "API error: $error_message"
            ;;
        *)
            print_error "Unknown error: $error_message"
            ;;
    esac
    
    exit 1
}

# Logging
LOG_LEVEL="${LOG_LEVEL:-INFO}"

log_debug() {
    [ "$LOG_LEVEL" = "DEBUG" ] && echo "[DEBUG] $1" >&2
}

log_info() {
    [[ "$LOG_LEVEL" =~ (DEBUG|INFO) ]] && echo "[INFO] $1" >&2
}

log_warn() {
    [[ "$LOG_LEVEL" =~ (DEBUG|INFO|WARN) ]] && echo "[WARN] $1" >&2
}

log_error() {
    echo "[ERROR] $1" >&2
}

# Standard timeouts
EXPIRY_OFFSET=300        # 5 minutes for order expiry
FILL_DEADLINE_OFFSET=600 # 10 minutes for fill deadline
DEADLINE_OFFSET=300      # 5 minutes for Permit2 deadline

# Fixed addresses
PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"

# Empty data hashes
ZERO_BYTES32="0x0000000000000000000000000000000000000000000000000000000000000000"

# Lock type constants
LOCK_TYPE_PERMIT2_ESCROW=1      # Permit2-based escrow mechanism
LOCK_TYPE_EIP3009_ESCROW=2      # EIP-3009 based escrow mechanism
LOCK_TYPE_RESOURCE_LOCK=3       # Resource lock mechanism (The Compact)

# Export functions for use in other modules
export -f address_to_bytes32
export -f bytes32_to_address
export -f to_uii_address
export -f from_uii_address
export -f get_deadline
export -f get_timestamp
export -f get_timestamp_ms
export -f wei_to_ether
export -f ether_to_wei
export -f format_balance
export -f validate_address
export -f validate_chain_id
export -f validate_amount
export -f generate_nonce
export -f handle_error