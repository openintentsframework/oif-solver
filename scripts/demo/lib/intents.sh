#!/usr/bin/env bash
#
# ==============================================================================
# Intents Module - Build and Submit Cross-Chain Intents
# ==============================================================================
#
# This module handles the creation, signing, and submission of cross-chain
# intents using both escrow and compact (ResourceLock) mechanisms.
#
# Supported Intent Types:
# - Escrow: Traditional escrow-based intents using Permit2 or EIP-3009
# - Compact: ResourceLock-based intents for gas-efficient execution
#
# Key Features:
# - EIP-712 structured data signing
# - Permit2 authorization handling
# - ResourceLock (Compact) support
# - Multiple token format support (symbols and addresses)
# - Intent validation and verification
# - Quote request format generation
#
# Dependencies:
# - signature.sh: For EIP-712 signing
# - blockchain.sh: For chain interactions
# - config.sh: For configuration management
# - api.sh: For API submissions
#
# Usage:
#   intent_build escrow permit2 31337 31338 TokenA TokenB
#   intent_submit demo-output/post_intent.req.json
#   intent_test escrow permit2 A2B
#
# ==============================================================================

# -----------------------------------------------------------------------------
# Global State Management
# -----------------------------------------------------------------------------
# Intent status tracking - stores state from last intent operation
# Using regular variables
INTENT_STATUS_last_order_id=""
INTENT_STATUS_last_tx_hash=""
INTENT_STATUS_last_signature=""
INTENT_STATUS_last_lock_type=""

# -----------------------------------------------------------------------------
# Status Management Functions
# -----------------------------------------------------------------------------
# Clear intent status
clear_intent_status() {
    INTENT_STATUS_last_order_id=""
    INTENT_STATUS_last_tx_hash=""
    INTENT_STATUS_last_signature=""
    INTENT_STATUS_last_lock_type=""
}

# Get intent status field
get_intent_status() {
    local field="$1"
    case "$field" in
        "last_order_id")
            echo "$INTENT_STATUS_last_order_id"
            ;;
        "last_tx_hash")
            echo "$INTENT_STATUS_last_tx_hash"
            ;;
        "last_signature")
            echo "$INTENT_STATUS_last_signature"
            ;;
        "last_lock_type")
            echo "$INTENT_STATUS_last_lock_type"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Set intent status field
set_intent_status() {
    local field="$1"
    local value="$2"
    case "$field" in
        "last_order_id")
            INTENT_STATUS_last_order_id="$value"
            ;;
        "last_tx_hash")
            INTENT_STATUS_last_tx_hash="$value"
            ;;
        "last_signature")
            INTENT_STATUS_last_signature="$value"
            ;;
        "last_lock_type")
            INTENT_STATUS_last_lock_type="$value"
            ;;
    esac
}

# Build mandate output structure
build_mandate_output() {
    local oracle="$1"
    local settler="$2"
    local chain_id="$3"
    local token="$4"
    local amount="$5"
    local recipient="$6"
    local call_data="${7:-0x}"
    local context_data="${8:-0x}"
    
    # Convert addresses to bytes32 (must be lowercase)
    local oracle_lower=$(echo "$oracle" | tr '[:upper:]' '[:lower:]')
    local settler_lower=$(echo "$settler" | tr '[:upper:]' '[:lower:]')
    local token_lower=$(echo "$token" | tr '[:upper:]' '[:lower:]')
    local recipient_lower=$(echo "$recipient" | tr '[:upper:]' '[:lower:]')
    local oracle_bytes32="0x000000000000000000000000${oracle_lower#0x}"
    local settler_bytes32="0x000000000000000000000000${settler_lower#0x}"
    local token_bytes32="0x000000000000000000000000${token_lower#0x}"
    local recipient_bytes32="0x000000000000000000000000${recipient_lower#0x}"
    
    echo "$oracle_bytes32,$settler_bytes32,$chain_id,$token_bytes32,$amount,$recipient_bytes32,$call_data,$context_data"
}

# Build input tokens array
build_input_tokens() {
    local token_address="$1"
    local amount="$2"
    
    # Convert token address to uint256 for the inputs array
    local token_uint256=$(cast_to_dec "$token_address")
    echo "[[$token_uint256,$amount]]"
}

# Build StandardOrder structure
build_standard_order_struct() {
    local user="$1"
    local nonce="$2"
    local origin_chain_id="$3"
    local expiry="$4"
    local fill_deadline="$5"
    local input_oracle="$6"
    local input_tokens="$7"  # Already formatted as [[token,amount],...]
    local outputs_array="$8"  # Already formatted as [(oracle,settler,chain,token,amount,recipient,call,context),...]
    
    echo "($user,$nonce,$origin_chain_id,$expiry,$fill_deadline,$input_oracle,$input_tokens,$outputs_array)"
}

# Create escrow intent (Permit2-based)
create_escrow_intent() {
    local user_addr="$1"
    local user_private_key="$2"
    local origin_chain_id="$3"
    local dest_chain_id="$4"
    local input_token="$5"
    local input_amount="$6"
    local output_token="$7"
    local output_amount="$8"
    local recipient="$9"
    local input_settler="${10}"
    local output_settler="${11}"
    local input_oracle="${12}"
    
    print_info "Creating escrow intent (Permit2)" >&2
    print_debug "User: $user_addr" >&2
    print_debug "Input: $input_amount tokens of $input_token on chain $origin_chain_id" >&2
    print_debug "Output: $output_amount tokens of $output_token on chain $dest_chain_id" >&2
    print_debug "Recipient: $recipient" >&2
    
    # Generate unique nonce (allow override via NONCE env variable)
    local nonce
    if [ -n "${NONCE:-}" ]; then
        nonce="$NONCE"
        print_debug "Using provided NONCE: $nonce" >&2
    else
        nonce=$(generate_nonce)
    fi
    
    # Calculate deadlines (allow override via environment variables)
    local current_time=$(get_timestamp)
    local expiry
    local fill_deadline
    
    if [ -n "${EXPIRY:-}" ]; then
        expiry="$EXPIRY"
        print_debug "Using provided EXPIRY: $expiry" >&2
    else
        expiry=$((current_time + EXPIRY_OFFSET))
    fi
    
    if [ -n "${FILL_DEADLINE:-}" ]; then
        fill_deadline="$FILL_DEADLINE"
        print_debug "Using provided FILL_DEADLINE: $fill_deadline" >&2
    else
        fill_deadline=$((current_time + FILL_DEADLINE_OFFSET))
    fi
    local permit2_deadline
    if [ -n "${PERMIT2_DEADLINE:-}" ]; then
        permit2_deadline="$PERMIT2_DEADLINE"
        print_debug "Using provided PERMIT2_DEADLINE: $permit2_deadline" >&2
    else
        permit2_deadline=$((current_time + DEADLINE_OFFSET))
    fi
    
    print_debug "Nonce: $nonce" >&2
    print_debug "Expiry: $expiry" >&2
    print_debug "Fill deadline: $fill_deadline" >&2
    print_debug "Permit2 deadline: $permit2_deadline" >&2
    
    # Build mandate output
    local mandate_output=$(build_mandate_output \
        "0x0000000000000000000000000000000000000000000000000000000000000000" \
        "$output_settler" "$dest_chain_id" "$output_token" "$output_amount" "$recipient")
    
    # Build input tokens array
    local input_tokens=$(build_input_tokens "$input_token" "$input_amount")
    
    # Build outputs array (single output for now)
    local zero_bytes32="0x0000000000000000000000000000000000000000000000000000000000000000"
    local output_settler_bytes32="0x000000000000000000000000${output_settler#0x}"
    local output_token_bytes32="0x000000000000000000000000${output_token#0x}"
    local recipient_bytes32="0x000000000000000000000000${recipient#0x}"
    
    local outputs_array="[($zero_bytes32,$output_settler_bytes32,$dest_chain_id,$output_token_bytes32,$output_amount,$recipient_bytes32,0x,0x)]"
    
    # Build StandardOrder
    local order_struct=$(build_standard_order_struct \
        "$user_addr" "$nonce" "$origin_chain_id" "$expiry" "$fill_deadline" \
        "$input_oracle" "$input_tokens" "$outputs_array")
    
    local abi_type='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'
    local order_data=$(cast_abi_encode "$abi_type" "$order_struct")
    
    if [ -z "$order_data" ]; then
        print_error "Failed to encode StandardOrder" >&2
        return 1
    fi
    
    print_debug "StandardOrder encoded: $order_data" >&2
    
    # Generate Permit2 signature
    print_info "Generating Permit2 signature..." >&2
    
    local mandate_outputs_json="[{\"oracle\":\"$zero_bytes32\",\"settler\":\"$output_settler_bytes32\",\"chainId\":$dest_chain_id,\"token\":\"$output_token_bytes32\",\"amount\":\"$output_amount\",\"recipient\":\"$recipient_bytes32\"}]"
    
    local signature=$(sign_standard_intent \
        "$user_private_key" "$origin_chain_id" "$input_token" "$input_amount" \
        "$input_settler" "$nonce" "$fill_deadline" "$expiry" "$input_oracle" \
        "$mandate_outputs_json")
    
    if [ -z "$signature" ]; then
        print_error "Failed to generate signature" >&2
        return 1
    fi
    
    print_success "Escrow intent created" >&2
    print_debug "Order data: $order_data" >&2
    print_debug "Signature: $signature" >&2
    
    # Store in global state
    set_intent_status "last_signature" "$signature"
    set_intent_status "last_lock_type" "$LOCK_TYPE_PERMIT2_ESCROW"
    
    # Include debug information if DEBUG_OUTPUT environment variable is set
    if [ -n "${DEBUG_OUTPUT:-}" ]; then
        # For escrow, we can include useful debug info too
        echo "{\"order\":\"$order_data\",\"signature\":\"$signature\",\"lock_type\":$LOCK_TYPE_PERMIT2_ESCROW,\"sponsor\":\"$user_addr\",\"_debug\":{\"nonce\":\"$nonce\",\"expiry\":\"$expiry\",\"fill_deadline\":\"$fill_deadline\"}}"
    else
        # Return order data and signature as JSON (normal mode)
        echo "{\"order\":\"$order_data\",\"signature\":\"$signature\",\"lock_type\":$LOCK_TYPE_PERMIT2_ESCROW,\"sponsor\":\"$user_addr\"}"
    fi
    return 0
}

# Create EIP-3009 intent (using receiveWithAuthorization)
create_eip3009_intent() {
    local user_addr="$1"
    local user_private_key="$2"
    local origin_chain_id="$3"
    local dest_chain_id="$4"
    local input_token="$5"
    local input_amount="$6"
    local output_token="$7"
    local output_amount="$8"
    local recipient="$9"
    local input_settler="${10}"
    local output_settler="${11}"
    local input_oracle="${12}"
    
    print_info "Creating EIP-3009 intent" >&2
    print_debug "User: $user_addr" >&2
    print_debug "Input: $input_amount tokens of $input_token on chain $origin_chain_id" >&2
    print_debug "Output: $output_amount tokens of $output_token on chain $dest_chain_id" >&2
    print_debug "Recipient: $recipient" >&2
    
    # Generate unique nonce
    local nonce
    if [ -n "${NONCE:-}" ]; then
        nonce="$NONCE"
        print_debug "Using provided NONCE: $nonce" >&2
    else
        nonce=$(generate_nonce)
    fi
    
    # Calculate deadlines
    local current_time=$(get_timestamp)
    local expiry
    local fill_deadline
    
    if [ -n "${EXPIRY:-}" ]; then
        expiry="$EXPIRY"
        print_debug "Using provided EXPIRY: $expiry" >&2
    else
        expiry=$((current_time + EXPIRY_OFFSET))
    fi
    
    if [ -n "${FILL_DEADLINE:-}" ]; then
        fill_deadline="$FILL_DEADLINE"
        print_debug "Using provided FILL_DEADLINE: $fill_deadline" >&2
    else
        fill_deadline=$((current_time + FILL_DEADLINE_OFFSET))
    fi
    
    print_debug "Nonce: $nonce" >&2
    print_debug "Expiry: $expiry" >&2
    print_debug "Fill deadline: $fill_deadline" >&2
    
    # Build input tokens array
    local input_tokens=$(build_input_tokens "$input_token" "$input_amount")
    
    # Build outputs array
    local zero_bytes32="0x0000000000000000000000000000000000000000000000000000000000000000"
    local output_settler_bytes32="0x000000000000000000000000${output_settler#0x}"
    local output_token_bytes32="0x000000000000000000000000${output_token#0x}"
    local recipient_bytes32="0x000000000000000000000000${recipient#0x}"
    
    local outputs_array="[($zero_bytes32,$output_settler_bytes32,$dest_chain_id,$output_token_bytes32,$output_amount,$recipient_bytes32,0x,0x)]"
    
    # Build StandardOrder
    local order_struct=$(build_standard_order_struct \
        "$user_addr" "$nonce" "$origin_chain_id" "$expiry" "$fill_deadline" \
        "$input_oracle" "$input_tokens" "$outputs_array")
    
    local abi_type='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'
    local order_data=$(cast_abi_encode "$abi_type" "$order_struct")
    
    if [ -z "$order_data" ]; then
        print_error "Failed to encode StandardOrder" >&2
        return 1
    fi
    
    print_debug "StandardOrder encoded: $order_data" >&2
    
    # Compute order ID from the InputSettlerEscrow contract
    print_info "Computing order ID from contract..." >&2
    local origin_rpc=$(config_get_network "$origin_chain_id" "rpc_url")
    if [ -z "$origin_rpc" ]; then
        origin_rpc="http://localhost:8545"
    fi
    
    # Pass the StandardOrder struct directly to orderIdentifier
    local order_identifier_sig="orderIdentifier((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))"
    local order_id=$(cast call "$input_settler" \
        "$order_identifier_sig" \
        "$order_struct" --rpc-url "$origin_rpc")
    
    if [ -z "$order_id" ] || [ "$order_id" = "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
        print_error "Failed to compute order ID from contract" >&2
        return 1
    fi
    
    print_debug "Order ID: $order_id" >&2
    
    # Check if token supports EIP-3009
    local eip3009_selector="0xef55bec6"  # receiveWithAuthorization selector
    local has_eip3009=$(cast call "$input_token" "supportsInterface(bytes4)" "$eip3009_selector" --rpc-url "$origin_rpc" 2>/dev/null || echo "0x0")
    
    if [ "$has_eip3009" != "0x0000000000000000000000000000000000000000000000000000000000000001" ]; then
        print_warning "Token may not support EIP-3009, continuing anyway..." >&2
    fi
    
    # Generate EIP-3009 signature
    print_info "Generating EIP-3009 signature..." >&2
    
    local signature=$(sign_eip3009_order \
        "$user_private_key" "$origin_chain_id" "$input_token" "$input_amount" \
        "$input_settler" "$order_id" "$fill_deadline" "$origin_rpc")
    
    if [ -z "$signature" ]; then
        print_error "Failed to generate EIP-3009 signature" >&2
        return 1
    fi
    
    # Add EIP-3009 prefix to signature
    local prefixed_signature=$(create_prefixed_signature "$signature" "eip3009")
    
    print_success "EIP-3009 intent created" >&2
    print_debug "Order data: $order_data" >&2
    print_debug "Signature: $prefixed_signature" >&2
    
    # Store in global state
    set_intent_status "last_signature" "$prefixed_signature"
    set_intent_status "last_lock_type" "$LOCK_TYPE_EIP3009_ESCROW"
    
    # Return order data and signature as JSON
    if [ -n "${DEBUG_OUTPUT:-}" ]; then
        echo "{\"order\":\"$order_data\",\"signature\":\"$prefixed_signature\",\"lock_type\":$LOCK_TYPE_EIP3009_ESCROW,\"sponsor\":\"$user_addr\",\"_debug\":{\"order_id\":\"$order_id\",\"nonce\":\"$nonce\",\"expiry\":\"$expiry\",\"fill_deadline\":\"$fill_deadline\"}}"
    else
        echo "{\"order\":\"$order_data\",\"signature\":\"$prefixed_signature\",\"lock_type\":$LOCK_TYPE_EIP3009_ESCROW,\"sponsor\":\"$user_addr\"}"
    fi
    return 0
}

# Create compact intent (resource lock-based)
create_compact_intent() {
    local user_addr="$1"
    local user_private_key="$2"
    local origin_chain_id="$3"
    local dest_chain_id="$4"
    local token_id_u256="$5"  # The TOKEN_ID as uint256 (lock_tag + token_address)
    local allocator_lock_tag="$6"  # The 12-byte allocator lock tag
    local lock_amount="$7"
    local output_token="$8"
    local output_amount="$9"
    local recipient="${10}"
    local input_settler_compact="${11}"
    local output_settler="${12}"
    local the_compact_addr="${13}"
    local input_oracle="${14}"
    
    print_info "Creating compact intent (resource lock)" >&2
    print_debug "User: $user_addr" >&2
    print_debug "TOKEN_ID (uint256): $token_id_u256" >&2
    print_debug "Allocator lock tag: $allocator_lock_tag" >&2
    print_debug "Lock amount: $lock_amount" >&2
    print_debug "Output: $output_amount tokens of $output_token on chain $dest_chain_id" >&2
    
    # Generate unique nonce (allow override via NONCE env variable)
    local nonce
    if [ -n "${NONCE:-}" ]; then
        nonce="$NONCE"
        print_debug "Using provided NONCE: $nonce" >&2
    else
        nonce=$(generate_nonce)
    fi
    
    # Calculate deadlines (allow override via environment variables)
    local current_time=$(get_timestamp)
    local expiry
    local fill_deadline
    
    if [ -n "${EXPIRY:-}" ]; then
        expiry="$EXPIRY"
        print_debug "Using provided EXPIRY: $expiry" >&2
    else
        expiry=$((current_time + EXPIRY_OFFSET))
    fi
    
    if [ -n "${FILL_DEADLINE:-}" ]; then
        fill_deadline="$FILL_DEADLINE"
        print_debug "Using provided FILL_DEADLINE: $fill_deadline" >&2
    else
        fill_deadline=$((current_time + FILL_DEADLINE_OFFSET))
    fi
    
    print_debug "Nonce: $nonce" >&2
    print_debug "Expiry: $expiry" >&2
    print_debug "Fill deadline: $fill_deadline" >&2
    
    # Build the ResourceLock structure for input
    # For resource locks, we use the TOKEN_ID which combines lock_tag + token_address
    # This matches what the working script does
    local input_tokens="[[$token_id_u256,$lock_amount]]"
    
    # Build outputs array
    local zero_bytes32="0x0000000000000000000000000000000000000000000000000000000000000000"
    local output_settler_bytes32="0x000000000000000000000000${output_settler#0x}"
    local output_token_bytes32="0x000000000000000000000000${output_token#0x}"
    local recipient_bytes32="0x000000000000000000000000${recipient#0x}"
    
    local outputs_array="[($zero_bytes32,$output_settler_bytes32,$dest_chain_id,$output_token_bytes32,$output_amount,$recipient_bytes32,0x,0x)]"
    
    # Use the oracle passed as parameter
    local compact_oracle="$input_oracle"
    
    # Build StandardOrder
    local order_struct=$(build_standard_order_struct \
        "$user_addr" "$nonce" "$origin_chain_id" "$expiry" "$fill_deadline" \
        "$compact_oracle" "$input_tokens" "$outputs_array")
    
    local abi_type='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'
    local order_data=$(cast_abi_encode "$abi_type" "$order_struct")
    
    if [ -z "$order_data" ]; then
        print_error "Failed to encode StandardOrder for compact intent"
        return 1
    fi
    
    print_debug "StandardOrder encoded: $order_data" >&2
    
    # Generate Compact signature
    print_info "Generating Compact signature..." >&2
    
    # Need to compute the witness hash like the working script does
    # First compute the mandate output hash
    local zero_bytes32="0x0000000000000000000000000000000000000000000000000000000000000000"
    local output_settler_bytes32="0x000000000000000000000000${output_settler#0x}"
    local output_token_bytes32="0x000000000000000000000000${output_token#0x}"
    local recipient_bytes32="0x000000000000000000000000${recipient#0x}"
    
    # Compute MandateOutput hash
    local mandate_output_type_hash=$(cast keccak "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)")
    local empty_bytes_hash="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"  # keccak256("")
    
    local output_hash=$(cast keccak $(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32,bytes32)" \
        "$mandate_output_type_hash" "$zero_bytes32" "$output_settler_bytes32" "$dest_chain_id" \
        "$output_token_bytes32" "$output_amount" "$recipient_bytes32" "$empty_bytes_hash" "$empty_bytes_hash"))
    
    # Compute outputs hash (hash of the single output hash)
    local outputs_hash=$(cast keccak "$output_hash")
    
    # Compute witness hash
    local mandate_type_hash=$(cast keccak "Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)")
    local witness_hash=$(cast keccak $(cast abi-encode "f(bytes32,uint32,address,bytes32)" \
        "$mandate_type_hash" "$fill_deadline" "$input_oracle" "$outputs_hash"))
    
    print_debug "Witness hash: $witness_hash" >&2
    
    # Extract the origin token address from the TOKEN_ID
    # The TOKEN_ID was built as: lock_tag (12 bytes) + token_address (20 bytes)
    # Since we already have allocator_lock_tag, we can reconstruct the token address
    # TOKEN_ID = allocator_lock_tag + origin_token_address
    # We need to extract the token address from the TOKEN_ID
    
    # Use cast to convert to hex (handles large numbers properly)
    local token_id_hex=$(cast to-hex "$token_id_u256")
    # Get the last 40 hex chars (20 bytes) which is the token address
    local origin_token_address="0x${token_id_hex: -40}"
    
    # Call updated sign_compact_order with all required parameters
    local compact_signature=$(sign_compact_order \
        "$user_private_key" "$the_compact_addr" "$origin_chain_id" \
        "$origin_token_address" "$allocator_lock_tag" "$lock_amount" "$nonce" "$expiry" "$user_addr" \
        "$input_settler_compact" "$fill_deadline" "$input_oracle" "$witness_hash")
    
    if [ -z "$compact_signature" ]; then
        print_error "Failed to generate compact signature"
        return 1
    fi
    
    # For compact/resource lock, we need to ABI-encode the signature with allocator data
    # This matches what the working send_offchain_resource_lock_intent.sh script does
    local allocator_data="0x"  # Empty allocator data for demo
    local encoded_signature=$(cast abi-encode "f(bytes,bytes)" "$compact_signature" "$allocator_data")
    
    print_success "Compact intent created" >&2
    print_debug "Order data: $order_data" >&2
    print_debug "Signature (encoded): $encoded_signature" >&2
    
    # Store in global state
    set_intent_status "last_signature" "$encoded_signature"
    set_intent_status "last_lock_type" "$LOCK_TYPE_RESOURCE_LOCK"
    
    # Include debug information if DEBUG_OUTPUT environment variable is set
    if [ -n "${DEBUG_OUTPUT:-}" ]; then
        # Get the final digest that was signed (need to recompute it here for debug)
        local domain_separator=$(cast call "$the_compact_addr" "DOMAIN_SEPARATOR()" --rpc-url "http://localhost:8545" 2>/dev/null)
        local batch_compact_type_hash=$(cast keccak "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)")
        
        # Recompute commitments hash
        local lock_type_hash=$(cast keccak "Lock(bytes12 lockTag,address token,uint256 amount)")
        local lock_hash=$(cast keccak $(cast abi-encode "f(bytes32,bytes12,address,uint256)" \
            "$lock_type_hash" "$allocator_lock_tag" "$origin_token_address" "$lock_amount"))
        local commitments_hash_debug=$(cast keccak "$lock_hash")
        
        # Recompute inner struct and final digest
        local inner_struct_hash=$(cast keccak $(cast abi-encode "f(bytes32,address,address,uint256,uint256,bytes32,bytes32)" \
            "$batch_compact_type_hash" "$input_settler_compact" "$user_addr" "$nonce" "$expiry" "$commitments_hash_debug" "$witness_hash"))
        local final_digest=$(cast keccak "0x1901${domain_separator:2}${inner_struct_hash:2}")
        
        # Return with debug info
        echo "{\"order\":\"$order_data\",\"signature\":\"$encoded_signature\",\"lock_type\":$LOCK_TYPE_RESOURCE_LOCK,\"sponsor\":\"$user_addr\",\"_debug\":{\"witness_hash\":\"$witness_hash\",\"commitments_hash\":\"$commitments_hash_debug\",\"final_digest\":\"$final_digest\",\"sponsor_sig\":\"$compact_signature\",\"domain_separator\":\"$domain_separator\"}}"
    else
        # Return order data and signature as JSON (normal mode)
        echo "{\"order\":\"$order_data\",\"signature\":\"$encoded_signature\",\"lock_type\":$LOCK_TYPE_RESOURCE_LOCK,\"sponsor\":\"$user_addr\"}"
    fi
    return 0
}

# Create onchain intent (direct blockchain submission)
create_onchain_intent() {
    local user_addr="$1"
    local user_private_key="$2"
    local origin_chain_id="$3"
    local dest_chain_id="$4"
    local input_token="$5"
    local input_amount="$6"
    local output_token="$7"
    local output_amount="$8"
    local recipient="$9"
    local input_settler="${10}"
    local output_settler="${11}"
    local input_oracle="${12}"
    
    print_info "Creating onchain intent" >&2
    print_debug "User: $user_addr" >&2
    print_debug "Input: $input_amount tokens of $input_token on chain $origin_chain_id" >&2
    print_debug "Output: $output_amount tokens of $output_token on chain $dest_chain_id" >&2
    print_debug "Recipient: $recipient" >&2
    
    # Generate unique nonce
    local nonce
    if [ -n "${NONCE:-}" ]; then
        nonce="$NONCE"
        print_debug "Using provided NONCE: $nonce" >&2
    else
        nonce=$(generate_nonce)
    fi
    
    # Calculate deadlines
    local current_time=$(get_timestamp)
    local expiry
    local fill_deadline
    
    if [ -n "${EXPIRY:-}" ]; then
        expiry="$EXPIRY"
        print_debug "Using provided EXPIRY: $expiry" >&2
    else
        expiry=$((current_time + EXPIRY_OFFSET))
    fi
    
    if [ -n "${FILL_DEADLINE:-}" ]; then
        fill_deadline="$FILL_DEADLINE"
        print_debug "Using provided FILL_DEADLINE: $fill_deadline" >&2
    else
        fill_deadline=$((current_time + FILL_DEADLINE_OFFSET))
    fi
    
    print_debug "Nonce: $nonce" >&2
    print_debug "Expiry: $expiry" >&2
    print_debug "Fill deadline: $fill_deadline" >&2
    
    # Build input tokens array
    local input_tokens=$(build_input_tokens "$input_token" "$input_amount")
    
    # Build outputs array
    local zero_bytes32="0x0000000000000000000000000000000000000000000000000000000000000000"
    local output_settler_bytes32="0x000000000000000000000000${output_settler#0x}"
    local output_token_bytes32="0x000000000000000000000000${output_token#0x}"
    local recipient_bytes32="0x000000000000000000000000${recipient#0x}"
    
    local outputs_array="[($zero_bytes32,$output_settler_bytes32,$dest_chain_id,$output_token_bytes32,$output_amount,$recipient_bytes32,0x,0x)]"
    
    # Build StandardOrder
    local order_struct=$(build_standard_order_struct \
        "$user_addr" "$nonce" "$origin_chain_id" "$expiry" "$fill_deadline" \
        "$input_oracle" "$input_tokens" "$outputs_array")
    
    local abi_type='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'
    local order_data=$(cast_abi_encode "$abi_type" "$order_struct")
    
    if [ -z "$order_data" ]; then
        print_error "Failed to encode StandardOrder" >&2
        return 1
    fi
    
    print_success "Onchain intent created" >&2
    print_debug "Order data: $order_data" >&2
    print_debug "Order struct: $order_struct" >&2

    # Return order data for onchain submission (signature will be generated at submission time)
    # Include the order_struct so we don't have to decode it later
    echo "{\"order\":\"$order_data\",\"order_struct\":\"$order_struct\",\"sponsor\":\"$user_addr\",\"input_settler\":\"$input_settler\",\"input_token\":\"$input_token\",\"input_amount\":\"$input_amount\"}"
    return 0
}

# Submit intent onchain (direct blockchain call)
submit_intent_onchain() {
    local intent_json="$1"
    local user_private_key="$2"
    local origin_chain_id="$3"
    
    print_info "Submitting intent onchain"
    
    # Parse intent JSON to extract required fields
    local order_data=$(echo "$intent_json" | jq -r '.order')
    local order_struct=$(echo "$intent_json" | jq -r '.order_struct // empty')
    local input_settler=$(echo "$intent_json" | jq -r '.input_settler')
    local input_token=$(echo "$intent_json" | jq -r '.input_token')
    local input_amount=$(echo "$intent_json" | jq -r '.input_amount')
    local sponsor=$(echo "$intent_json" | jq -r '.sponsor')
    
    if [ -z "$order_data" ] || [ "$order_data" = "null" ]; then
        print_error "Missing order data in intent JSON"
        return 1
    fi
    
    # Get RPC URL for origin chain
    local origin_rpc=$(config_get_network "$origin_chain_id" "rpc_url")
    if [ -z "$origin_rpc" ]; then
        origin_rpc="http://localhost:8545"
    fi
    
    print_step "Approving tokens for InputSettler"
    
    # Check user's token balance first
    local user_balance=$(cast call "$input_token" "balanceOf(address)" "$sponsor" --rpc-url "$origin_rpc")
    local user_balance_dec=$(cast to-dec "$user_balance" 2>/dev/null || echo "0")
    
    if [ $(echo "$user_balance_dec < $input_amount" | bc) -eq 1 ]; then
        print_error "Insufficient token balance"
        print_info "User balance: $user_balance_dec"
        print_info "Required: $input_amount"
        return 1
    fi
    
    # Approve InputSettler to spend tokens
    print_debug "Approving InputSettler at $input_settler to spend $input_amount tokens"
    local approve_tx=$(cast send "$input_token" "approve(address,uint256)" "$input_settler" "$input_amount" \
        --rpc-url "$origin_rpc" \
        --private-key "$user_private_key" --json 2>&1)
    
    if [ $? -ne 0 ]; then
        print_error "Failed to approve tokens"
        print_debug "Error: $approve_tx"
        return 1
    fi
    
    # Extract approval tx hash from JSON output
    local approve_hash=""
    approve_hash=$(echo "$approve_tx" | jq -r '.transactionHash // empty' 2>/dev/null)
    
    if [ -n "$approve_hash" ] && [ "$approve_hash" != "null" ]; then
        print_success "Token approval submitted (tx: ${approve_hash:0:10}...)"
    else
        print_warning "Could not extract approval transaction hash"
    fi
    
    print_step "Submitting intent to InputSettler"
    
    # Call InputSettler.open() with the order data
    print_debug "Calling InputSettler.open() with order data"

    # Check if we have the order_struct from the JSON (for new format)
    if [ -n "$order_struct" ] && [ "$order_struct" != "null" ] && [ "$order_struct" != "empty" ]; then
        print_debug "Using saved order struct from intent JSON"
        print_debug "Order struct: $order_struct"
    else
        # Fallback: try to decode from order_data (for backward compatibility)
        print_error "Order struct not found in intent JSON"
        print_info "Please rebuild the intent using the appropriate build command for your intent type."
        return 1
    fi

    # Pass the StandardOrder struct to open
    local open_signature="open((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))"
    local submit_tx=$(cast send "$input_settler" \
        "$open_signature" \
        "$order_struct" \
        --rpc-url "$origin_rpc" \
        --private-key "$user_private_key" \
        --json 2>&1)
    
    if [ $? -ne 0 ]; then
        print_error "Failed to submit intent onchain"
        print_debug "Error: $submit_tx"
        return 1
    fi
    
    # Extract transaction hash from JSON output
    local tx_hash=""
    tx_hash=$(echo "$submit_tx" | jq -r '.transactionHash // empty' 2>/dev/null)
    
    if [ -z "$tx_hash" ] || [ "$tx_hash" = "null" ]; then
        print_error "Could not extract transaction hash from response"
        print_debug "Response: $submit_tx"
        return 1
    fi
    if [ -n "$tx_hash" ]; then
        print_success "Intent submitted onchain successfully"
        print_info "Transaction hash: $tx_hash"
        set_intent_status "last_tx_hash" "$tx_hash"
        
        # Wait for transaction to be mined with timeout and progress
        print_info "Waiting for transaction to be mined..."
        local max_wait=30  # 30 seconds timeout
        local elapsed=0
        local mined=false
        
        # First, let's try a different approach - use eth_getTransactionByHash directly
        while [ $elapsed -lt $max_wait ]; do
            # Show progress every 3 seconds
            if [ $((elapsed % 3)) -eq 0 ] && [ $elapsed -gt 0 ]; then
                print_info "Waiting for transaction to be mined... (${elapsed}s)"
            fi
            
            # Use eth_getTransactionByHash RPC call directly to check if tx is mined
            local tx_json=$(cast rpc eth_getTransactionByHash "$tx_hash" --rpc-url "$origin_rpc" 2>/dev/null || echo "null")
            
            if [ "$tx_json" != "null" ] && [ -n "$tx_json" ]; then
                # Check if transaction has a blockNumber (indicates it's mined)
                local block_number=$(echo "$tx_json" | jq -r '.blockNumber // "null"' 2>/dev/null || echo "null")
                
                if [ "$block_number" != "null" ] && [ "$block_number" != "" ]; then
                    # Convert hex block number to decimal for display
                    local block_dec=$(cast to-dec "$block_number" 2>/dev/null || echo "$block_number")
                    mined=true
                    print_success "Transaction mined in block $block_dec"
                    break
                fi
            fi
            
            sleep 1
            elapsed=$((elapsed + 1))
        done
        
        if [ "$mined" = false ]; then
            print_warning "Transaction mining timeout after ${max_wait}s"
            print_info "Transaction may still be pending: $tx_hash"
            print_info "Check manually with: cast receipt $tx_hash --rpc-url $origin_rpc"
            return 1
        fi
        
        print_success "Transaction mined successfully (took ${elapsed}s)"
        
        # Try to extract the order ID from the transaction receipt
        print_debug "Fetching transaction receipt for order ID"
        local order_id=""
        local receipt=$(cast rpc eth_getTransactionReceipt "$tx_hash" --rpc-url "$origin_rpc" 2>/dev/null || echo "null")
        if [ "$receipt" != "null" ] && [ -n "$receipt" ]; then
            # The Open event signature for new contracts: Open(bytes32 indexed orderId, StandardOrder order)
            # Note: The StandardOrder is not indexed, so it's in the data field, not topics
            local open_event_topic="0x9ff74bd56d00785b881ef9fa3f03d7b598686a39a9bcff89a6008db588b18a7b"
            
            # Extract order ID from the second topic (first indexed parameter)
            order_id=$(echo "$receipt" | jq -r ".logs[] | select(.topics[0] == \"$open_event_topic\") | .topics[1]" 2>/dev/null | head -n1)
            
            if [ -n "$order_id" ] && [ "$order_id" != "null" ]; then
                print_info "Order ID: $order_id"
                set_intent_status "last_order_id" "$order_id"
            else
                print_debug "Could not find order ID in transaction logs"
            fi
        fi
        
        # Determine status based on what we found
        local status="submitted"
        if [ -n "$order_id" ] && [ "$order_id" != "null" ]; then
            # If we got an order ID, the intent was accepted by the contract
            status="accepted"
        elif [ "$mined" = true ]; then
            # Transaction was mined but we couldn't extract order ID
            status="mined"
        fi
        
        # Build response object
        local response_json=$(jq -n \
            --arg tx_hash "$tx_hash" \
            --arg order_id "${order_id:-}" \
            --arg block_number "${block_dec:-}" \
            --arg timestamp "$(get_timestamp)" \
            --arg status "$status" \
            '{
                transaction_hash: $tx_hash,
                order_id: (if $order_id == "" then null else $order_id end),
                block_number: (if $block_number == "" then null else $block_number end),
                timestamp: ($timestamp | tonumber),
                status: $status,
                status_description: (
                    if $status == "accepted" then "Intent accepted by contract and assigned order ID"
                    elif $status == "mined" then "Transaction mined but order ID not found"
                    else "Transaction submitted to blockchain"
                    end
                )
            }')
        
        # Save transaction details to file
        local response_file="${OUTPUT_DIR:-./demo-output}/onchain_intent.tx.json"
        echo "$response_json" > "$response_file"
        print_info "Transaction details saved to: $response_file"
        
        # Print formatted response
        print_separator
        print_info "Onchain Submission Result:"
        echo "$response_json" | jq '.'
        print_separator
    else
        print_error "Failed to extract transaction hash"
        return 1
    fi
    
    return 0
}

# Submit intent to solver API
submit_intent() {
    local intent_json="$1"
    local api_url="${2:-http://localhost:3000/api/orders}"
    local max_retries="${3:-3}"

    print_info "Submitting intent to solver API"
    print_debug "API URL: $api_url"
    print_debug "Intent JSON: $intent_json"

    # Validate intent JSON
    if ! validate_json "$intent_json"; then
        print_error "Invalid intent JSON"
        return 1
    fi

    # Submit with retry - api_post_retry will automatically handle JWT authentication via jwt_ensure_token
    if api_post_retry "$api_url" "$intent_json" "" "$max_retries"; then
        local status_code=$(get_api_response "status_code")
        local response_body=$(get_api_response "body")
        
        print_success "Intent submitted successfully (HTTP $status_code)"
        
        # Save response to file
        local response_file="${OUTPUT_DIR:-./demo-output}/post_intent.res.json"
        echo "$response_body" | jq '.' > "$response_file" 2>/dev/null || echo "$response_body" > "$response_file"
        print_info "Response saved to: $response_file"
        
        # Extract order ID if available
        local order_id=$(parse_json_response '.order_id // .id // empty')
        if [ -n "$order_id" ] && [ "$order_id" != "null" ]; then
            print_info "Order ID: $order_id"
            set_intent_status "last_order_id" "$order_id"
        fi
        
        # Print response
        if echo "$response_body" | jq empty 2>/dev/null; then
            echo "$response_body" | jq '.'
        else
            echo "$response_body"
        fi
        
        return 0
    else
        local error_msg=$(get_api_error_message)
        print_error "Failed to submit intent: $error_msg"
        print_api_response
        return 1
    fi
}

# Submit escrow intent workflow
submit_escrow_intent() {
    local user_addr="$1"
    local user_private_key="$2"
    local origin_chain_id="$3"
    local dest_chain_id="$4"
    local input_token="$5"
    local input_amount="$6"
    local output_token="$7"
    local output_amount="$8"
    local recipient="$9"
    local api_url="${10:-http://localhost:3000/api/orders}"
    
    # Get contract addresses from config
    local input_settler=$(config_get_network "$origin_chain_id" "input_settler_address")
    local output_settler=$(config_get_network "$dest_chain_id" "output_settler_address")
    local input_oracle=$(config_get_oracle "$origin_chain_id" "input")
    
    if [ -z "$input_settler" ] || [ -z "$output_settler" ]; then
        print_error "Required contract addresses not found in config"
        return 1
    fi
    
    print_header "Submitting Escrow Intent"
    
    # Create intent
    local intent_json=$(create_escrow_intent \
        "$user_addr" "$user_private_key" "$origin_chain_id" "$dest_chain_id" \
        "$input_token" "$input_amount" "$output_token" "$output_amount" "$recipient" \
        "$input_settler" "$output_settler" "$input_oracle")
    
    if [ -z "$intent_json" ]; then
        return 1
    fi
    
    # Submit intent
    submit_intent "$intent_json" "$api_url"
}

# Submit compact intent workflow
submit_compact_intent() {
    local user_addr="$1"
    local user_private_key="$2"
    local origin_chain_id="$3"
    local dest_chain_id="$4"
    local token_id_u256="$5"  # The TOKEN_ID as uint256
    local allocator_lock_tag="$6"  # The 12-byte allocator lock tag
    local lock_amount="$7"
    local output_token="$8"
    local output_amount="$9"
    local recipient="${10}"
    local api_url="${11:-http://localhost:3000/api/orders}"
    
    # Get contract addresses from config
    local input_settler_compact=$(config_get_network "$origin_chain_id" "input_settler_compact_address")
    local output_settler=$(config_get_network "$dest_chain_id" "output_settler_address")
    local the_compact_addr=$(config_get_network "$origin_chain_id" "the_compact_address")
    local input_oracle=$(config_get_oracle "$origin_chain_id" "input")
    
    if [ -z "$input_settler_compact" ] || [ -z "$output_settler" ] || [ -z "$the_compact_addr" ]; then
        print_error "Required contract addresses not found in config"
        return 1
    fi
    
    print_header "Submitting Compact Intent"
    
    # Create intent
    local intent_json=$(create_compact_intent \
        "$user_addr" "$user_private_key" "$origin_chain_id" "$dest_chain_id" \
        "$token_id_u256" "$allocator_lock_tag" "$lock_amount" \
        "$output_token" "$output_amount" "$recipient" \
        "$input_settler_compact" "$output_settler" "$the_compact_addr" "$input_oracle")
    
    if [ -z "$intent_json" ]; then
        return 1
    fi
    
    # Submit intent
    submit_intent "$intent_json" "$api_url"
}

# Monitor intent status
monitor_intent() {
    local order_id="${1:-$(get_intent_status last_order_id)}"
    local api_url="${2:-http://localhost:3000}"
    local timeout="${3:-120}"
    
    if [ -z "$order_id" ]; then
        print_error "No order ID provided or found in status"
        return 1
    fi
    
    print_info "Monitoring intent: $order_id"
    
    local status_url="$api_url/api/orders/$order_id"
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if api_get "$status_url"; then
            # The API returns status at .order.status
            local status=$(parse_json_response '.order.status // .status // "unknown"')
            local tx_hash=$(parse_json_response '.order.fillTransaction.hash // .transactionHash // empty')
            
            print_info "Status: $status"
            
            if [ -n "$tx_hash" ] && [ "$tx_hash" != "null" ]; then
                print_info "Transaction: $tx_hash"
                set_intent_status "last_tx_hash" "$tx_hash"
            fi
            
            # Convert status to lowercase for consistent matching
            local status_lower=$(echo "$status" | tr '[:upper:]' '[:lower:]')
            
            case "$status_lower" in
                "finalized")
                    print_success "Order finalized - complete!"
                    return 0
                    ;;
                "settled"|"postfilled"|"preclaimed")
                    print_info "Order near completion: $status"
                    ;;
                "executed")
                    print_debug "Order executed - awaiting settlement..."
                    ;;
                "executing")
                    print_debug "Order executing..."
                    ;;
                "pending")
                    print_debug "Order pending..."
                    ;;
                "created")
                    print_debug "Order created..."
                    ;;
                "failed"*)
                    print_error "Order failed: $status"
                    return 1
                    ;;
                *)
                    print_debug "Order status: $status"
                    ;;
            esac
        else
            print_warning "Failed to query intent status"
        fi
        
        sleep 5
        elapsed=$((elapsed + 5))
    done
    
    print_warning "Intent monitoring timed out after ${timeout}s"
    return 1
}

# Show intent summary
show_intent_summary() {
    local order_id=$(get_intent_status "last_order_id")
    local tx_hash=$(get_intent_status "last_tx_hash")
    local signature=$(get_intent_status "last_signature")
    local lock_type=$(get_intent_status "last_lock_type")
    
    print_header "Intent Summary"
    
    if [ -n "$order_id" ]; then
        print_info "Order ID: $order_id"
    fi
    
    if [ -n "$lock_type" ]; then
        case "$lock_type" in
            "$LOCK_TYPE_PERMIT2_ESCROW")
                print_info "Type: Permit2 Escrow"
                ;;
            "$LOCK_TYPE_EIP3009_ESCROW")
                print_info "Type: EIP-3009 Escrow"
                ;;
            "$LOCK_TYPE_RESOURCE_LOCK")
                print_info "Type: Resource Lock (Compact)"
                ;;
            *)
                print_info "Type: Unknown ($lock_type)"
                ;;
        esac
    fi
    
    if [ -n "$signature" ]; then
        print_info "Signature: ${signature:0:20}..."
    fi
    
    if [ -n "$tx_hash" ]; then
        print_info "Transaction: $tx_hash"
    fi
    
    print_separator
}

# Command line interface functions
intent_build() {
    local onchain_mode=false
    local intent_type=""
    local lock_type=""
    local origin_chain=""
    local dest_chain=""
    local token_in=""
    local token_out=""
    local amount_in="1000000000000000000" # 1 token default
    local amount_out="1000000000000000000" # 1 token default
    
    # Parse arguments to detect --onchain flag
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --onchain)
                onchain_mode=true
                shift
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done
    
    # Now parse positional arguments from args array
    if [ "$onchain_mode" = true ]; then
        # For onchain: <intent_type> <origin_chain> <dest_chain> <token_in> <token_out> [amount_in] [amount_out]
        intent_type="${args[0]:-escrow}"
        origin_chain="${args[1]:-31337}"
        dest_chain="${args[2]:-31338}"
        token_in="${args[3]:-}"
        token_out="${args[4]:-}"
        [ ${#args[@]} -gt 5 ] && amount_in="${args[5]}"
        [ ${#args[@]} -gt 6 ] && amount_out="${args[6]}"
        
        # Validate onchain only works with escrow
        if [ "$intent_type" != "escrow" ]; then
            print_error "Onchain submission only supports escrow intent type"
            print_info "Usage: intent_build --onchain escrow <origin_chain> <dest_chain> <token_in> <token_out> [amount_in] [amount_out]"
            return 1
        fi
    else
        # For offchain: <intent_type> <lock_type> <origin_chain> <dest_chain> <token_in> <token_out> [amount_in] [amount_out]
        intent_type="${args[0]:-escrow}"
        lock_type="${args[1]:-permit2}"
        origin_chain="${args[2]:-31337}"
        dest_chain="${args[3]:-31338}"
        token_in="${args[4]:-}"
        token_out="${args[5]:-}"
        [ ${#args[@]} -gt 6 ] && amount_in="${args[6]}"
        [ ${#args[@]} -gt 7 ] && amount_out="${args[7]}"
    fi
    
    # Validate required parameters
    if [ -z "$token_in" ] || [ -z "$token_out" ]; then
        if [ "$onchain_mode" = true ]; then
            print_error "Usage: intent_build --onchain escrow <origin_chain> <dest_chain> <token_in> <token_out> [amount_in] [amount_out]"
        else
            print_error "Usage: intent_build <escrow|compact> <permit2|eip3009> <origin_chain> <dest_chain> <token_in> <token_out> [amount_in] [amount_out]"
        fi
        return 1
    fi
    
    # Resolve token symbols to addresses if needed
    # Handle common aliases
    case "$token_in" in
        TokenA) token_in="TOKA" ;;
        TokenB) token_in="TOKB" ;;
    esac
    
    case "$token_out" in
        TokenA) token_out="TOKA" ;;
        TokenB) token_out="TOKB" ;;
    esac
    
    # Check if token_in is a symbol (not an address starting with 0x)
    if [[ ! "$token_in" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        local resolved_token_in=$(config_get_token_by_symbol "$origin_chain" "$token_in")
        if [ -z "$resolved_token_in" ]; then
            print_error "Unknown token symbol '$token_in' on chain $origin_chain"
            return 1
        fi
        print_debug "Resolved $token_in to $resolved_token_in on chain $origin_chain"
        token_in="$resolved_token_in"
    fi
    
    # Check if token_out is a symbol (not an address starting with 0x)
    if [[ ! "$token_out" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        local resolved_token_out=$(config_get_token_by_symbol "$dest_chain" "$token_out")
        if [ -z "$resolved_token_out" ]; then
            print_error "Unknown token symbol '$token_out' on chain $dest_chain"
            return 1
        fi
        print_debug "Resolved $token_out to $resolved_token_out on chain $dest_chain"
        token_out="$resolved_token_out"
    fi
    
    # Get account addresses from config or environment variables
    local user_addr=$(config_get_account "user" "address")
    local user_key=$(config_get_account "user" "private_key") 
    local recipient_addr=$(config_get_account "recipient" "address")
    
    # Fall back to environment variables if config doesn't have values
    if [ -z "$user_addr" ] && [ -n "${USER_ADDRESS:-}" ]; then
        user_addr="$USER_ADDRESS"
    fi
    if [ -z "$user_key" ] && [ -n "${USER_PRIVATE_KEY:-}" ]; then
        user_key="$USER_PRIVATE_KEY"
    fi
    if [ -z "$recipient_addr" ] && [ -n "${RECIPIENT_ADDRESS:-}" ]; then
        recipient_addr="$RECIPIENT_ADDRESS"
    fi
    
    # Validate required account information
    if [ -z "$user_addr" ]; then
        print_error "User address not configured. Set USER_ADDRESS environment variable or run 'oif-demo init <config-file>'"
        return 1
    fi
    
    if [ -z "$user_key" ]; then
        print_error "User private key not configured. Set USER_PRIVATE_KEY environment variable or run 'oif-demo init <config-file>'"
        return 1
    fi
    
    if [ -z "$recipient_addr" ]; then
        print_error "Recipient address not configured. Set RECIPIENT_ADDRESS environment variable or run 'oif-demo init <config-file>'"
        return 1
    fi
    
    if [ "$onchain_mode" = true ]; then
        print_info "Building $intent_type intent for onchain submission"
    else
        print_info "Building $intent_type intent with $lock_type auth type"
    fi
    print_info "From chain $origin_chain to chain $dest_chain"
    print_info "Input: $amount_in wei of $token_in"
    print_info "Output: $amount_out wei of $token_out"
    print_info "User: $user_addr"
    print_info "Recipient: $recipient_addr"
    
    # Get required contract addresses from config
    local input_settler=$(config_get_network "$origin_chain" "input_settler_address")
    local output_settler=$(config_get_network "$dest_chain" "output_settler_address")
    
    # Handle onchain mode separately
    if [ "$onchain_mode" = true ]; then
        # Validate required contract addresses for onchain
        if [ -z "$input_settler" ]; then
            print_error "Input settler address not configured for chain $origin_chain"
            print_info "Run 'oif-demo env up' to deploy contracts and generate config"
            return 1
        fi
        if [ -z "$output_settler" ]; then
            print_error "Output settler address not configured for chain $dest_chain"
            print_info "Run 'oif-demo env up' to deploy contracts and generate config"
            return 1
        fi
        
        # Get oracle address from settlement configuration
        local oracle=$(config_get_oracle "$origin_chain" "input")
        intent_json=$(create_onchain_intent "$user_addr" "$user_key" "$origin_chain" "$dest_chain" \
                           "$token_in" "$amount_in" "$token_out" "$amount_out" \
                           "$recipient_addr" "$input_settler" "$output_settler" "$oracle")
    else
        case "$intent_type" in
            escrow)
                case "$lock_type" in
                permit2)
                    # Validate required contract addresses for escrow
                    if [ -z "$input_settler" ]; then
                        print_error "Input settler address not configured for chain $origin_chain"
                        print_info "Run 'oif-demo env up' to deploy contracts and generate config"
                        return 1
                    fi
                    if [ -z "$output_settler" ]; then
                        print_error "Output settler address not configured for chain $dest_chain"
                        print_info "Run 'oif-demo env up' to deploy contracts and generate config"
                        return 1
                    fi
                    
                    # Get oracle address from settlement configuration
                    local oracle=$(config_get_oracle "$origin_chain" "input")
                    intent_json=$(create_escrow_intent "$user_addr" "$user_key" "$origin_chain" "$dest_chain" \
                                       "$token_in" "$amount_in" "$token_out" "$amount_out" \
                                       "$recipient_addr" "$input_settler" "$output_settler" "$oracle")
                    ;;
                eip3009)
                    # Validate required contract addresses for EIP-3009
                    if [ -z "$input_settler" ]; then
                        print_error "Input settler address not configured for chain $origin_chain"
                        print_info "Run 'oif-demo env up' to deploy contracts and generate config"
                        return 1
                    fi
                    if [ -z "$output_settler" ]; then
                        print_error "Output settler address not configured for chain $dest_chain"
                        print_info "Run 'oif-demo env up' to deploy contracts and generate config"
                        return 1
                    fi
                    
                    # Get oracle address from settlement configuration
                    local oracle=$(config_get_oracle "$origin_chain" "input")
                    intent_json=$(create_eip3009_intent "$user_addr" "$user_key" "$origin_chain" "$dest_chain" \
                                       "$token_in" "$amount_in" "$token_out" "$amount_out" \
                                       "$recipient_addr" "$input_settler" "$output_settler" "$oracle")
                    ;;
                *)
                    print_error "Unsupported lock type for escrow: $lock_type"
                    print_info "Supported lock types: permit2, eip3009"
                    return 1
                    ;;
            esac
            ;;
        compact)
            # Validate lock_type for compact - only permit2 is supported
            if [ "$lock_type" != "permit2" ]; then
                print_error "Compact does not support $lock_type lock type"
                print_info "Compact only supports permit2 for resource locks"
                print_info "EIP-3009 is only supported with escrow intents"
                return 1
            fi
            
            # Get compact-specific addresses
            local the_compact=$(config_get_network "$origin_chain" "the_compact_address")
            local input_settler_compact=$(config_get_network "$origin_chain" "input_settler_compact_address")
            local output_settler=$(config_get_network "$dest_chain" "output_settler_address")
            local oracle=$(config_get_oracle "$origin_chain" "input")
            
            # Validate required contract addresses for compact
            if [ -z "$the_compact" ]; then
                print_error "TheCompact address not configured for chain $origin_chain"
                print_info "Run 'oif-demo env up' to deploy contracts and generate config"
                return 1
            fi
            if [ -z "$input_settler_compact" ]; then
                print_error "Input settler compact address not configured for chain $origin_chain"
                print_info "Run 'oif-demo env up' to deploy contracts and generate config"
                return 1
            fi
            if [ -z "$output_settler" ]; then
                print_error "Output settler address not configured for chain $dest_chain"
                print_info "Run 'oif-demo env up' to deploy contracts and generate config"
                return 1
            fi
            
            # Get allocator address from network config
            local allocator_address=$(config_get_network "$origin_chain" "allocator_address")
            if [ -z "$allocator_address" ]; then
                print_error "Allocator address not found for chain $origin_chain"
                print_info "Run 'oif-demo env up' to deploy contracts and generate config"
                return 1
            fi
            
            # Generate allocator lock tag from allocator address
            # Lock tag = 0x00 + last 11 bytes of allocator address
            # Address format: 0x + 40 hex chars (20 bytes)
            # We want last 11 bytes = last 22 hex chars
            # Position: 0x (2 chars) + first 18 hex chars = 20, so start at position 21
            local allocator_lock_tag="0x00$(echo $allocator_address | cut -c21- | tr '[:upper:]' '[:lower:]')"
            print_debug "Generated allocator lock tag: $allocator_lock_tag from address: $allocator_address"
            
            # Get RPC URL for origin chain
            local origin_rpc=$(config_get_network "$origin_chain" "rpc_url")
            if [ -z "$origin_rpc" ]; then
                origin_rpc="http://localhost:8545"
            fi
            
            # Always deposit tokens to get a fresh TOKEN_ID
            print_info "Depositing tokens to TheCompact..."
            
            local token_id_hex=""
            local token_id_u256=""
            
            # Check user's token balance first
            local user_balance=$(cast call "$token_in" "balanceOf(address)" "$user_addr" --rpc-url "$origin_rpc")
            local user_balance_dec=$(cast to-dec "$user_balance" 2>/dev/null || echo "0")
            
            if [ $(echo "$user_balance_dec < $amount_in" | bc) -eq 1 ]; then
                print_error "Insufficient token balance for user"
                print_info "User balance: $user_balance_dec"
                print_info "Required: $amount_in"
                return 1
            fi
            
            # Approve TheCompact to spend user tokens
            print_debug "Approving TheCompact to spend tokens..."
            cast send "$token_in" "approve(address,uint256)" "$the_compact" "$amount_in" \
                --rpc-url "$origin_rpc" \
                --private-key "$user_key" > /dev/null
            
            # Deposit tokens to TheCompact using depositERC20
            print_debug "Depositing $amount_in tokens to TheCompact..."
            local deposit_tx=$(cast send "$the_compact" "depositERC20(address,bytes12,uint256,address)" \
                "$token_in" "$allocator_lock_tag" "$amount_in" "$user_addr" \
                --rpc-url "$origin_rpc" \
                --private-key "$user_key" 2>&1)
            
            if [ $? -ne 0 ]; then
                print_error "Failed to deposit tokens to TheCompact"
                print_debug "Error: $deposit_tx"
                return 1
            fi
            
            # Extract transaction hash for logging
            local tx_hash=$(echo "$deposit_tx" | grep -Eo '0x[0-9a-fA-F]{64}' | head -n1)
            if [ -n "$tx_hash" ]; then
                print_success "Tokens deposited successfully (tx: ${tx_hash:0:10}...)"
            fi
            
            # Compute TOKEN_ID from allocator lock tag and token address
            # TOKEN_ID = lock_tag (12 bytes) + token_address (20 bytes)
            token_id_hex="0x$(echo $allocator_lock_tag | cut -c3-)$(echo $token_in | cut -c3-)"
            token_id_u256=$(cast to-dec "$token_id_hex")
            print_success "TOKEN_ID: $token_id_hex"
            
            print_debug "Allocator lock tag: $allocator_lock_tag"
            print_debug "TOKEN_ID (hex): $token_id_hex"
            print_debug "TOKEN_ID (uint256): $token_id_u256"
            
            intent_json=$(create_compact_intent "$user_addr" "$user_key" "$origin_chain" "$dest_chain" \
                               "$token_id_u256" "$allocator_lock_tag" "$amount_in" "$token_out" "$amount_out" \
                               "$recipient_addr" "$input_settler_compact" "$output_settler" "$the_compact" "$oracle")
            ;;
        *)
            print_error "Unknown intent type: $intent_type"
            print_info "Supported types: escrow, compact"
            return 1
            ;;
    esac
    fi  # End of onchain_mode check
    
    # Save intent to file
    if [ -n "$intent_json" ]; then
        # Save submission format
        local output_file="${OUTPUT_DIR:-./demo-output}/post_intent.req.json"
        echo "$intent_json" > "$output_file"
        print_success "Intent saved to: $output_file (for submission)"
        
        # Also create quote request format
        local quote_file="${OUTPUT_DIR:-./demo-output}/get_quote.req.json"
        
        # Build UII addresses for quote format (using to_uii_address function)
        local user_uii=$(to_uii_address "$origin_chain" "$user_addr")
        local input_asset_uii=$(to_uii_address "$origin_chain" "$token_in")
        local output_asset_uii=$(to_uii_address "$dest_chain" "$token_out")
        local recipient_uii=$(to_uii_address "$dest_chain" "$recipient_addr")
        
        # Create quote request JSON (matching API expected format)
        local quote_request=$(jq -n \
            --arg user "$user_uii" \
            --arg input_user "$user_uii" \
            --arg input_asset "$input_asset_uii" \
            --arg input_amount "$amount_in" \
            --arg output_receiver "$recipient_uii" \
            --arg output_asset "$output_asset_uii" \
            --arg output_amount "$amount_out" \
            '{
                user: $user,
                availableInputs: [
                    {
                        user: $input_user,
                        asset: $input_asset,
                        amount: $input_amount
                    }
                ],
                requestedOutputs: [
                    {
                        receiver: $output_receiver,
                        asset: $output_asset,
                        amount: $output_amount
                    }
                ]
            }')
        
        echo "$quote_request" | jq '.' > "$quote_file"
        print_success "Quote request saved to: $quote_file (for quotes)"
        
        print_separator
        print_info "Next steps:"
        print_info "  • Submit intent: oif-demo intent submit $output_file"
        print_info "  • Get quote: oif-demo quote get $quote_file"
    else
        print_error "Failed to generate intent"
        return 1
    fi
}

intent_submit() {
    local onchain_mode=false
    local intent_file=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --onchain)
                onchain_mode=true
                shift
                ;;
            *)
                intent_file="$1"
                shift
                ;;
        esac
    done
    
    # Use default file if not specified
    if [ -z "$intent_file" ]; then
        intent_file="${OUTPUT_DIR:-./demo-output}/post_intent.req.json"
    fi
    
    if [ ! -f "$intent_file" ]; then
        print_error "Intent file not found: $intent_file"
        return 1
    fi
    
    # Read the JSON content from the file
    local intent_json=$(cat "$intent_file")
    
    if [ -z "$intent_json" ]; then
        print_error "Intent file is empty: $intent_file"
        return 1
    fi
    
    if [ "$onchain_mode" = true ]; then
        print_info "Submitting intent onchain from: $intent_file"
        
        # For onchain submission, we need user private key and chain info
        local user_key=$(config_get_account "user" "private_key")
        if [ -z "$user_key" ] && [ -n "${USER_PRIVATE_KEY:-}" ]; then
            user_key="$USER_PRIVATE_KEY"
        fi
        
        if [ -z "$user_key" ]; then
            print_error "User private key not configured for onchain submission"
            print_info "Set USER_PRIVATE_KEY environment variable or run 'oif-demo init <config-file>'"
            return 1
        fi
        
        # Default to origin chain 31337 if not specified
        local origin_chain="${ORIGIN_CHAIN_ID:-31337}"
        
        submit_intent_onchain "$intent_json" "$user_key" "$origin_chain"
    else
        print_info "Submitting intent offchain from: $intent_file"
        submit_intent "$intent_json"
    fi
}

intent_test() {
    local onchain_mode=false
    local lock_type=""
    local auth_type=""
    local token_pair=""
    
    # Parse arguments to detect --onchain flag
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --onchain)
                onchain_mode=true
                shift
                ;;
            *)
                if [ -z "$lock_type" ]; then
                    lock_type="$1"
                elif [ -z "$auth_type" ] && [ "$onchain_mode" = false ]; then
                    auth_type="$1"
                elif [ -z "$token_pair" ]; then
                    token_pair="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Set defaults
    lock_type="${lock_type:-escrow}"
    token_pair="${token_pair:-A2B}"
    
    # For onchain mode, auth_type is not needed
    if [ "$onchain_mode" = true ]; then
        if [ -n "$auth_type" ] && [ "$auth_type" != "" ]; then
            # If auth_type was provided with --onchain, treat it as token_pair
            if [ -z "$token_pair" ] || [ "$token_pair" = "A2B" ]; then
                token_pair="$auth_type"
            fi
            auth_type=""
        fi
        
        # Validate that onchain only works with escrow
        if [ "$lock_type" != "escrow" ]; then
            print_error "Onchain submission only supports escrow lock type"
            print_info "Usage: intent test --onchain escrow <A2A|A2B|B2A|B2B>"
            return 1
        fi
    else
        # Offchain mode - auth_type is required
        auth_type="${auth_type:-permit2}"
        
        # Validate lock type
        if [[ "$lock_type" != "escrow" && "$lock_type" != "compact" ]]; then
            print_error "Invalid lock type: $lock_type"
            print_info "Usage: intent test <escrow|compact> <permit2|eip3009> <A2A|A2B|B2A|B2B>"
            return 1
        fi
        
        # Validate auth type and combinations
        if [[ "$lock_type" == "compact" && "$auth_type" == "eip3009" ]]; then
            print_error "Compact lock type does not support EIP-3009 auth"
            print_info "Compact only supports permit2 auth"
            print_info "Usage: intent test compact permit2 <A2A|A2B|B2A|B2B>"
            return 1
        fi
        
        if [[ "$auth_type" != "permit2" && "$auth_type" != "eip3009" ]]; then
            print_error "Invalid auth type: $auth_type"
            print_info "Supported auth types: permit2, eip3009 (eip3009 only for escrow)"
            print_info "Usage: intent test <escrow|compact> <permit2|eip3009> <A2A|A2B|B2A|B2B>"
            return 1
        fi
    fi
    
    # Parse token pair
    local from_token=""
    local to_token=""
    local origin_chain=""
    local dest_chain=""
    
    case "$token_pair" in
        A2A)
            from_token="TOKA"
            to_token="TOKA"
            origin_chain="31337"
            dest_chain="31338"
            ;;
        A2B)
            from_token="TOKA"
            to_token="TOKB"
            origin_chain="31337"
            dest_chain="31338"
            ;;
        B2A)
            from_token="TOKB"
            to_token="TOKA"
            origin_chain="31337"
            dest_chain="31338"
            ;;
        B2B)
            from_token="TOKB"
            to_token="TOKB"
            origin_chain="31337"
            dest_chain="31338"
            ;;
        *)
            print_error "Invalid token pair: $token_pair"
            print_info "Valid options: A2A, A2B, B2A, B2B"
            return 1
            ;;
    esac
    
    if [ "$onchain_mode" = true ]; then
        print_header "Testing ${lock_type} intent with onchain submission: ${from_token} → ${to_token}"
        
        # Step 1: Build onchain intent
        print_step "Building ${lock_type} intent for onchain submission"
        
        if ! intent_build --onchain "$lock_type" "$origin_chain" "$dest_chain" "$from_token" "$to_token"; then
            print_error "Failed to build ${lock_type} intent for onchain submission"
            return 1
        fi
        
        print_success "Intent built successfully"
        
        # Step 2: Submit intent onchain
        print_step "Submitting intent onchain"
        local intent_file="${OUTPUT_DIR:-./demo-output}/post_intent.req.json"
        
        if [ ! -f "$intent_file" ]; then
            print_error "Intent file not found: $intent_file"
            return 1
        fi
        
        if ! intent_submit --onchain "$intent_file"; then
            print_error "Failed to submit intent onchain"
            return 1
        fi
        
        print_success "Onchain intent test completed: ${lock_type} ${token_pair}"
    else
        print_header "Testing ${lock_type} intent with ${auth_type} auth: ${from_token} → ${to_token}"
        
        # Step 1: Build intent
        print_step "Building ${lock_type} intent with ${auth_type} auth"
        
        if ! intent_build "$lock_type" "$auth_type" "$origin_chain" "$dest_chain" "$from_token" "$to_token"; then
            print_error "Failed to build ${lock_type} intent with ${auth_type} auth"
            return 1
        fi
        
        print_success "Intent built successfully"
        
        # Step 2: Submit intent
        print_step "Submitting intent"
        local intent_file="${OUTPUT_DIR:-./demo-output}/post_intent.req.json"
        
        if [ ! -f "$intent_file" ]; then
            print_error "Intent file not found: $intent_file"
            return 1
        fi
        
        if ! intent_submit "$intent_file"; then
            print_error "Failed to submit intent"
            return 1
        fi
        
        print_success "Intent test completed: ${lock_type} ${token_pair}"
    fi
    
    # Show summary
    local order_id=$(get_intent_status "last_order_id")
    if [ -n "$order_id" ] && [ "$order_id" != "" ]; then
        print_info "Order ID: $order_id"
    fi
    
    return 0
}

# Export functions
export -f clear_intent_status
export -f get_intent_status
export -f set_intent_status
export -f build_mandate_output
export -f build_input_tokens
export -f build_standard_order_struct
export -f create_escrow_intent
export -f create_eip3009_intent
export -f create_compact_intent
export -f submit_intent
export -f submit_escrow_intent
export -f submit_compact_intent
export -f monitor_intent
export -f show_intent_summary
export -f intent_build
export -f intent_submit
export -f intent_test