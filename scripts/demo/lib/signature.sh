#!/usr/bin/env bash
#
# ==============================================================================
# Signature Module - EIP-712 Structured Data Signing
# ==============================================================================
#
# This module implements EIP-712 structured data signing for cross-chain intents,
# supporting both Permit2 and Compact (ResourceLock) authorization mechanisms.
#
# Key Features:
# - EIP-712 domain separator computation
# - Permit2 witness signing with MandateOutput structures
# - Compact/ResourceLock signing with allocator support
# - Type hash generation for complex structures
# - Signature generation using cast wallet
#
# Signing Flows:
# 1. Permit2: Standard EIP-712 signing with witness data
#    - PermitBatchWitnessTransferFrom structure
#    - MandateOutput[] witness array
#    - TokenPermissions for input tokens
#
# 2. Compact: ResourceLock-based signing
#    - BatchCompactAllocation structure
#    - Allocator-based resource management
#    - Lock ID generation
#
# Type Structures:
# - MandateOutput: Cross-chain execution instructions
# - TokenPermissions: Token transfer authorizations
# - CompactAllocation: Resource lock specifications
#
# Dependencies:
# - cast: For keccak hashing and signature generation
# - Common utilities for address manipulation
#
# Usage:
#   sign_standard_intent $private_key $chain_id $token $amount ...
#   sign_compact_intent $private_key $allocator $lock_id ...
#
# ==============================================================================

# -----------------------------------------------------------------------------
# Domain Separator Functions
# -----------------------------------------------------------------------------
# Standard EIP-712 domain separator computation
compute_domain_separator() {
    local name="$1"
    local version="${2:-1}"
    local chain_id="$3"
    local verifying_contract="$4"
    
    local domain_type_hash=$(cast_keccak "EIP712Domain(string name,uint256 chainId,address verifyingContract)")
    local name_hash=$(cast_keccak "$name")
    local version_hash=$(cast_keccak "$version")
    
    local domain_separator=$(cast_abi_encode "f(bytes32,bytes32,uint256,address)" \
        "$domain_type_hash" "$name_hash" "$chain_id" "$verifying_contract")
    
    cast_keccak "$domain_separator"
}

# Permit2 domain separator (standard for all chains)
get_permit2_domain_separator() {
    local chain_id="$1"
    local permit2_address="${2:-0x000000000022D473030F116dDEE9F6B43aC78BA3}"
    
    # Permit2 uses a simpler domain separator without version
    local domain_type_hash=$(cast_keccak "EIP712Domain(string name,uint256 chainId,address verifyingContract)")
    local name_hash=$(cast_keccak "Permit2")
    
    local domain_separator=$(cast_abi_encode "f(bytes32,bytes32,uint256,address)" \
        "$domain_type_hash" "$name_hash" "$chain_id" "$permit2_address")
    
    cast_keccak "$domain_separator"
}

# EIP-712 type hash computation
compute_type_hash() {
    local type_string="$1"
    cast_keccak "$type_string"
}

# Standard Permit2 type definitions
get_permit2_types() {
    echo "TokenPermissions(address token,uint256 amount)"
    echo "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)"
    echo "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)"
    
    # With witness types
    echo "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
    echo "Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)"
    echo "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)"
    echo "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)"
}

# Hash array of structs (for dynamic arrays)
hash_struct_array() {
    local type_hash="$1"
    shift
    local elements=("$@")
    
    if [ ${#elements[@]} -eq 0 ]; then
        # Empty array hash
        cast_keccak "0x"
        return
    fi
    
    local concatenated=""
    for element in "${elements[@]}"; do
        concatenated="${concatenated}${element#0x}"
    done
    
    cast_keccak "0x${concatenated}"
}

# Compute MandateOutput struct hash
compute_mandate_output_hash() {
    local oracle="$1"
    local settler="$2"
    local chain_id="$3"
    local token="$4"
    local amount="$5"
    local recipient="$6"
    local call_data_hash="${7:-0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470}"  # keccak256("")
    local context_data_hash="${8:-0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470}"  # keccak256("")
    
    local type_hash=$(compute_type_hash "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)")
    
    local encoded=$(cast_abi_encode "f(bytes32,bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32,bytes32)" \
        "$type_hash" "$oracle" "$settler" "$chain_id" "$token" "$amount" "$recipient" "$call_data_hash" "$context_data_hash")
    
    cast_keccak "$encoded"
}

# Compute Permit2Witness struct hash
compute_permit2_witness_hash() {
    local expires="$1"
    local input_oracle="$2"
    shift 2
    local output_hashes=("$@")
    
    # The type hash must include the MandateOutput type definition
    local mandate_output_type="MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
    local witness_type="Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)${mandate_output_type}"
    local type_hash=$(compute_type_hash "$witness_type")
    local outputs_hash=$(hash_struct_array "" "${output_hashes[@]}")
    
    print_debug "Witness encode params: type_hash=$type_hash, expires=$expires, oracle=$input_oracle, outputs_hash=$outputs_hash"
    local encoded=$(cast_abi_encode "f(bytes32,uint32,address,bytes32)" \
        "$type_hash" "$expires" "$input_oracle" "$outputs_hash")
    print_debug "Witness encoded: $encoded"
    
    cast_keccak "$encoded"
}

# Compute TokenPermissions struct hash
compute_token_permissions_hash() {
    local token="$1"
    local amount="$2"
    
    local type_hash=$(compute_type_hash "TokenPermissions(address token,uint256 amount)")
    
    local encoded=$(cast_abi_encode "f(bytes32,address,uint256)" \
        "$type_hash" "$token" "$amount")
    
    cast_keccak "$encoded"
}

# Generate Permit2 signature for standard order
sign_permit2_order() {
    local user_private_key="$1"
    local chain_id="$2"
    local token_address="$3"
    local amount="$4"
    local spender="$5"
    local nonce="$6"
    local deadline="$7"
    local expires="$8"
    local input_oracle="$9"
    shift 9
    local mandate_outputs=("$@")
    
    print_debug "Signing Permit2 order with witness"
    print_debug "Chain ID: $chain_id"
    print_debug "Token: $token_address"
    print_debug "Amount: $amount"
    print_debug "Spender: $spender"
    print_debug "Nonce: $nonce"
    print_debug "Deadline: $deadline"
    print_debug "Expires: $expires"
    print_debug "Input Oracle: $input_oracle"
    
    # Get domain separator
    local domain_separator=$(get_permit2_domain_separator "$chain_id")
    print_debug "Domain separator: $domain_separator"
    
    # Compute TokenPermissions hash
    local token_perm_hash=$(compute_token_permissions_hash "$token_address" "$amount")
    local permitted_array_hash=$(cast_keccak "$token_perm_hash")
    print_debug "Token permissions hash: $token_perm_hash"
    print_debug "Permitted array hash: $permitted_array_hash"
    
    # Compute MandateOutput hashes
    local output_hashes=()
    for output in "${mandate_outputs[@]}"; do
        # Parse mandate output: oracle,settler,chainId,token,amount,recipient
        IFS=',' read -ra output_parts <<< "$output"
        # Oracle field is always zeros for outputs (not the input oracle)
        local oracle="0x0000000000000000000000000000000000000000000000000000000000000000"
        local settler="${output_parts[1]}"
        local dest_chain_id="${output_parts[2]}"
        local dest_token="${output_parts[3]}"
        local dest_amount="${output_parts[4]}"
        local dest_recipient="${output_parts[5]}"
        
        print_debug "MandateOutput params: oracle=$oracle, settler=$settler, chain=$dest_chain_id, token=$dest_token, amount=$dest_amount, recipient=$dest_recipient"
        local output_hash=$(compute_mandate_output_hash "$oracle" "$settler" "$dest_chain_id" \
            "$dest_token" "$dest_amount" "$dest_recipient")
        output_hashes+=("$output_hash")
        print_debug "MandateOutput hash: $output_hash"
    done
    
    # Compute Permit2Witness hash
    local witness_hash=$(compute_permit2_witness_hash "$expires" "$input_oracle" "${output_hashes[@]}")
    print_debug "Witness hash: $witness_hash"
    
    # Build the main struct hash for signing
    local mandate_output_type="MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
    local token_permissions_type="TokenPermissions(address token,uint256 amount)"
    
    # The witness type string concatenation must match exactly - do NOT include the full Permit2Witness definition twice
    local witness_type_string="Permit2Witness witness)${mandate_output_type}${token_permissions_type}Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)"
    local permit_batch_witness_string="PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,${witness_type_string}"
    
    local permit_batch_type_hash=$(compute_type_hash "$permit_batch_witness_string")
    print_debug "Permit batch type string: $permit_batch_witness_string"
    print_debug "Permit batch type hash: $permit_batch_type_hash"
    
    print_debug "Main struct params: type_hash=$permit_batch_type_hash, permitted_array=$permitted_array_hash, spender=$spender, nonce=$nonce, deadline=$deadline, witness=$witness_hash"
    local main_struct_encoded=$(cast_abi_encode "f(bytes32,bytes32,address,uint256,uint256,bytes32)" \
        "$permit_batch_type_hash" "$permitted_array_hash" "$spender" "$nonce" "$deadline" "$witness_hash")
    local main_struct_hash=$(cast_keccak "$main_struct_encoded")
    print_debug "Main struct hash: $main_struct_hash"
    
    # Create final EIP-712 digest
    local digest_prefix="0x1901"
    local digest="${digest_prefix}${domain_separator#0x}${main_struct_hash#0x}"
    print_debug "Pre-hash digest: $digest"
    print_debug "Domain separator for digest: $domain_separator"
    print_debug "Main struct hash for digest: $main_struct_hash"
    local final_digest=$(cast_keccak "$digest")
    
    print_debug "Final digest: $final_digest"
    
    # Sign the digest
    local signature=$(cast_sign "$user_private_key" "$final_digest" "true")
    
    if [ -z "$signature" ]; then
        print_error "Failed to generate Permit2 signature"
        return 1
    fi
    
    print_success "Permit2 signature generated" >&2
    echo "$signature"
}

# Generate Compact signature for resource lock
sign_compact_order() {
    local user_private_key="$1"
    local compact_address="$2"
    local chain_id="$3"
    local token_address="$4"  # Was allocator_id, now using token address
    local resource_lock_tag="$5"  # The allocator lock tag
    local amount="$6"
    local nonce="$7"
    local expires="$8"
    local user_address="$9"
    local input_settler_compact="${10}"
    local fill_deadline="${11}"
    local input_oracle="${12}"
    local witness_hash="${13}"
    
    print_debug "Signing BatchCompact order (matching working script)"
    print_debug "Compact address: $compact_address"
    print_debug "Chain ID: $chain_id"
    print_debug "Token: $token_address"
    print_debug "Resource lock tag: $resource_lock_tag"
    print_debug "Amount: $amount"
    print_debug "Nonce: $nonce"
    print_debug "Expires: $expires"
    print_debug "Input settler compact: $input_settler_compact"
    
    # Get TheCompact domain separator from chain
    local domain_separator=$(cast call "$compact_address" "DOMAIN_SEPARATOR()" --rpc-url "http://localhost:8545" 2>/dev/null || echo "")
    
    if [ -z "$domain_separator" ] || [ "$domain_separator" = "null" ]; then
        # Fallback to computed domain separator
        domain_separator=$(compute_domain_separator "TheCompact" "1" "$chain_id" "$compact_address")
    fi
    print_debug "Domain separator: $domain_separator"
    
    # BatchCompact type hash matching the working script exactly
    local batch_compact_type_string="BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
    local batch_compact_type_hash=$(compute_type_hash "$batch_compact_type_string")
    print_debug "BatchCompact type hash: $batch_compact_type_hash"
    
    # Compute commitments hash (for single Lock)
    local lock_type_hash=$(compute_type_hash "Lock(bytes12 lockTag,address token,uint256 amount)")
    local lock_hash=$(cast_keccak $(cast_abi_encode "f(bytes32,bytes12,address,uint256)" \
        "$lock_type_hash" "$resource_lock_tag" "$token_address" "$amount"))
    local commitments_hash=$(cast_keccak "$lock_hash")
    print_debug "Commitments hash: $commitments_hash"
    
    # Build inner struct hash for BatchCompact
    local inner_struct_encoded=$(cast_abi_encode "f(bytes32,address,address,uint256,uint256,bytes32,bytes32)" \
        "$batch_compact_type_hash" "$input_settler_compact" "$user_address" "$nonce" "$expires" "$commitments_hash" "$witness_hash")
    local inner_struct_hash=$(cast_keccak "$inner_struct_encoded")
    print_debug "Inner struct hash: $inner_struct_hash"
    
    # Create final EIP-712 digest
    local digest_prefix="0x1901"
    local digest="${digest_prefix}${domain_separator#0x}${inner_struct_hash#0x}"
    local final_digest=$(cast_keccak "$digest")
    
    print_debug "Final digest: $final_digest"
    
    # Sign the digest (no-hash since we already have the digest)
    local signature=$(cast wallet sign --no-hash --private-key "$user_private_key" "$final_digest")
    
    if [ -z "$signature" ]; then
        print_error "Failed to generate Compact signature"
        return 1
    fi
    
    print_success "Compact signature generated" >&2
    echo "$signature"
}

# Simple EIP-191 personal sign
sign_personal_message() {
    local private_key="$1"
    local message="$2"
    
    # Add Ethereum personal message prefix
    local prefix="\x19Ethereum Signed Message:\n${#message}"
    local full_message="${prefix}${message}"
    
    local message_hash=$(cast_keccak "$full_message")
    cast_sign "$private_key" "$message_hash" "false"
}

# Verify signature against address
verify_signature() {
    local signature="$1"
    local message_hash="$2"
    local expected_address="$3"
    
    # Use cast to recover address from signature
    local recovered_addr
    recovered_addr=$(cast_cmd "wallet" "verify" "--address" "$expected_address" "$signature" "$message_hash" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        print_success "Signature verification passed"
        return 0
    else
        print_error "Signature verification failed"
        print_debug "Expected: $expected_address"
        print_debug "Message: $message_hash"
        print_debug "Signature: $signature"
        return 1
    fi
}

# Create prefixed signature for different signature types
create_prefixed_signature() {
    local signature="$1"
    local signature_type="${2:-permit2}"  # permit2, eip3009, personal
    
    case "$signature_type" in
        permit2)
            # Permit2 signature type prefix (0x00)
            echo "0x00${signature#0x}"
            ;;
        eip3009)
            # EIP-3009 signature type prefix (0x01)
            echo "0x01${signature#0x}"
            ;;
        personal)
            # Personal sign signature (no prefix needed)
            echo "$signature"
            ;;
        *)
            print_error "Unknown signature type: $signature_type"
            return 1
            ;;
    esac
}

# Build StandardOrder data structure
build_standard_order() {
    local user="$1"
    local nonce="$2"
    local origin_chain_id="$3"
    local expiry="$4"
    local fill_deadline="$5"
    local input_oracle="$6"
    local input_token="$7"
    local input_amount="$8"
    local output_settler="$9"
    local dest_chain_id="${10}"
    local dest_token="${11}"
    local dest_amount="${12}"
    local recipient="${13}"
    
    # Convert addresses to proper format
    local output_settler_bytes32="0x000000000000000000000000${output_settler#0x}"
    local dest_token_bytes32="0x000000000000000000000000${dest_token#0x}"
    local recipient_bytes32="0x000000000000000000000000${recipient#0x}"
    
    # Zero bytes32 for empty oracle
    local zero_bytes32="0x0000000000000000000000000000000000000000000000000000000000000000"
    
    # StandardOrder ABI type
    local abi_type='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'
    
    # Build order structure
    local order_struct="(${user},${nonce},${origin_chain_id},${expiry},${fill_deadline},${input_oracle},[[$input_token,$input_amount]],[($zero_bytes32,$output_settler_bytes32,$dest_chain_id,$dest_token_bytes32,$dest_amount,$recipient_bytes32,0x,0x)])"
    
    cast_abi_encode "$abi_type" "$order_struct"
}

# Extract digest from quote JSON
extract_digest_from_quote() {
    local quote_json="$1"
    
    echo "$quote_json" | jq -r '.quotes[0].orders[0].message.digest // empty'
}

# Generate EIP-3009 signature for receiveWithAuthorization
sign_eip3009_order() {
    local user_private_key="$1"
    local origin_chain_id="$2"
    local token_address="$3"
    local amount="$4"
    local input_settler="$5"
    local order_id="$6"  # Use order ID as nonce
    local fill_deadline="$7"
    local rpc_url="${8:-http://localhost:8545}"
    
    print_debug "Signing EIP-3009 order" >&2
    print_debug "Token: $token_address" >&2
    print_debug "Amount: $amount" >&2
    print_debug "To: $input_settler" >&2
    print_debug "Order ID (nonce): $order_id" >&2
    print_debug "Fill deadline: $fill_deadline" >&2
    
    # Get token domain separator for EIP-3009
    print_debug "Getting DOMAIN_SEPARATOR from token at $token_address via $rpc_url" >&2
    local domain_separator=$(cast call "$token_address" "DOMAIN_SEPARATOR()" --rpc-url "$rpc_url" 2>/dev/null || echo "")
    
    if [ -z "$domain_separator" ] || [ "$domain_separator" = "null" ] || [ "$domain_separator" = "0x" ]; then
        print_error "Token at $token_address does not support EIP-712 domain separator" >&2
        print_debug "Domain separator result: '$domain_separator'" >&2
        print_debug "Make sure the token implements DOMAIN_SEPARATOR() function" >&2
        return 1
    fi
    
    print_debug "Token domain separator: $domain_separator" >&2
    
    # Build EIP-3009 signature for receiveWithAuthorization
    local eip3009_type_hash=$(cast_keccak "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    
    # EIP-3009 parameters
    local valid_after=0  # Valid immediately
    local valid_before="$fill_deadline"  # Valid until fill deadline
    local nonce_bytes32="$order_id"  # Use order ID as nonce
    
    # Get user address from private key
    local user_addr=$(cast wallet address --private-key "$user_private_key")
    
    # Encode the struct hash
    local struct_encoded=$(cast_abi_encode "f(bytes32,address,address,uint256,uint256,uint256,bytes32)" \
        "$eip3009_type_hash" \
        "$user_addr" \
        "$input_settler" \
        "$amount" \
        "$valid_after" \
        "$valid_before" \
        "$nonce_bytes32")
    
    local struct_hash=$(cast_keccak "$struct_encoded")
    
    print_debug "EIP-3009 struct hash: $struct_hash" >&2
    
    # Create EIP-712 digest
    local digest_prefix="0x1901"
    local digest="${digest_prefix}${domain_separator#0x}${struct_hash#0x}"
    local final_digest=$(cast_keccak "$digest")
    
    print_debug "EIP-3009 final digest: $final_digest" >&2
    
    # Sign the digest using --no-hash flag for EIP-712 signatures
    local signature=$(cast wallet sign --no-hash --private-key "$user_private_key" "$final_digest")
    
    if [ -z "$signature" ]; then
        print_error "Failed to generate EIP-3009 signature" >&2
        return 1
    fi
    
    print_success "EIP-3009 signature generated" >&2
    echo "$signature"
}

# Simple signature workflow for standard intents
sign_standard_intent() {
    local user_private_key="$1"
    local origin_chain_id="$2"
    local token_address="$3"
    local amount="$4"
    local settler_address="$5"
    local nonce="$6"
    local deadline="$7"
    local expires="$8"
    local input_oracle="$9"
    local mandate_outputs_json="${10}"
    
    # Parse mandate outputs from JSON
    local mandate_outputs=()
    while IFS= read -r line; do
        mandate_outputs+=("$line")
    done < <(echo "$mandate_outputs_json" | jq -r '.[] | "\(.oracle),\(.settler),\(.chainId),\(.token),\(.amount),\(.recipient)"')
    
    # Generate signature
    local signature=$(sign_permit2_order "$user_private_key" "$origin_chain_id" "$token_address" \
        "$amount" "$settler_address" "$nonce" "$deadline" "$expires" "$input_oracle" "${mandate_outputs[@]}")
    
    if [ -z "$signature" ]; then
        return 1
    fi
    
    # Return prefixed signature
    create_prefixed_signature "$signature" "permit2"
}

# Export functions
export -f compute_domain_separator
export -f get_permit2_domain_separator
export -f compute_type_hash
export -f compute_mandate_output_hash
export -f compute_permit2_witness_hash
export -f compute_token_permissions_hash
export -f sign_permit2_order
export -f sign_compact_order
export -f sign_eip3009_order
export -f sign_personal_message
export -f verify_signature
export -f create_prefixed_signature
export -f build_standard_order
export -f extract_digest_from_quote
export -f sign_standard_intent