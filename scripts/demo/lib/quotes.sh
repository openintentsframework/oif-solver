#!/usr/bin/env bash
#
# ==============================================================================
# Quotes Module - Request and Accept Solver Quotes
# ==============================================================================
#
# This module handles the quote lifecycle for cross-chain intents, including
# requesting quotes from solvers, displaying quote details, and accepting quotes
# for execution.
#
# Key Features:
# - Quote request generation from intents
# - ERC-7930 interop address support
# - Quote validation and expiry checking
# - Quote comparison and selection
# - EIP-712 order signing for quote acceptance
# - Quote ID-based submission (future support)
#
# Quote Workflow:
# 1. Build quote request from intent
# 2. Submit request to solver API
# 3. Display and validate received quotes
# 4. Sign EIP-712 order for acceptance
# 5. Submit signed order with quote ID
#
# Dependencies:
# - api.sh: For API interactions
# - signature.sh: For EIP-712 signing
# - config.sh: For network configuration
#
# Usage:
#   quote_get demo-output/intent-quote.json
#   quote_accept demo-output/quote.json
#   quote_test escrow permit2 A2B
#
# ==============================================================================

# -----------------------------------------------------------------------------
# Constants and Configuration  
# -----------------------------------------------------------------------------
# Quote preferences
PREFERENCE_SPEED="speed"
PREFERENCE_COST="cost"
PREFERENCE_BALANCED="balanced"

# Quote status tracking
declare -gA QUOTE_STATUS=()
QUOTE_STATUS[last_quote_id]=""
QUOTE_STATUS[last_quote_json]=""
QUOTE_STATUS[last_request_json]=""
QUOTE_STATUS[last_order_id]=""

# Clear quote status
clear_quote_status() {
    QUOTE_STATUS[last_quote_id]=""
    QUOTE_STATUS[last_quote_json]=""
    QUOTE_STATUS[last_request_json]=""
    QUOTE_STATUS[last_order_id]=""
}

# Get quote status field
get_quote_status() {
    local field="$1"
    echo "${QUOTE_STATUS[$field]:-}"
}

# Set quote status field
set_quote_status() {
    local field="$1"
    local value="$2"
    QUOTE_STATUS[$field]="$value"
}

# Build UII address (ERC-7930 format)
build_uii_address() {
    local chain_id="$1"
    local address="$2"
    
    to_uii_address "$chain_id" "$address"
}

# Parse UII address
parse_uii_address() {
    local uii="$1"
    
    from_uii_address "$uii"
}

# Build quote request for simple token swap
build_quote_request() {
    local user_address="$1"
    local input_chain_id="$2"
    local input_token="$3"
    local input_amount="$4"
    local output_chain_id="$5"
    local output_token="$6"
    local output_amount="$7"
    local recipient="${8:-$user_address}"
    local preference="${9:-$PREFERENCE_SPEED}"
    local min_valid_until="${10:-600}"  # 10 minutes
    
    print_debug "Building quote request"
    print_debug "User: $user_address"
    print_debug "Input: $input_amount of $input_token on chain $input_chain_id"
    print_debug "Output: $output_amount of $output_token on chain $output_chain_id"
    print_debug "Recipient: $recipient"
    print_debug "Preference: $preference"
    
    # Build UII addresses
    local user_uii=$(build_uii_address "$input_chain_id" "$user_address")
    local input_token_uii=$(build_uii_address "$input_chain_id" "$input_token")
    local output_token_uii=$(build_uii_address "$output_chain_id" "$output_token")
    local recipient_uii=$(build_uii_address "$output_chain_id" "$recipient")
    
    print_debug "User UII: $user_uii"
    print_debug "Input token UII: $input_token_uii"
    print_debug "Output token UII: $output_token_uii"
    print_debug "Recipient UII: $recipient_uii"
    
    # Build quote request JSON
    local quote_request=$(jq -n \
        --arg user "$user_uii" \
        --arg input_user "$user_uii" \
        --arg input_asset "$input_token_uii" \
        --arg input_amount "$input_amount" \
        --arg output_receiver "$recipient_uii" \
        --arg output_asset "$output_token_uii" \
        --arg output_amount "$output_amount" \
        --arg preference "$preference" \
        --argjson min_valid_until "$min_valid_until" \
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
            ],
            preference: $preference,
            minValidUntil: $min_valid_until
        }')
    
    echo "$quote_request"
}

# Request quote from solver
request_quote() {
    local quote_request_json="$1"
    local api_url="${2:-http://localhost:3000/api/quotes}"
    local timeout="${3:-30}"
    
    print_info "Requesting quote from solver"
    print_debug "API URL: $api_url"
    print_debug "Timeout: ${timeout}s"
    
    # Validate request JSON
    if ! validate_json "$quote_request_json"; then
        print_error "Invalid quote request JSON"
        return 1
    fi
    
    # Store request for reference
    set_quote_status "last_request_json" "$quote_request_json"
    
    # Make API request
    if api_post "$api_url" "$quote_request_json" "" "$timeout"; then
        local status_code=$(get_api_response "status_code")
        local response_body=$(get_api_response "body")
        
        print_success "Quote request successful (HTTP $status_code)"
        
        # Validate response contains quotes
        local quotes_count=$(echo "$response_body" | jq -r '.quotes | length // 0' 2>/dev/null)
        
        if [ "$quotes_count" -eq 0 ]; then
            print_error "No quotes received from solver"
            print_debug "Response: $response_body"
            return 1
        fi
        
        print_info "Received $quotes_count quote(s)"
        
        # Store quote response
        set_quote_status "last_quote_json" "$response_body"
        
        # Extract first quote ID
        local quote_id=$(echo "$response_body" | jq -r '.quotes[0].quoteId // empty' 2>/dev/null)
        if [ -n "$quote_id" ] && [ "$quote_id" != "null" ]; then
            set_quote_status "last_quote_id" "$quote_id"
            print_info "Quote ID: $quote_id"
        fi
        
        return 0
    else
        local error_msg=$(get_api_error_message)
        print_error "Quote request failed: $error_msg"
        print_api_response
        return 1
    fi
}

# Accept quote and build transaction
accept_quote() {
    local quote_json="${1:-$(get_quote_status last_quote_json)}"
    local quote_index="${2:-0}"
    
    if [ -z "$quote_json" ]; then
        print_error "No quote JSON provided or found in status"
        return 1
    fi
    
    print_info "Accepting quote (index: $quote_index)"
    
    # Validate quote JSON
    if ! validate_json "$quote_json"; then
        print_error "Invalid quote JSON"
        return 1
    fi
    
    # Check if quote exists at index
    local quote_exists=$(echo "$quote_json" | jq -e ".quotes[$quote_index]" >/dev/null 2>&1 && echo "true" || echo "false")
    if [ "$quote_exists" != "true" ]; then
        print_error "Quote at index $quote_index not found"
        return 1
    fi
    
    # Extract quote details
    local quote_id=$(echo "$quote_json" | jq -r ".quotes[$quote_index].quoteId // empty")
    local valid_until=$(echo "$quote_json" | jq -r ".quotes[$quote_index].validUntil // empty")
    local orders_count=$(echo "$quote_json" | jq -r ".quotes[$quote_index].orders | length // 0")
    
    print_info "Quote ID: $quote_id"
    print_info "Valid until: $valid_until"
    print_info "Orders count: $orders_count"
    
    # Check if quote is still valid
    if [ -n "$valid_until" ] && [ "$valid_until" != "null" ]; then
        local current_time=$(get_timestamp)
        if [ "$current_time" -gt "$valid_until" ]; then
            print_error "Quote has expired (current: $current_time, valid until: $valid_until)"
            return 1
        fi
    fi
    
    # For now, we'll return the quote JSON for external processing
    # In a full implementation, this would build and sign the transaction
    echo "$quote_json"
    return 0
}

# Simple quote workflow for token swap
request_token_swap_quote() {
    local user_address="$1"
    local user_private_key="$2"
    local input_chain_id="$3"
    local input_token="$4"
    local input_amount="$5"
    local output_chain_id="$6"
    local output_token="$7"
    local output_amount="$8"
    local recipient="${9:-$user_address}"
    local api_url="${10:-http://localhost:3000/api/quotes}"
    
    print_header "Requesting Token Swap Quote"
    
    # Build quote request
    local quote_request=$(build_quote_request \
        "$user_address" "$input_chain_id" "$input_token" "$input_amount" \
        "$output_chain_id" "$output_token" "$output_amount" "$recipient")
    
    if [ -z "$quote_request" ]; then
        print_error "Failed to build quote request"
        return 1
    fi
    
    print_debug "Quote request JSON:"
    echo "$quote_request" | jq '.' >&2
    
    # Request quote
    if request_quote "$quote_request" "$api_url"; then
        local quote_json=$(get_quote_status "last_quote_json")
        
        # Show quote summary
        show_quote_summary "$quote_json"
        
        return 0
    else
        return 1
    fi
}

# Quick quote request with defaults
quick_quote_request() {
    local amount="${1:-1000000000000000000}"  # 1 token
    local api_url="${2:-http://localhost:3000/api/quotes}"
    
    # Get config values
    local user_addr=$(config_get_account "user" "address")
    local user_key=$(config_get_account "user" "private_key")
    local recipient=$(config_get_account "recipient" "address")
    local tokena_origin=$(config_get_token "31337" "tokena")
    local tokena_dest=$(config_get_token "31338" "tokena")
    
    request_token_swap_quote \
        "$user_addr" "$user_key" "31337" "$tokena_origin" "$amount" \
        "31338" "$tokena_dest" "$amount" "$recipient" "$api_url"
}

# Show quote summary
show_quote_summary() {
    local quote_json="${1:-$(get_quote_status last_quote_json)}"
    
    if [ -z "$quote_json" ]; then
        print_warning "No quote data available"
        return 1
    fi
    
    print_header "Quote Summary"
    
    local quotes_count=$(echo "$quote_json" | jq -r '.quotes | length // 0')
    print_info "Number of quotes: $quotes_count"
    
    if [ "$quotes_count" -eq 0 ]; then
        print_warning "No quotes available"
        return 1
    fi
    
    # Show first quote details
    local quote_id=$(echo "$quote_json" | jq -r '.quotes[0].quoteId // "N/A"')
    local valid_until=$(echo "$quote_json" | jq -r '.quotes[0].validUntil // "N/A"')
    local orders_count=$(echo "$quote_json" | jq -r '.quotes[0].orders | length // 0')
    
    print_info "Quote ID: $quote_id"
    print_info "Valid until: $valid_until"
    print_info "Orders: $orders_count"
    
    # Show pricing info if available
    local price=$(echo "$quote_json" | jq -r '.quotes[0].price // empty')
    local fee=$(echo "$quote_json" | jq -r '.quotes[0].fee // empty')
    
    if [ -n "$price" ] && [ "$price" != "null" ]; then
        print_info "Price: $price"
    fi
    
    if [ -n "$fee" ] && [ "$fee" != "null" ]; then
        print_info "Fee: $fee"
    fi
    
    # Show input/output summary
    echo ""
    print_info "Trade details:"
    
    # Parse first order for trade details
    local input_token=$(echo "$quote_json" | jq -r '.quotes[0].orders[0].message.eip712.permitted[0].token // "N/A"')
    local input_amount=$(echo "$quote_json" | jq -r '.quotes[0].orders[0].message.eip712.permitted[0].amount // "N/A"')
    local output_token=$(echo "$quote_json" | jq -r '.quotes[0].orders[0].message.eip712.witness.outputs[0].token // "N/A"')
    local output_amount=$(echo "$quote_json" | jq -r '.quotes[0].orders[0].message.eip712.witness.outputs[0].amount // "N/A"')
    
    if [ "$input_amount" != "N/A" ]; then
        local input_formatted=$(format_balance "$input_amount")
        print_info "  Input: $input_formatted tokens ($input_token)"
    fi
    
    if [ "$output_amount" != "N/A" ]; then
        local output_formatted=$(format_balance "$output_amount")
        print_info "  Output: $output_formatted tokens ($output_token)"
    fi
    
    print_separator
}

# Show detailed quote information
show_quote_details() {
    local quote_json="${1:-$(get_quote_status last_quote_json)}"
    local quote_index="${2:-0}"
    
    if [ -z "$quote_json" ]; then
        print_warning "No quote data available"
        return 1
    fi
    
    print_header "Quote Details (Index: $quote_index)"
    
    # Check if quote exists at index
    local quote_exists=$(echo "$quote_json" | jq -e ".quotes[$quote_index]" >/dev/null 2>&1 && echo "true" || echo "false")
    if [ "$quote_exists" != "true" ]; then
        print_error "Quote at index $quote_index not found"
        return 1
    fi
    
    # Extract and display quote details
    local quote_data=$(echo "$quote_json" | jq ".quotes[$quote_index]")
    
    echo "$quote_data" | jq '.'
    
    print_separator
}

# List all available quotes
list_quotes() {
    local quote_json="${1:-$(get_quote_status last_quote_json)}"
    
    if [ -z "$quote_json" ]; then
        print_warning "No quote data available"
        return 1
    fi
    
    print_header "Available Quotes"
    
    local quotes_count=$(echo "$quote_json" | jq -r '.quotes | length // 0')
    
    if [ "$quotes_count" -eq 0 ]; then
        print_warning "No quotes available"
        return 1
    fi
    
    for ((i=0; i<quotes_count; i++)); do
        local quote_id=$(echo "$quote_json" | jq -r ".quotes[$i].quoteId // \"N/A\"")
        local valid_until=$(echo "$quote_json" | jq -r ".quotes[$i].validUntil // \"N/A\"")
        local orders_count=$(echo "$quote_json" | jq -r ".quotes[$i].orders | length // 0")
        
        echo "[$i] Quote ID: $quote_id"
        echo "    Valid until: $valid_until"
        echo "    Orders: $orders_count"
        echo ""
    done
    
    print_separator
}

# Check quote validity
is_quote_valid() {
    local quote_json="${1:-$(get_quote_status last_quote_json)}"
    local quote_index="${2:-0}"
    
    if [ -z "$quote_json" ]; then
        return 1
    fi
    
    local valid_until=$(echo "$quote_json" | jq -r ".quotes[$quote_index].validUntil // empty")
    
    if [ -z "$valid_until" ] || [ "$valid_until" = "null" ]; then
        return 0  # No expiry, assume valid
    fi
    
    local current_time=$(get_timestamp)
    
    if [ "$current_time" -lt "$valid_until" ]; then
        return 0  # Valid
    else
        return 1  # Expired
    fi
}

# Get quote expiry time remaining
get_quote_time_remaining() {
    local quote_json="${1:-$(get_quote_status last_quote_json)}"
    local quote_index="${2:-0}"
    
    if [ -z "$quote_json" ]; then
        echo "0"
        return 1
    fi
    
    local valid_until=$(echo "$quote_json" | jq -r ".quotes[$quote_index].validUntil // empty")
    
    if [ -z "$valid_until" ] || [ "$valid_until" = "null" ]; then
        echo "unlimited"
        return 0
    fi
    
    local current_time=$(get_timestamp)
    local remaining=$((valid_until - current_time))
    
    if [ "$remaining" -lt 0 ]; then
        echo "0"
    else
        echo "$remaining"
    fi
}

# Compare quotes
compare_quotes() {
    local quote_json="${1:-$(get_quote_status last_quote_json)}"
    
    if [ -z "$quote_json" ]; then
        print_warning "No quote data available"
        return 1
    fi
    
    print_header "Quote Comparison"
    
    local quotes_count=$(echo "$quote_json" | jq -r '.quotes | length // 0')
    
    if [ "$quotes_count" -lt 2 ]; then
        print_warning "Need at least 2 quotes for comparison"
        return 1
    fi
    
    echo "Index | Quote ID | Valid Until | Orders | Status"
    echo "------|----------|-------------|--------|--------"
    
    for ((i=0; i<quotes_count; i++)); do
        local quote_id=$(echo "$quote_json" | jq -r ".quotes[$i].quoteId // \"N/A\"")
        local valid_until=$(echo "$quote_json" | jq -r ".quotes[$i].validUntil // \"N/A\"")
        local orders_count=$(echo "$quote_json" | jq -r ".quotes[$i].orders | length // 0")
        
        local status="Valid"
        if ! is_quote_valid "$quote_json" "$i"; then
            status="Expired"
        fi
        
        printf "%-5s | %-8s | %-11s | %-6s | %s\n" \
            "$i" "${quote_id:0:8}" "$valid_until" "$orders_count" "$status"
    done
    
    print_separator
}

# CLI command handlers
quote_get() {
    local intent_file="${1:-}"
    local api_url="${2:-http://localhost:3000/api/quotes}"
    local save_to="${3:-${OUTPUT_DIR:-./demo-output}/quote.json}"  # Default to OUTPUT_DIR/quote.json
    
    # Check if intent file provided
    if [ -z "$intent_file" ]; then
        # Try quick quote with defaults
        print_info "No intent file provided, using default test values"
        if quick_quote_request; then
            local quote_json=$(get_quote_status "last_quote_json")
            
            # Always save to file
            echo "$quote_json" | jq '.' > "$save_to"
            print_success "Quote saved to: $save_to"
            print_info "Use 'oif-demo quote accept $save_to' to accept the quote"
            
            return 0
        else
            return 1
        fi
    fi
    
    # Check for --intent flag
    if [ "$intent_file" = "--intent" ]; then
        intent_file="${2:-}"
        api_url="${3:-http://localhost:3000/api/quotes}"
        save_to="${4:-}"
        
        if [ -z "$intent_file" ]; then
            print_error "Intent file required after --intent flag"
            print_info "Usage: oif-demo quote get --intent <intent-file> [api-url] [save-to]"
            return 1
        fi
    fi
    
    # Check if intent file exists
    if [ ! -f "$intent_file" ]; then
        print_error "Intent file not found: $intent_file"
        return 1
    fi
    
    print_info "Getting quote for intent: $intent_file"
    
    # Read and validate intent JSON
    local intent_json=$(cat "$intent_file")
    if ! validate_json "$intent_json"; then
        print_error "Invalid intent JSON in file: $intent_file"
        return 1
    fi
    
    # Check if this is a signed order or a quote request
    local has_order=$(echo "$intent_json" | jq 'has("order")')
    local has_signature=$(echo "$intent_json" | jq 'has("signature")')
    
    if [ "$has_order" = "true" ] && [ "$has_signature" = "true" ]; then
        print_error "File contains a signed order, not a quote request intent"
        print_info "A quote request intent should have the following structure:"
        print_info '  {
    "user": "chain_id:user_address",
    "inputs": [
      {
        "user": "chain_id:user_address",
        "asset": "chain_id:token_address",
        "amount": "amount_in_wei"
      }
    ],
    "outputs": [
      {
        "receiver": "chain_id:recipient_address",
        "asset": "chain_id:token_address",
        "amount": "amount_in_wei"
      }
    ]
  }'
        print_info ""
        print_info "Example: Create a quote request for swapping 1 TokenA on chain 31337 to 1 TokenA on chain 31338"
        print_info "Or run without arguments to use default test values: oif-demo quote get"
        return 1
    fi
    
    # Convert intent to quote request format
    # Extract key fields from intent for quote request
    local user=$(echo "$intent_json" | jq -r '.user // empty')
    local inputs=$(echo "$intent_json" | jq -c '.inputs // .availableInputs // []')
    local outputs=$(echo "$intent_json" | jq -c '.outputs // .requestedOutputs // []')
    
    if [ -z "$user" ] || [ "$user" = "null" ]; then
        # Try to extract from sponsor field if present
        local sponsor=$(echo "$intent_json" | jq -r '.sponsor // empty')
        if [ -n "$sponsor" ] && [ "$sponsor" != "null" ]; then
            # Assume origin chain for sponsor
            user="31337:$sponsor"
            print_info "Using sponsor as user: $user"
        else
            print_error "Intent missing 'user' field"
            print_info "The intent file should contain a 'user' field in the format 'chain_id:address'"
            print_info "Example: \"user\": \"31337:0x70997970C51812dc3A010C7d01b50e0d17dc79C8\""
            return 1
        fi
    fi
    
    # Build quote request from intent
    local quote_request=$(jq -n \
        --arg user "$user" \
        --argjson inputs "$inputs" \
        --argjson outputs "$outputs" \
        '{
            user: $user,
            availableInputs: $inputs,
            requestedOutputs: $outputs,
            preference: "speed",
            minValidUntil: 600
        }')
    
    # Request quote
    if request_quote "$quote_request" "$api_url"; then
        local quote_json=$(get_quote_status "last_quote_json")
        
        # Always save to file
        echo "$quote_json" | jq '.' > "$save_to"
        print_success "Quote saved to: $save_to"
        print_info "Use 'oif-demo quote accept $save_to' to accept the quote"
        
        return 0
    else
        return 1
    fi
}

quote_accept() {
    local quote_file="${1:-${OUTPUT_DIR:-./demo-output}/quote.json}"  # Default to OUTPUT_DIR/quote.json
    local quote_index="${2:-0}"
    local execute="${3:-false}"  # Auto-execute flag
    
    local quote_json=""
    
    # Check if quote file exists
    if [ -f "$quote_file" ]; then
        # Read quote from file
        quote_json=$(cat "$quote_file")
        if ! validate_json "$quote_json"; then
            print_error "Invalid quote JSON in file: $quote_file"
            return 1
        fi
        print_info "Using quote from: $quote_file"
    else
        # Try to use last quote from status as fallback
        quote_json=$(get_quote_status "last_quote_json")
        if [ -z "$quote_json" ]; then
            print_error "Quote file not found: $quote_file"
            print_info "Run 'oif-demo quote get' to fetch a quote first"
            return 1
        fi
        print_info "Using last quote from memory"
    fi
    
    # Show quote details
    show_quote_details "$quote_json" "$quote_index"
    
    # Check if quote is still valid
    if ! is_quote_valid "$quote_json" "$quote_index"; then
        print_warning "Quote has expired"
        
        local time_remaining=$(get_quote_time_remaining "$quote_json" "$quote_index")
        if [ "$time_remaining" != "unlimited" ]; then
            print_info "Quote expired $((-time_remaining)) seconds ago"
        fi
        
        return 1
    fi
    
    local time_remaining=$(get_quote_time_remaining "$quote_json" "$quote_index")
    if [ "$time_remaining" != "unlimited" ]; then
        print_info "Time remaining: ${time_remaining} seconds"
    fi
    
    # Confirm acceptance
    if [ "$execute" != "true" ] && [ "$execute" != "yes" ]; then
        if ! confirm_action "Accept this quote?"; then
            print_info "Quote acceptance cancelled"
            return 1
        fi
    fi
    
    # Accept the quote (validation check)
    if accept_quote "$quote_json" "$quote_index" > /dev/null; then
        print_success "Quote accepted successfully"
        
        # Extract quote ID for reference
        local quote_id=$(echo "$quote_json" | jq -r ".quotes[$quote_index].quoteId // \"N/A\"")
        print_info "Quote ID: $quote_id"
        
        print_debug "Starting order signing and submission process..."
        
        # Extract the order details from the quote
        local order_data=$(echo "$quote_json" | jq -r ".quotes[$quote_index].orders[0] // empty")
        
        print_debug "Order data extracted: ${#order_data} chars"
        
        if [ -z "$order_data" ] || [ "$order_data" = "null" ]; then
            print_error "No order data found in quote"
            return 1
        fi
        
        print_debug "Order data is valid, proceeding to get user key..."
        
        # Get user's private key from config
        local user_key=$(config_get_account "user" "private_key")
        print_debug "User key loaded: ${#user_key} chars"
        if [ -z "$user_key" ]; then
            print_error "User private key not configured"
            return 1
        fi
        print_debug "User key found, extracting EIP-712 message..."
        
        # Extract EIP-712 message for signing
        local eip712_message=$(echo "$order_data" | jq -r '.message.eip712 // empty')
        if [ -z "$eip712_message" ] || [ "$eip712_message" = "null" ]; then
            print_error "No EIP-712 message found in order"
            return 1
        fi
        
        print_info "Signing EIP-712 order..."
        
        # Extract witness data first (needed for signing)
        local witness=$(echo "$eip712_message" | jq -r '.witness // empty')
        local witness_expires=$(echo "$witness" | jq -r '.expires // 0')
        local input_oracle=$(echo "$witness" | jq -r '.inputOracle // "0x0000000000000000000000000000000000000000"')
        
        # Sign the EIP-712 message
        local domain=$(echo "$eip712_message" | jq -r '.signing.domain // empty')
        local primary_type=$(echo "$eip712_message" | jq -r '.signing.primaryType // "PermitBatchWitnessTransferFrom"')
        local deadline=$(echo "$eip712_message" | jq -r '.deadline // empty')
        local nonce=$(echo "$eip712_message" | jq -r '.nonce // empty')
        local spender=$(echo "$eip712_message" | jq -r '.spender // empty')
        
        # Extract the required fields for Permit2 signing
        local permitted_token=$(echo "$eip712_message" | jq -r '.permitted[0].token // empty')
        local permitted_amount=$(echo "$eip712_message" | jq -r '.permitted[0].amount // empty')
        
        # Convert interop address to standard Ethereum address if needed for signing
        local standard_permitted_token="$permitted_token"
        # Interop addresses are longer than standard addresses (42 chars)
        if [[ ${#permitted_token} -gt 42 ]]; then
            # This is likely an interop address, convert to standard
            standard_permitted_token=$(from_uii_address "$permitted_token")
            print_debug "Converted permitted token from interop to standard: $permitted_token -> $standard_permitted_token"
        fi
        
        # Get origin chain ID from the domain
        local origin_chain_id=$(echo "$domain" | jq -r '.chainId // 31337')
        
        # Build mandate outputs array from witness outputs
        local mandate_outputs_json=$(echo "$witness" | jq -c '.outputs')
        
        # Use the sign_standard_intent function which handles Permit2 properly
        local signature=$(sign_standard_intent \
            "$user_key" \
            "$origin_chain_id" \
            "$standard_permitted_token" \
            "$permitted_amount" \
            "$spender" \
            "$nonce" \
            "$deadline" \
            "$witness_expires" \
            "$input_oracle" \
            "$mandate_outputs_json")
        
        if [ -z "$signature" ]; then
            print_error "Failed to sign EIP-712 order"
            return 1
        fi
        
        print_success "EIP-712 order signed"
        print_debug "Signature: $signature"
        
        # Create submission payload with quoteId
        local submission_json=$(jq -n \
            --arg quoteId "$quote_id" \
            --arg signature "$signature" \
            '{
                quoteId: $quoteId,
                signature: $signature
            }')
        
        # Submit to solver
        local api_url="${SOLVER_API_URL:-http://localhost:3000/api/orders}"
        print_info "Submitting signed order with quote ID to solver..."
        print_debug "API URL: $api_url"
        
        # Debug: Show what we're submitting
        print_debug "Submission payload:"
        if [ "${DEBUG:-0}" = "1" ]; then
            echo "$submission_json" | jq '.' >&2
        fi
        
        print_debug "Quote ID: $quote_id"
        print_debug "Signature: $signature"
        print_debug "Submitting to API URL: $api_url"
        
        if api_post "$api_url" "$submission_json"; then
            local status_code=$(get_api_response "status_code")
            local response_body=$(get_api_response "body")
            
            print_success "Quote order submitted successfully (HTTP $status_code)"
            print_debug "API Response body:"
            if [ "${DEBUG:-0}" = "1" ]; then
                echo "$response_body" | jq '.' >&2 || echo "$response_body" >&2
            fi
            
            # Save submission response
            local output_file="${OUTPUT_DIR:-./demo-output}/quote-submission.json"
            echo "$response_body" | jq '.' > "$output_file" 2>/dev/null || echo "$response_body" > "$output_file"
            print_info "Submission response saved to: $output_file"
            
            # Extract order ID if available
            local order_id=$(echo "$response_body" | jq -r '.orderId // .order_id // .id // empty' 2>/dev/null)
            if [ -n "$order_id" ] && [ "$order_id" != "null" ] && [ "$order_id" != "empty" ]; then
                print_success "Order ID: $order_id"
                set_quote_status "last_order_id" "$order_id"
                # Also set it in intent status for compatibility
                set_intent_status "last_order_id" "$order_id"
            else
                print_debug "No order ID found in response"
                print_debug "Response keys: $(echo "$response_body" | jq -r 'keys' 2>/dev/null)"
            fi
            
            return 0
        else
            local status_code=$(get_api_response "status_code")
            local response_body=$(get_api_response "body")
            local error_msg=$(get_api_error_message)
            
            # Check if this is the expected placeholder response (501 NOT_IMPLEMENTED)
            if [ "$status_code" = "501" ]; then
                # Parse the response to check if it's our placeholder
                local response_status=$(echo "$response_body" | jq -r '.status // empty' 2>/dev/null)
                local response_quote_id=$(echo "$response_body" | jq -r '.quoteId // empty' 2>/dev/null)
                
                if [ "$response_status" = "pending_implementation" ]; then
                    print_warning "Quote acceptance recognized but not yet implemented"
                    print_info "Quote ID: $response_quote_id"
                    print_info "This feature is pending implementation on the solver side"
                    
                    # Save the placeholder response
                    local output_file="${OUTPUT_DIR:-./demo-output}/quote-submission.json"
                    echo "$response_body" | jq '.' > "$output_file" 2>/dev/null || echo "$response_body" > "$output_file"
                    print_info "Response saved to: $output_file"
                    
                    # Return success since the submission was recognized
                    return 0
                fi
            fi
            
            # Otherwise, treat as actual error
            print_error "Failed to submit quote order: $error_msg"
            print_debug "HTTP Status: $status_code"
            print_debug "Response body:"
            if [ "${DEBUG:-0}" = "1" ]; then
                echo "$response_body" | jq '.' >&2 || echo "$response_body" >&2
                print_api_response
            fi
            return 1
        fi
    else
        print_error "Failed to accept quote"
        return 1
    fi
}

quote_test() {
    local lock_type="${1:-escrow}"
    local auth_type="${2:-permit2}"
    local token_pair="${3:-A2B}"
    
    # Validate lock type
    if [[ "$lock_type" != "escrow" && "$lock_type" != "compact" ]]; then
        print_error "Invalid lock type: $lock_type"
        print_info "Usage: quote test <escrow|compact> <permit2|eip3009> <A2A|A2B|B2A|B2B>"
        return 1
    fi
    
    # Validate auth type
    if [ "$lock_type" = "compact" ] && [ "$auth_type" != "permit2" ]; then
        print_error "Compact only supports permit2 auth"
        print_info "Usage: quote test compact permit2 <A2A|A2B|B2A|B2B>"
        return 1
    fi
    
    if [[ "$auth_type" != "permit2" && "$auth_type" != "eip3009" ]]; then
        print_error "Invalid auth type: $auth_type"
        print_info "Supported auth types: permit2, eip3009 (eip3009 only for escrow)"
        print_info "Usage: quote test <escrow|compact> <permit2|eip3009> <A2A|A2B|B2A|B2B>"
        return 1
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
    
    print_header "Testing quote flow: ${lock_type} with ${auth_type} auth, ${from_token} → ${to_token}"
    
    # Step 1: Build intent
    print_step "Building ${lock_type} intent with ${auth_type} auth"
    
    if ! intent_build "$lock_type" "$auth_type" "$origin_chain" "$dest_chain" "$from_token" "$to_token"; then
        print_error "Failed to build ${lock_type} intent with ${auth_type} auth"
        return 1
    fi
    
    print_success "Intent built successfully"
    
    # Step 2: Get quote
    print_step "Getting quote"
    local intent_file="${OUTPUT_DIR:-./demo-output}/intent-quote.json"
    
    if [ ! -f "$intent_file" ]; then
        print_error "Intent quote file not found: $intent_file"
        return 1
    fi
    
    if ! quote_get "$intent_file"; then
        print_error "Failed to get quote"
        return 1
    fi
    
    print_success "Quote received successfully"
    
    # Step 3: Accept quote
    print_step "Accepting quote"
    local quote_file="${OUTPUT_DIR:-./demo-output}/quote.json"
    
    if [ ! -f "$quote_file" ]; then
        print_error "Quote file not found: $quote_file"
        return 1
    fi
    
    # Accept with auto-execute flag to skip confirmation
    if ! quote_accept "$quote_file" 0 true; then
        print_error "Failed to accept quote"
        return 1
    fi
    
    print_success "Quote test completed: ${lock_type} ${token_pair}"
    
    # Show summary
    local quote_id=$(get_quote_status "last_quote_id")
    if [ -n "$quote_id" ] && [ "$quote_id" != "" ]; then
        print_info "Quote ID: $quote_id"
    fi
    
    local order_id=$(get_quote_status "last_order_id")
    if [ -n "$order_id" ] && [ "$order_id" != "" ]; then
        print_info "Order ID: $order_id"
    fi
    
    return 0
}

# Export functions
export -f clear_quote_status
export -f get_quote_status
export -f set_quote_status
export -f build_uii_address
export -f parse_uii_address
export -f build_quote_request
export -f request_quote
export -f accept_quote
export -f request_token_swap_quote
export -f quick_quote_request
export -f show_quote_summary
export -f show_quote_details
export -f list_quotes
export -f is_quote_valid
export -f get_quote_time_remaining
export -f compare_quotes
export -f quote_get
export -f quote_accept
export -f quote_test