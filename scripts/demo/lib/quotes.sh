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
#   quote_get demo-output/get_quote.req.json
#   quote_accept demo-output/get_quote.res.json
#   quote_test escrow permit2 A2B
#   quote_test compact A2B
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
QUOTE_STATUS_last_quote_id=""
QUOTE_STATUS_last_quote_json=""
QUOTE_STATUS_last_request_json=""
QUOTE_STATUS_last_order_id=""

# Clear quote status
clear_quote_status() {
    QUOTE_STATUS_last_quote_id=""
    QUOTE_STATUS_last_quote_json=""
    QUOTE_STATUS_last_request_json=""
    QUOTE_STATUS_last_order_id=""
}

# Get quote status field
get_quote_status() {
    local field="$1"
    case "$field" in
        last_quote_id) echo "$QUOTE_STATUS_last_quote_id" ;;
        last_quote_json) echo "$QUOTE_STATUS_last_quote_json" ;;
        last_request_json) echo "$QUOTE_STATUS_last_request_json" ;;
        last_order_id) echo "$QUOTE_STATUS_last_order_id" ;;
        *) echo "" ;;
    esac
}

# Set quote status field
set_quote_status() {
    local field="$1"
    local value="$2"
    case "$field" in
        last_quote_id) QUOTE_STATUS_last_quote_id="$value" ;;
        last_quote_json) QUOTE_STATUS_last_quote_json="$value" ;;
        last_request_json) QUOTE_STATUS_last_request_json="$value" ;;
        last_order_id) QUOTE_STATUS_last_order_id="$value" ;;
    esac
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
    local save_to="${3:-${OUTPUT_DIR:-./demo-output}/get_quote.res.json}"  # Default to OUTPUT_DIR/get_quote.res.json
    
    # Check if intent file provided
    if [ -z "$intent_file" ]; then
        print_info "No intent file provided"
        return 1
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
    local quote_file="${1:-${OUTPUT_DIR:-./demo-output}/get_quote.res.json}"  # Default to OUTPUT_DIR/get_quote.res.json
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
        print_debug "User key found, determining order type..."

        # Extract the full message object and signature type
        local full_message=$(echo "$order_data" | jq -r '.message // empty')
        local signature_type=$(echo "$order_data" | jq -r '.signatureType // empty')
        local primary_type=$(echo "$order_data" | jq -r '.primaryType // empty')
        
        if [ -z "$full_message" ] || [ "$full_message" = "null" ]; then
            print_error "No message found in order"
            return 1
        fi

        print_debug "Signature type: $signature_type, Primary type: $primary_type"
        local signature=""

        if [ "$signature_type" = "erc3009" ]; then
            print_info "Signing ERC-3009 order..."

            # Check if this is a multi-signature order (new format)
            local signatures_array=$(echo "$full_message" | jq -r '.signatures // empty')

            if [ -n "$signatures_array" ] && [ "$signatures_array" != "null" ] && [ "$signatures_array" != "empty" ]; then
                # Handle multiple signatures (new format from quote generator)
                print_info "Processing multiple ERC-3009 signatures..."

                local signature_count=$(echo "$signatures_array" | jq '. | length')
                print_debug "Number of signatures required: $signature_count"

                local signatures_bytes_array=""
                local i=0

                # Process each signature in the array
                while [ $i -lt "$signature_count" ]; do
                    local sig_message=$(echo "$signatures_array" | jq -r ".[$i]")

                    # Parse individual signature message
                    local domain_address=$(echo "$order_data" | jq -r '.domain // empty')
                    local uii_parsed=$(from_uii_address "$domain_address")
                    local origin_chain_id=$(echo "$uii_parsed" | cut -d' ' -f1)
                    local token_contract=$(echo "$uii_parsed" | cut -d' ' -f2)

                    local from_address=$(echo "$sig_message" | jq -r '.from // empty')
                    local to_address=$(echo "$sig_message" | jq -r '.to // empty')
                    local value=$(echo "$sig_message" | jq -r '.value // empty')
                    local valid_after=$(echo "$sig_message" | jq -r '.validAfter // 0')
                    local valid_before=$(echo "$sig_message" | jq -r '.validBefore // 0')
                    local nonce=$(echo "$sig_message" | jq -r '.nonce // empty')

                    print_debug "Signature $((i+1)): token=$token_contract, value=$value, nonce=$nonce"

                    # Sign this individual ERC-3009 authorization
                    local individual_signature=$(sign_erc3009_authorization \
                        "$user_key" "$origin_chain_id" "$token_contract" \
                        "$from_address" "$to_address" "$value" \
                        "$valid_after" "$valid_before" "$nonce")

                    if [ -z "$individual_signature" ]; then
                        print_error "Failed to sign ERC-3009 order $((i+1))"
                        return 1
                    fi

                    # Add this signature to the array (no prefix for individual signatures)
                    if [ -z "$signatures_bytes_array" ]; then
                        signatures_bytes_array="$individual_signature"
                    else
                        signatures_bytes_array="$signatures_bytes_array,$individual_signature"
                    fi

                    i=$((i+1))
                done

                # Encode the signatures array and add ERC-3009 prefix
                local encoded_signatures=$(cast abi-encode "f(bytes[])" "[$signatures_bytes_array]")
                signature=$(create_prefixed_signature "$encoded_signatures" "eip3009")

                print_success "Multiple ERC-3009 orders signed successfully ($signature_count signatures)"

            else
                # Handle single signature (backwards compatibility)
                print_info "Processing single ERC-3009 signature..."

                # For ERC-3009, we use the domain address as the token contract address
                local domain_address=$(echo "$order_data" | jq -r '.domain // empty')

                # Parse UII address to get chain ID and token address
                print_debug "Domain address (UII): $domain_address"
                local uii_parsed=$(from_uii_address "$domain_address")
                print_debug "UII parsed result: '$uii_parsed'"
                local origin_chain_id=$(echo "$uii_parsed" | cut -d' ' -f1)
                local token_contract=$(echo "$uii_parsed" | cut -d' ' -f2)

                # Extract ERC-3009 fields directly from message
                local from_address=$(echo "$full_message" | jq -r '.from // empty')
                local to_address=$(echo "$full_message" | jq -r '.to // empty')
                local value=$(echo "$full_message" | jq -r '.value // empty')
                local valid_after=$(echo "$full_message" | jq -r '.validAfter // 0')
                local valid_before=$(echo "$full_message" | jq -r '.validBefore // 0')
                local nonce=$(echo "$full_message" | jq -r '.nonce // empty')

                print_debug "ERC-3009 params: chain_id=$origin_chain_id, token=$token_contract"
                print_debug "ERC-3009 params: from=$from_address, to=$to_address, value=$value, nonce=$nonce"

                # For ERC-3009, we need to calculate the correct orderIdentifier from the contract
                # because the quote nonce is temporary. Use same approach as working direct intent.
                print_debug "Computing orderIdentifier from contract for ERC-3009 nonce (same method as direct intent)..."

                # Get RPC URL for the chain
                local rpc_url="http://localhost:8545"
                if [ "$origin_chain_id" = "31338" ]; then
                    rpc_url="http://localhost:8546"
                fi

                # Get input settler address for the chain
                local input_settler_address
                if [ "$origin_chain_id" = "31337" ]; then
                    input_settler_address="0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
                else
                    input_settler_address="0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
                fi

                # Build StandardOrder struct using the same approach as intents script
                # Use valid_before as both fill_deadline and expiry (this is the key fix)
                local fill_deadline="$valid_before"
                local expiry="$valid_before"
                local input_oracle="0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"

                # Build input tokens array: [[token, amount]]
                local input_tokens="[[$token_contract,$value]]"

                # Build outputs array (empty for ERC-3009 order ID calculation)
                local outputs_array="[]"

                # Build StandardOrder struct (same format as intents script)
                local order_struct="($from_address,0,$origin_chain_id,$expiry,$fill_deadline,$input_oracle,$input_tokens,$outputs_array)"

                # Use same orderIdentifier signature as working intents script
                local order_identifier_sig="orderIdentifier((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))"
                print_debug "Calling contract to get order identifier with order_struct: $order_struct"
                print_debug "Input settler address: $input_settler_address"
                print_debug "RPC URL: $rpc_url"
                
                # Capture cast call output and filter out any debug logs
                # We need to suppress RUST_LOG temporarily to avoid contamination
                local old_rust_log="${RUST_LOG:-}"
                export RUST_LOG=""
                
                local cast_output=$(cast call "$input_settler_address" \
                    "$order_identifier_sig" \
                    "$order_struct" \
                    --rpc-url "$rpc_url" 2>/dev/null)
                local cast_exit_code=$?
                
                # Restore original RUST_LOG
                if [ -n "$old_rust_log" ]; then
                    export RUST_LOG="$old_rust_log"
                else
                    unset RUST_LOG
                fi
                
                print_debug "Cast exit code: $cast_exit_code"
                print_debug "Cast output: '$cast_output'"
                
                local contract_nonce=""
                if [ $cast_exit_code -eq 0 ] && [ -n "$cast_output" ]; then
                    # Filter out any remaining ANSI codes or debug text, keep only the hex result
                    contract_nonce=$(echo "$cast_output" | grep -o "0x[0-9a-fA-F]\{64\}" | head -1)
                    print_debug "Filtered contract nonce: '$contract_nonce'"
                else
                    print_error "Cast call failed with exit code $cast_exit_code: $cast_output"
                fi

                print_debug "Contract returned nonce: '$contract_nonce'"
                print_debug "Original quote nonce: '$nonce'"

                # For ERC-3009 quotes, ALWAYS use the original quote nonce (order_identifier)
                # The quote was generated with a specific order_identifier that was calculated by the solver
                # Recalculating with a different structure will give a different order_identifier
                local final_nonce="$nonce"
                print_debug "Final nonce for ERC-3009: $final_nonce (using original quote nonce)"
                
                if [ -n "$contract_nonce" ] && [ "$contract_nonce" != "" ] && [ "$contract_nonce" != "$nonce" ]; then
                    print_warning "Contract calculated different nonce ($contract_nonce) vs quote nonce ($nonce). Using quote nonce to maintain signature consistency."
                fi

                # Debug: Show exactly what parameters are being used for signing
                print_debug "=== ERC-3009 SIGNING PARAMETERS ==="
                print_debug "user_key: ${#user_key} chars"
                print_debug "origin_chain_id: $origin_chain_id"
                print_debug "token_contract: $token_contract"
                print_debug "from_address: $from_address"
                print_debug "to_address: $to_address"
                print_debug "value: $value"
                print_debug "valid_after: $valid_after"
                print_debug "valid_before: $valid_before"
                print_debug "final_nonce: $final_nonce"
                print_debug "=================================="

                # Sign ERC-3009 authorization with the correct nonce
                signature=$(sign_erc3009_authorization \
                    "$user_key" "$origin_chain_id" "$token_contract" \
                    "$from_address" "$to_address" "$value" \
                    "$valid_after" "$valid_before" "$final_nonce")

                if [ -z "$signature" ]; then
                    print_error "Failed to sign ERC-3009 order"
                    return 1
                fi

                # Add ERC-3009 prefix to signature (like in intent flow)
                signature=$(create_prefixed_signature "$signature" "eip3009")

                print_success "ERC-3009 order signed successfully"
            fi
            
        elif [ "$signature_type" = "eip712" ]; then
            print_info "Signing EIP-712 order..."

            # Extract EIP-712 message for signing (for compatibility with existing code)
            local eip712_message=$(echo "$full_message" | jq -r '.eip712 // empty')
            if [ -z "$eip712_message" ] || [ "$eip712_message" = "null" ]; then
                print_error "No EIP-712 message found in EIP-712 order"
                return 1
            fi

            # Determine the order type based on primaryType
            local eip712_primary_type=$(echo "$eip712_message" | jq -r '.primaryType // "PermitBatchWitnessTransferFrom"')
            print_debug "EIP-712 Primary type: $eip712_primary_type"

            if [ "$eip712_primary_type" = "BatchCompact" ]; then
                print_info "Detected BatchCompact order, using compact signing..."

                # Use client-side digest computation
                signature=$(sign_compact_digest_from_quote "$user_key" "$full_message")

                if [ -z "$signature" ]; then
                    print_error "Failed to sign BatchCompact order"
                    return 1
                fi

                print_success "BatchCompact order signed successfully"

                # For compact/resource lock, we need to ABI-encode the signature with allocator data
                # This matches what the working direct intent flow does in intents.sh
                local allocator_data="0x"  # Empty allocator data for demo
                signature=$(cast abi-encode "f(bytes,bytes)" "$signature" "$allocator_data")

                print_debug "ABI-encoded signature: $signature"

            else
                print_info "Detected Permit2 order, using standard signing..."

            # Extract witness data first (needed for signing)
            local witness=$(echo "$eip712_message" | jq -r '.witness // empty')
            local witness_expires=$(echo "$witness" | jq -r '.expires // 0')
            local input_oracle=$(echo "$witness" | jq -r '.inputOracle // "0x0000000000000000000000000000000000000000"')

            # Sign the EIP-712 message
            local domain=$(echo "$eip712_message" | jq -r '.signing.domain // empty')
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

            # Use client-side digest computation but with proper signature formatting
            print_info "Computing client-side digest..."
            local client_digest=$(compute_permit2_digest_from_quote "$eip712_message")
            if [ $? -ne 0 ] || [ -z "$client_digest" ]; then
                print_error "Failed to compute client-side digest"
                return 1
            fi
            print_debug "Client computed digest: $client_digest"
            print_info "Signing with client-computed digest: $client_digest"

            # Sign the digest directly and add proper permit2 prefix
            local raw_signature=$(cast wallet sign --no-hash --private-key "$user_key" "$client_digest")
            if [ $? -ne 0 ] || [ -z "$raw_signature" ]; then
                print_error "Failed to sign digest"
                return 1
            fi

                # Create prefixed signature for permit2
                signature=$(create_prefixed_signature "$raw_signature" "permit2")

                if [ -z "$signature" ]; then
                    print_error "Failed to sign EIP-712 order"
                    return 1
                fi

                print_success "Permit2 signature generated with client-side digest"
            fi
            
            print_success "EIP-712 order signed"
        else
            print_error "Unsupported signature type: $signature_type"
            return 1
        fi
        
        print_debug "Signature: $signature"
        
        # Create submission payload with quoteId
        local submission_json=$(jq -n \
            --arg quoteId "$quote_id" \
            --arg signature "$signature" \
            '{
                quoteId: $quoteId,
                signature: $signature
            }')
        
        # Save request to file
        local request_file="${OUTPUT_DIR:-./demo-output}/post_quote.req.json"
        echo "$submission_json" | jq '.' > "$request_file"
        print_info "Request saved to: $request_file"
        
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

        # api_post will automatically handle JWT authentication via jwt_ensure_token
        if api_post "$api_url" "$submission_json"; then
            local status_code=$(get_api_response "status_code")
            local response_body=$(get_api_response "body")
            
            print_success "Quote order submitted successfully (HTTP $status_code)"
            print_debug "API Response body:"
            if [ "${DEBUG:-0}" = "1" ]; then
                echo "$response_body" | jq '.' >&2 || echo "$response_body" >&2
            fi
            
            # Save submission response
            local output_file="${OUTPUT_DIR:-./demo-output}/post_quote.res.json"
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
                    local output_file="${OUTPUT_DIR:-./demo-output}/post_quote.res.json"
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
    local intent_type="${1:-escrow}"
    local auth_type=""
    local token_pair=""
    
    # Parse arguments based on intent type
    if [ "$intent_type" = "compact" ]; then
        # Compact: no auth type needed
        token_pair="${2:-A2B}"
    else
        # Escrow: auth type required
        auth_type="${2:-permit2}"
        token_pair="${3:-A2B}"
        
        # Validate auth type for escrow
        if [[ "$auth_type" != "permit2" && "$auth_type" != "eip3009" ]]; then
            print_error "Invalid auth type for escrow: $auth_type"
            print_info "Supported auth types for escrow: permit2, eip3009"
            print_info "Usage: quote test escrow <permit2|eip3009> <A2A|A2B|B2A|B2B>"
            return 1
        fi
    fi
    
    # Validate intent type
    if [[ "$intent_type" != "escrow" && "$intent_type" != "compact" ]]; then
        print_error "Invalid intent type: $intent_type"
        print_info "Usage: quote test escrow <permit2|eip3009> <A2A|A2B|B2A|B2B>"
        print_info "Usage: quote test compact <A2A|A2B|B2A|B2B>"
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
    
    # Build header based on intent type
    if [ "$intent_type" = "compact" ]; then
        print_header "Testing quote flow: compact (BatchCompact), ${from_token} → ${to_token}"
    else
        print_header "Testing quote flow: ${intent_type} with ${auth_type} auth, ${from_token} → ${to_token}"
    fi
    
    # Step 1: Build intent
    if [ "$intent_type" = "compact" ]; then
        print_step "Building compact intent"
        
        if ! intent_build "compact" "$origin_chain" "$dest_chain" "$from_token" "$to_token"; then
            print_error "Failed to build compact intent"
            return 1
        fi
    else
        print_step "Building ${intent_type} intent with ${auth_type} auth"
        
        if ! intent_build "$intent_type" "$auth_type" "$origin_chain" "$dest_chain" "$from_token" "$to_token"; then
            print_error "Failed to build ${intent_type} intent with ${auth_type} auth"
            return 1
        fi
    fi
    
    print_success "Intent built successfully"
    
    # Step 2: Get quote
    print_step "Getting quote"
    local intent_file="${OUTPUT_DIR:-./demo-output}/get_quote.req.json"
    
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
    local quote_file="${OUTPUT_DIR:-./demo-output}/get_quote.res.json"
    
    if [ ! -f "$quote_file" ]; then
        print_error "Quote file not found: $quote_file"
        return 1
    fi
    
    # Accept with auto-execute flag to skip confirmation
    if ! quote_accept "$quote_file" 0 true; then
        print_error "Failed to accept quote"
        return 1
    fi
    
    print_success "Quote test completed: ${intent_type} ${token_pair}"
    
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
export -f show_quote_summary
export -f show_quote_details
export -f list_quotes
export -f is_quote_valid
export -f get_quote_time_remaining
export -f compare_quotes
export -f quote_get
export -f quote_accept
export -f quote_test