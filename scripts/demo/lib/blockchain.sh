#!/usr/bin/env bash
#
# ==============================================================================
# Blockchain Module - Chain Interactions and Balance Management
# ==============================================================================
#
# This module provides all blockchain interaction functionality including
# balance checking, transaction monitoring, and multi-chain operations.
#
# Key Features:
# - Multi-chain balance queries (ETH and ERC20 tokens)
# - Account balance tracking (user, solver, settlers, recipients)
# - Settler contract balance monitoring
# - Real-time balance monitoring with auto-refresh
# - Token approval status checking
# - Gas estimation and transaction utilities
#
# Supported Account Types:
# - User: Main wallet account
# - Recipient: Intent recipient account
# - Solver: Solver service account
# - Settlers: Escrow and Compact settler contracts
#
# Dependencies:
# - cast: Foundry's CLI tool for blockchain interactions
# - config.sh: For network and account configuration
# - ui.sh: For formatted output display
#
# Usage:
#   get_balance 31337 0xAddress TokenA
#   show_all_balances
#   monitor_balances 5 user
#
# ==============================================================================

# -----------------------------------------------------------------------------
# Balance Query Functions
# -----------------------------------------------------------------------------
# Get balance for any address on any chain
get_balance() {
    local chain_id="$1"
    local address="$2"
    local token="${3:-ETH}"
    
    local rpc_url=$(config_get_network "$chain_id" "rpc_url")
    
    if [ "$token" = "ETH" ]; then
        cast balance "$address" --rpc-url "$rpc_url" 2>/dev/null || echo "0"
    else
        cast call "$token" "balanceOf(address)(uint256)" \
             "$address" --rpc-url "$rpc_url" 2>/dev/null || echo "0"
    fi
}

# Get user balances
get_user_balances() {
    local user_addr=$(config_get_account "user" "address")
    local short_user="${user_addr:0:6}...${user_addr: -4}"
    
    print_balance_table "USER BALANCES ($short_user)"
    print_balance_section "Chain 31337 (Origin)"
    
    # Get token addresses by symbol
    local tokena_origin=$(config_get_token_by_symbol "31337" "TOKA")
    local tokenb_origin=$(config_get_token_by_symbol "31337" "TOKB")
    
    # Get balances
    local tokena_balance=$(get_balance "31337" "$user_addr" "$tokena_origin")
    local tokenb_balance=$(get_balance "31337" "$user_addr" "$tokenb_origin")
    
    print_balance_row "TokenA" "$(format_balance $tokena_balance)" "TOKA"
    print_balance_row "TokenB" "$(format_balance $tokenb_balance)" "TOKB"
    
    print_balance_end
}

# Get recipient balances
get_recipient_balances() {
    local recipient_addr=$(config_get_account "recipient" "address")
    local short_recipient="${recipient_addr:0:6}...${recipient_addr: -4}"
    
    print_balance_table "RECIPIENT BALANCES ($short_recipient)"
    
    # Origin chain
    print_balance_section "Chain 31337 (Origin)"
    local tokena_origin=$(config_get_token_by_symbol "31337" "TOKA")
    local tokenb_origin=$(config_get_token_by_symbol "31337" "TOKB")
    
    # Get balances
    local tokena_balance=$(get_balance "31337" "$recipient_addr" "$tokena_origin")
    local tokenb_balance=$(get_balance "31337" "$recipient_addr" "$tokenb_origin")
    
    print_balance_row "TokenA" "$(format_balance $tokena_balance)" "TOKA"
    print_balance_row "TokenB" "$(format_balance $tokenb_balance)" "TOKB"
    
    # Destination chain
    print_balance_section "Chain 31338 (Destination)"
    local tokena_dest=$(config_get_token_by_symbol "31338" "TOKA")
    local tokenb_dest=$(config_get_token_by_symbol "31338" "TOKB")
    
    # Get balances
    tokena_balance=$(get_balance "31338" "$recipient_addr" "$tokena_dest")
    tokenb_balance=$(get_balance "31338" "$recipient_addr" "$tokenb_dest")
    
    print_balance_row "TokenA" "$(format_balance $tokena_balance)" "TOKA"
    print_balance_row "TokenB" "$(format_balance $tokenb_balance)" "TOKB"
    
    print_balance_end
}

# Get solver balances
get_solver_balances() {
    local solver_addr=$(config_get_account "solver" "address")
    local short_solver="${solver_addr:0:6}...${solver_addr: -4}"
    
    print_balance_table "SOLVER BALANCES ($short_solver)"
    
    # Origin chain
    print_balance_section "Chain 31337 (Origin)"
    local tokena_origin=$(config_get_token_by_symbol "31337" "TOKA")
    local tokenb_origin=$(config_get_token_by_symbol "31337" "TOKB")
    local tokena_balance=$(get_balance "31337" "$solver_addr" "$tokena_origin")
    local tokenb_balance=$(get_balance "31337" "$solver_addr" "$tokenb_origin")
    print_balance_row "TokenA" "$(format_balance $tokena_balance)" "TOKA"
    print_balance_row "TokenB" "$(format_balance $tokenb_balance)" "TOKB"
    
    # Destination chain
    print_balance_section "Chain 31338 (Destination)"
    local tokena_dest=$(config_get_token_by_symbol "31338" "TOKA")
    local tokenb_dest=$(config_get_token_by_symbol "31338" "TOKB")
    tokena_balance=$(get_balance "31338" "$solver_addr" "$tokena_dest")
    tokenb_balance=$(get_balance "31338" "$solver_addr" "$tokenb_dest")
    print_balance_row "TokenA" "$(format_balance $tokena_balance)" "TOKA"
    print_balance_row "TokenB" "$(format_balance $tokenb_balance)" "TOKB"
    
    print_balance_end
}

# Get settler balances
get_settler_balances() {
    local settlement_type="${1:-all}"
    
    print_balance_table "SETTLER BALANCES"
    
    if [[ "$settlement_type" == "escrow" || "$settlement_type" == "all" ]]; then
        check_escrow_balances
    fi
    
    if [[ "$settlement_type" == "compact" || "$settlement_type" == "all" ]]; then
        check_compact_balances
    fi
    
    if [[ "$settlement_type" == "all" ]]; then
        check_output_settler_balances
    fi
    
    print_balance_end
}

# Check escrow settler balances
check_escrow_balances() {
    local escrow_addr=$(config_get_network "31337" "input_settler_address")
    
    if [ -n "$escrow_addr" ]; then
        print_balance_section "InputSettlerEscrow (Chain 31337)"
        
        local tokena=$(config_get_token_by_symbol "31337" "TOKA")
        local tokenb=$(config_get_token_by_symbol "31337" "TOKB")
        
        local tokena_balance=$(get_balance "31337" "$escrow_addr" "$tokena")
        local tokenb_balance=$(get_balance "31337" "$escrow_addr" "$tokenb")
        
        print_balance_row "TokenA" "$(format_balance $tokena_balance)" "TOKA"
        print_balance_row "TokenB" "$(format_balance $tokenb_balance)" "TOKB"
    fi
}

# Check compact settler balances
check_compact_balances() {
    local compact_addr=$(config_get_network "31337" "input_settler_compact_address")
    local the_compact_addr=$(config_get_network "31337" "the_compact_address")
    
    if [ -n "$compact_addr" ]; then
        print_balance_section "InputSettlerCompact (Chain 31337)"
        
        local tokena=$(config_get_token_by_symbol "31337" "TOKA")
        local tokenb=$(config_get_token_by_symbol "31337" "TOKB")
        
        local tokena_balance=$(get_balance "31337" "$compact_addr" "$tokena")
        local tokenb_balance=$(get_balance "31337" "$compact_addr" "$tokenb")
        
        print_balance_row "TokenA" "$(format_balance $tokena_balance)" "TOKA"
        print_balance_row "TokenB" "$(format_balance $tokenb_balance)" "TOKB"
    fi
    
    # Check resource locks in TheCompact if available
    if [ -n "$the_compact_addr" ]; then
        check_resource_locks "$the_compact_addr"
    fi
}

# Check output settler balances
check_output_settler_balances() {
    local output_addr=$(config_get_network "31338" "output_settler_address")
    
    if [ -n "$output_addr" ]; then
        print_balance_section "OutputSettler (Chain 31338)"
        
        local tokena=$(config_get_token_by_symbol "31338" "TOKA")
        local tokenb=$(config_get_token_by_symbol "31338" "TOKB")
        
        local tokena_balance=$(get_balance "31338" "$output_addr" "$tokena")
        local tokenb_balance=$(get_balance "31338" "$output_addr" "$tokenb")
        
        print_balance_row "TokenA" "$(format_balance $tokena_balance)" "TOKA"
        print_balance_row "TokenB" "$(format_balance $tokenb_balance)" "TOKB"
    fi
}

# Check resource locks in TheCompact
check_resource_locks() {
    local the_compact_addr="$1"
    local user_addr=$(config_get_account "user" "address")
    local rpc_url=$(config_get_network "31337" "rpc_url")
    
    # Display TheCompact balance section
    print_balance_section "TheCompact (Resource Locks - Chain 31337)"
    
    # Get token addresses
    local tokena=$(config_get_token_by_symbol "31337" "TOKA")
    local tokenb=$(config_get_token_by_symbol "31337" "TOKB")
    
    # Check direct token balances in TheCompact (tokens held by the contract)
    if [ -n "$the_compact_addr" ] && [ -n "$tokena" ]; then
        local tokena_balance=$(get_balance "31337" "$the_compact_addr" "$tokena")
        local tokenb_balance=$(get_balance "31337" "$the_compact_addr" "$tokenb")
        
        print_balance_row "TokenA (locked)" "$(format_balance $tokena_balance)" "TOKA"
        print_balance_row "TokenB (locked)" "$(format_balance $tokenb_balance)" "TOKB"
        
        # Also show user's resource lock balance if we have the allocator address
        local allocator_address=$(config_get_network "31337" "allocator_address")
        if [ -n "$allocator_address" ] && [ -n "$user_addr" ]; then
            # Generate lock tag from allocator address (0x00 + last 11 bytes)
            # Address format: 0x + 40 hex chars (20 bytes), we want last 11 bytes = last 22 hex chars
            local allocator_lock_tag="0x00$(echo $allocator_address | cut -c21- | tr '[:upper:]' '[:lower:]')"
            # Calculate resource lock ID for TokenA
            local resource_id=$(calculate_resource_lock_id "$allocator_lock_tag" "$tokena")
            local user_lock_balance=$(get_compact_balance "$user_addr" "$resource_id")
            
            if [ "$user_lock_balance" != "0" ]; then
                print_balance_row "User's TokenA locks" "$(format_balance $user_lock_balance)" "TOKA"
            fi
        fi
    fi
}

# Get all balances
get_all_balances() {
    local show_settlers="${1:-true}"
    
    print_balance_table "ALL BALANCES"
    
    # Get configured chains
    local chains=($(config_get_chains))
    
    for chain_id in "${chains[@]}"; do
        print_balance_section "Chain $chain_id"
        
        # Get token count for this chain
        local token_count=$(config_get_network "$chain_id" "token_count" 0)
        
        # Show user balances if configured
        local user_addr=$(config_get_account "user" "address")
        if [ -n "$user_addr" ]; then
            local short_user="${user_addr:0:6}...${user_addr: -4}"
            print_balance_row "User ($short_user)" "" ""
            for ((i=0; i<token_count; i++)); do
                local token_addr=$(config_get_token "$chain_id" "$i" "address")
                local token_symbol=$(config_get_token "$chain_id" "$i" "symbol")
                local balance=$(get_balance "$chain_id" "$user_addr" "$token_addr")
                print_balance_row "  $token_symbol" "$(format_balance $balance)" ""
            done
        fi
        
        # Show recipient balances if configured
        local recipient_addr=$(config_get_account "recipient" "address")
        if [ -n "$recipient_addr" ]; then
            local short_recipient="${recipient_addr:0:6}...${recipient_addr: -4}"
            print_balance_row "Recipient ($short_recipient)" "" ""
            for ((i=0; i<token_count; i++)); do
                local token_addr=$(config_get_token "$chain_id" "$i" "address")
                local token_symbol=$(config_get_token "$chain_id" "$i" "symbol")
                local balance=$(get_balance "$chain_id" "$recipient_addr" "$token_addr")
                print_balance_row "  $token_symbol" "$(format_balance $balance)" ""
            done
        fi
        
        # Show solver balances if configured
        local solver_addr=$(config_get_account "solver" "address")
        if [ -n "$solver_addr" ]; then
            local short_solver="${solver_addr:0:6}...${solver_addr: -4}"
            print_balance_row "Solver ($short_solver)" "" ""
            for ((i=0; i<token_count; i++)); do
                local token_addr=$(config_get_token "$chain_id" "$i" "address")
                local token_symbol=$(config_get_token "$chain_id" "$i" "symbol")
                local balance=$(get_balance "$chain_id" "$solver_addr" "$token_addr")
                print_balance_row "  $token_symbol" "$(format_balance $balance)" ""
            done
        fi
        
        # Show settler balances if requested
        if [ "$show_settlers" = "true" ]; then
            # Check each type of settler
            for settler_type in input_settler_address input_settler_compact_address output_settler_address; do
                local settler_addr=$(config_get_network "$chain_id" "$settler_type")
                if [ -n "$settler_addr" ]; then
                    local settler_name=$(echo $settler_type | sed 's/_address$//' | sed 's/_/ /g')
                    local formatted_name="${settler_name^}"
                    # Truncate address for display: 0x1234...abcd
                    local short_addr="${settler_addr:0:6}...${settler_addr: -4}"
                    print_balance_row "$formatted_name ($short_addr)" "" ""
                    for ((i=0; i<token_count; i++)); do
                        local token_addr=$(config_get_token "$chain_id" "$i" "address")
                        local token_symbol=$(config_get_token "$chain_id" "$i" "symbol")
                        local balance=$(get_balance "$chain_id" "$settler_addr" "$token_addr")
                        print_balance_row "  $token_symbol" "$(format_balance $balance)" ""
                    done
                fi
            done
            
            # Also show TheCompact if it exists (only on origin chain)
            if [ "$chain_id" = "31337" ]; then
                local the_compact_addr=$(config_get_network "$chain_id" "the_compact_address")
                if [ -n "$the_compact_addr" ]; then
                    local short_addr="${the_compact_addr:0:6}...${the_compact_addr: -4}"
                    print_balance_row "TheCompact ($short_addr)" "" ""
                    for ((i=0; i<token_count; i++)); do
                        local token_addr=$(config_get_token "$chain_id" "$i" "address")
                        local token_symbol=$(config_get_token "$chain_id" "$i" "symbol")
                        local balance=$(get_balance "$chain_id" "$the_compact_addr" "$token_addr")
                        if [ "$balance" != "0" ]; then
                            print_balance_row "  $token_symbol (locked)" "$(format_balance $balance)" ""
                        else
                            print_balance_row "  $token_symbol" "$(format_balance $balance)" ""
                        fi
                    done
                fi
            fi
        fi
    done
    
    print_balance_end
}

# Token operations
approve_token() {
    local chain_id="$1"
    local token="$2"
    local spender="$3"
    local amount="$4"
    local private_key="${5:-$(config_get_account user private_key)}"
    
    local rpc_url=$(config_get_network "$chain_id" "rpc_url")
    
    print_info "Approving $amount tokens for $spender..."
    
    cast send "$token" "approve(address,uint256)" \
         "$spender" "$amount" \
         --rpc-url "$rpc_url" \
         --private-key "$private_key" 2>/dev/null
}

# Transaction monitoring
wait_for_tx() {
    local tx_hash="$1"
    local chain_id="$2"
    local confirmations="${3:-1}"
    
    local rpc_url=$(config_get_network "$chain_id" "rpc_url")
    
    print_info "Waiting for transaction confirmation..."
    
    cast receipt "$tx_hash" \
         --rpc-url "$rpc_url" \
         --confirmations "$confirmations" 2>/dev/null
}

monitor_transaction() {
    local tx_hash="$1"
    local chain_id="$2"
    
    print_info "Monitoring transaction $tx_hash on chain $chain_id"
    
    local rpc_url=$(config_get_network "$chain_id" "rpc_url")
    
    # Poll for status
    while true; do
        local receipt=$(cast receipt "$tx_hash" --rpc-url "$rpc_url" 2>/dev/null || echo "")
        
        if [ -n "$receipt" ]; then
            local status=$(echo "$receipt" | grep "status" | awk '{print $2}')
            
            if [ "$status" = "1" ]; then
                print_success "Transaction successful"
                return 0
            elif [ "$status" = "0" ]; then
                print_error "Transaction failed"
                return 1
            fi
        fi
        
        sleep 2
    done
}

# Chain interaction utilities
get_chain_id() {
    local rpc_url="$1"
    cast chain-id --rpc-url "$rpc_url" 2>/dev/null
}

get_block_number() {
    local chain_id="$1"
    local rpc_url=$(config_get_network "$chain_id" "rpc_url")
    cast block-number --rpc-url "$rpc_url" 2>/dev/null
}

get_gas_price() {
    local chain_id="$1"
    local rpc_url=$(config_get_network "$chain_id" "rpc_url")
    cast gas-price --rpc-url "$rpc_url" 2>/dev/null
}

# Get Compact balance (resource locks)
get_compact_balance() {
    local account="$1"
    local resource_lock_id="$2"
    local the_compact_addr=$(config_get_network "31337" "the_compact_address")
    local rpc_url=$(config_get_network "31337" "rpc_url")
    
    cast call "$the_compact_addr" "balanceOf(address,uint256)(uint256)" \
        "$account" "$resource_lock_id" \
        --rpc-url "$rpc_url" 2>/dev/null || echo "0"
}

# Calculate resource lock ID
calculate_resource_lock_id() {
    local lock_tag="$1"     # bytes12
    local token_address="$2"
    
    # Remove 0x prefix and concatenate
    local tag="${lock_tag#0x}"
    local token="${token_address#0x}"
    
    echo "0x${tag}${token}"
}

# Monitor balances with auto-refresh
monitor_balances() {
    local refresh_interval="${1:-5}"  # Default 5 seconds
    local target="${2:-all}"          # Default to all balances
    
    print_info "Monitoring balances (refresh every ${refresh_interval}s, press Ctrl+C to stop)"
    echo ""
    
    while true; do
        # Clear screen for clean refresh
        clear
        
        # Print timestamp
        echo "Last updated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Refresh interval: ${refresh_interval}s"
        echo "Press Ctrl+C to stop monitoring"
        echo ""
        
        # Show requested balances
        case "$target" in
            user)
                get_user_balances
                ;;
            recipient)
                get_recipient_balances
                ;;
            solver)
                get_solver_balances
                ;;
            settlers|settler)
                get_settler_balances "all"
                ;;
            all)
                get_all_balances "true"
                ;;
            *)
                get_all_balances "true"
                ;;
        esac
        
        # Wait before next refresh
        sleep "$refresh_interval"
    done
}

# Export functions
export -f get_balance
export -f get_user_balances
export -f get_recipient_balances
export -f get_solver_balances
export -f get_all_balances
export -f monitor_balances
export -f approve_token
export -f wait_for_tx
export -f monitor_transaction