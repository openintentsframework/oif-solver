#!/bin/bash
# Universal Gas Estimation Script
# Estimates gas usage for different lock and auth type combinations
#
# Usage: ./estimate_gas.sh [lock_type] [auth_type]
#   lock_type: compact, escrow (default: compact)
#   auth_type: permit2, eip3009 (default: permit2)
#
# Examples:
#   ./estimate_gas.sh                    # Uses compact + permit2
#   ./estimate_gas.sh escrow eip3009     # EIP-3009 escrow
#   ./estimate_gas.sh escrow permit2     # Permit2 escrow
#   ./estimate_gas.sh compact permit2    # Compact resource lock

set -e

# Parse arguments
LOCK_TYPE="${1:-compact}"
AUTH_TYPE="${2:-permit2}"

# Validate arguments
if [[ "$LOCK_TYPE" != "compact" && "$LOCK_TYPE" != "escrow" ]]; then
    echo "❌ Invalid lock_type: $LOCK_TYPE (must be 'compact' or 'escrow')"
    exit 1
fi

if [[ "$AUTH_TYPE" != "permit2" && "$AUTH_TYPE" != "eip3009" ]]; then
    echo "❌ Invalid auth_type: $AUTH_TYPE (must be 'permit2' or 'eip3009')"
    exit 1
fi

# Validate combination
if [[ "$LOCK_TYPE" == "compact" && "$AUTH_TYPE" == "eip3009" ]]; then
    echo "❌ Invalid combination: compact lock doesn't support EIP-3009"
    echo "   Compact resource lock only works with Permit2"
    exit 1
fi

SOLVER_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# Set description based on combination
DESCRIPTION=""
case "${LOCK_TYPE}_${AUTH_TYPE}" in
    "compact_permit2")
        DESCRIPTION="Compact Resource Lock with BatchCompact"
        ;;
    "escrow_eip3009")
        DESCRIPTION="Escrow with EIP-3009"
        ;;
    "escrow_permit2")
        DESCRIPTION="Escrow with Permit2"
        ;;
esac

echo "🚀 Gas Estimation: $DESCRIPTION"
echo "===================================================="
echo "🔧 Lock Type: $LOCK_TYPE"
if [[ "$LOCK_TYPE" == "compact" ]]; then
    echo "🔧 Auth Type: BatchCompact"
else
    echo "🔧 Auth Type: $AUTH_TYPE"
fi
echo "🔧 Solver address: $SOLVER_ADDR"
echo "🔧 Normalized: $(echo "$SOLVER_ADDR" | tr '[:upper:]' '[:lower:]')"

# Function to find transaction by specific nonce - efficient search
find_tx_by_nonce() {
    local target_nonce=$1
    local rpc_url=$2
    local chain_name=$3
    
    echo "    🔍 Searching for $chain_name nonce $target_nonce..." >&2
    
    local current_block=$(cast block-number --rpc-url "$rpc_url")
    local search_blocks=800
    local start_block=$((current_block - search_blocks))
    if [ $start_block -lt 0 ]; then start_block=0; fi
    echo "    📋 Scanning recent blocks $start_block to $current_block..." >&2

    local solver_lc=$(echo "$SOLVER_ADDR" | tr '[:upper:]' '[:lower:]')
    local nonce_hex=$(cast to-hex "$target_nonce" 2>/dev/null)

    for block in $(seq $current_block -1 $start_block); do
        local tx_hash=$(cast block $block --full --json --rpc-url "$rpc_url" 2>/dev/null \
            | jq -r --arg from "$solver_lc" --arg nonce "$nonce_hex" \
                '.transactions[]? | select(((.from // "") | ascii_downcase) == $from and (.nonce // "") == $nonce) | .hash' \
            | head -n 1 | tr -d '\r')
        if [ -n "$tx_hash" ]; then
            echo "    ✅ Found $chain_name TX: $tx_hash (block $block, nonce $target_nonce)" >&2
            echo "$tx_hash"
            return 0
        fi
        if [ $((block % 100)) -eq 0 ]; then echo "      ... searching block $block" >&2; fi
    done
    echo "    ❌ Could not find transaction with nonce $target_nonce in recent $search_blocks blocks" >&2
    return 1
}

# Get baseline nonces
echo "📊 Getting baseline nonces..."
origin_nonce_before=$(cast nonce "$SOLVER_ADDR" --rpc-url http://localhost:8545)
dest_nonce_before=$(cast nonce "$SOLVER_ADDR" --rpc-url http://localhost:8546)
origin_before_dec=$(cast to-dec "$origin_nonce_before")
dest_before_dec=$(cast to-dec "$dest_nonce_before")
echo "   Origin nonce: $origin_before_dec"
echo "   Dest nonce:   $dest_before_dec"

# Run the intent with specified lock and auth type
echo ""
echo "📤 Sending intent ($LOCK_TYPE + $AUTH_TYPE)..."

# Check if oif-demo exists in current directory or PATH
if [ -x "./oif-demo" ]; then
    OIF_DEMO_CMD="./oif-demo"
elif command -v oif-demo > /dev/null 2>&1; then
    OIF_DEMO_CMD="oif-demo"
else
    echo "❌ Error: oif-demo not found. Please run from project root or ensure oif-demo is built."
    exit 1
fi

$OIF_DEMO_CMD intent test "$LOCK_TYPE" "$AUTH_TYPE" A2B

# Wait for transactions to be mined
echo "⏳ Waiting for transactions to be mined..."
echo "   (This may take 30-60 seconds for all transactions to complete)"
sleep 35

# Get new nonces
echo "📊 Getting new nonces..."
origin_nonce_after=$(cast nonce "$SOLVER_ADDR" --rpc-url http://localhost:8545)
dest_nonce_after=$(cast nonce "$SOLVER_ADDR" --rpc-url http://localhost:8546)
origin_after_dec=$(cast to-dec "$origin_nonce_after")
dest_after_dec=$(cast to-dec "$dest_nonce_after")
echo "   Origin nonce: $origin_after_dec"
echo "   Dest nonce:   $dest_after_dec"

# Calculate how many transactions were sent
origin_tx_count=$((origin_after_dec - origin_before_dec))
dest_tx_count=$((dest_after_dec - dest_before_dec))

echo ""
echo "📊 Transactions created:"
echo "   Origin: $origin_tx_count transaction(s)"
echo "   Destination: $dest_tx_count transaction(s)"

# Track transactions and gas
declare -a origin_txs=()
declare -a dest_txs=()
origin_total_gas=0
dest_total_gas=0

# Individual gas tracking
open_gas=0
fill_gas=0
post_fill_gas=0
pre_claim_gas=0
claim_gas=0

# Find origin transactions
if [ $origin_tx_count -gt 0 ]; then
    echo ""
    echo "🔍 Finding Origin chain transactions..."
    for i in $(seq 0 $((origin_tx_count - 1))); do
        nonce=$((origin_before_dec + i))
        echo "  Looking for Origin nonce $nonce..."
        if tx_hash=$(find_tx_by_nonce "$nonce" "http://localhost:8545" "Origin"); then
            origin_txs+=("$tx_hash")
            gas_used=$(cast receipt "$tx_hash" --rpc-url http://localhost:8545 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
            origin_total_gas=$((origin_total_gas + gas_used))
            echo "    💰 Gas used: $gas_used"
        fi
    done
fi

# Find destination transactions  
if [ $dest_tx_count -gt 0 ]; then
    echo ""
    echo "🔍 Finding Destination chain transactions..."
    for i in $(seq 0 $((dest_tx_count - 1))); do
        nonce=$((dest_before_dec + i))
        echo "  Looking for Dest nonce $nonce..."
        if tx_hash=$(find_tx_by_nonce "$nonce" "http://localhost:8546" "Dest"); then
            dest_txs+=("$tx_hash")
            gas_used=$(cast receipt "$tx_hash" --rpc-url http://localhost:8546 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
            dest_total_gas=$((dest_total_gas + gas_used))
            echo "    💰 Gas used: $gas_used"
        fi
    done
fi

# Display results based on lock type
echo ""
echo "============================================="
echo "⛽ GAS ESTIMATION RESULTS: $DESCRIPTION"
echo "============================================="

# Parse individual transaction gas costs
if [[ "$LOCK_TYPE" == "compact" ]]; then
    # Compact flow: Fill -> PostFill (dest), PreClaim -> Claim (origin)
    if [ ${#dest_txs[@]} -ge 1 ]; then
        fill_gas=$(cast receipt "${dest_txs[0]}" --rpc-url http://localhost:8546 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
    if [ ${#dest_txs[@]} -ge 2 ]; then
        post_fill_gas=$(cast receipt "${dest_txs[1]}" --rpc-url http://localhost:8546 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
    if [ ${#origin_txs[@]} -ge 1 ]; then
        pre_claim_gas=$(cast receipt "${origin_txs[0]}" --rpc-url http://localhost:8545 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
    if [ ${#origin_txs[@]} -ge 2 ]; then
        claim_gas=$(cast receipt "${origin_txs[1]}" --rpc-url http://localhost:8545 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
else
    # Escrow flow: Open (origin), Fill -> PostFill (dest), PreClaim -> Claim (origin)
    if [ ${#origin_txs[@]} -ge 1 ]; then
        open_gas=$(cast receipt "${origin_txs[0]}" --rpc-url http://localhost:8545 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
    if [ ${#dest_txs[@]} -ge 1 ]; then
        fill_gas=$(cast receipt "${dest_txs[0]}" --rpc-url http://localhost:8546 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
    if [ ${#dest_txs[@]} -ge 2 ]; then
        post_fill_gas=$(cast receipt "${dest_txs[1]}" --rpc-url http://localhost:8546 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
    if [ ${#origin_txs[@]} -ge 2 ]; then
        pre_claim_gas=$(cast receipt "${origin_txs[1]}" --rpc-url http://localhost:8545 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
    if [ ${#origin_txs[@]} -ge 3 ]; then
        claim_gas=$(cast receipt "${origin_txs[2]}" --rpc-url http://localhost:8545 --json 2>/dev/null | jq -r '.gasUsed' | cast to-dec)
    fi
fi

# Display detailed results
echo "📍 Transaction Breakdown:"
if [[ "$LOCK_TYPE" == "escrow" ]]; then
    echo "   Open:     $open_gas gas (origin)"
fi
echo "   Fill:     $fill_gas gas (destination)"
echo "   PostFill: $post_fill_gas gas (destination)"
echo "   PreClaim: $pre_claim_gas gas (origin)"
echo "   Claim:    $claim_gas gas (origin)"
echo ""
echo "📍 Chain Totals:"
echo "   Origin:      $origin_total_gas gas"
echo "   Destination: $dest_total_gas gas"

echo ""
echo "🎯 Total Gas Used:"
echo "   Origin:      $origin_total_gas gas"
echo "   Destination: $dest_total_gas gas"
echo "   Grand Total: $((origin_total_gas + dest_total_gas)) gas"
echo "============================================="

# Update config suggestion for testnet-config.json
echo ""
echo "📝 Suggested config update for testnet-config.json:"
echo ""
echo "  \"gas_estimates\": {"

case "${LOCK_TYPE}_${AUTH_TYPE}" in
    "compact_permit2")
        echo "    \"compact_batch\": {"
        echo "      \"fill\": ${fill_gas:-0},"
        echo "      \"post_fill\": ${post_fill_gas:-0},"
        echo "      \"pre_claim\": ${pre_claim_gas:-0},"
        echo "      \"claim\": ${claim_gas:-0}"
        echo "    }"
        ;;
    "escrow_permit2")
        echo "    \"permit2_escrow\": {"
        echo "      \"open\": ${open_gas:-0},"
        echo "      \"fill\": ${fill_gas:-0},"
        echo "      \"post_fill\": ${post_fill_gas:-0},"
        echo "      \"pre_claim\": ${pre_claim_gas:-0},"
        echo "      \"claim\": ${claim_gas:-0}"
        echo "    }"
        ;;
    "escrow_eip3009")
        echo "    \"eip3009_escrow\": {"
        echo "      \"open\": ${open_gas:-0},"
        echo "      \"fill\": ${fill_gas:-0},"
        echo "      \"post_fill\": ${post_fill_gas:-0},"
        echo "      \"pre_claim\": ${pre_claim_gas:-0},"
        echo "      \"claim\": ${claim_gas:-0}"
        echo "    }"
        ;;
esac

echo "  }"
echo ""
echo "✅ Gas estimation complete!"