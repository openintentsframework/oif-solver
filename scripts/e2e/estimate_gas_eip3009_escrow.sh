#!/bin/bash
# Final gas capture - systematically get real gas from solver transactions
# This script captures REAL gas values by tracking nonce changes for EIP-3009 escrow

SOLVER_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

echo "🚀 Systematic Gas Capture (EIP-3009 Escrow)"
echo "============================================"
echo "🔧 Solver address: $SOLVER_ADDR"
echo "🔧 Normalized: $(echo "$SOLVER_ADDR" | tr '[:upper:]' '[:lower:]')"

# Function to find transaction by specific nonce - more efficient approach
find_tx_by_nonce() {
    local target_nonce=$1
    local rpc_url=$2
    local chain_name=$3

    echo "    🔍 Searching for $chain_name nonce $target_nonce..." >&2

    # Get current block and search backwards more efficiently
    local current_block=$(cast block-number --rpc-url "$rpc_url")
    local search_blocks=800  # broader window (~26 min @ 2s)
    local start_block=$((current_block - search_blocks))

    if [ $start_block -lt 0 ]; then
        start_block=0
    fi

    echo "    📋 Scanning recent blocks $start_block to $current_block..." >&2

    # Precompute lowercase solver and hex nonce
    local solver_lc=$(echo "$SOLVER_ADDR" | tr '[:upper:]' '[:lower:]')
    local nonce_hex=$(cast to-hex "$target_nonce" 2>/dev/null)

    # Search backwards from current block (more likely to find recent transactions)
    for block in $(seq $current_block -1 $start_block); do
        # Get block with full tx objects once and filter via jq
        local tx_hash=$(cast block $block --full --json --rpc-url "$rpc_url" 2>/dev/null \
            | jq -r --arg from "$solver_lc" --arg nonce "$nonce_hex" \
                '.transactions[]? | select(((.from // "") | ascii_downcase) == $from and (.nonce // "") == $nonce) | .hash' \
            | head -n 1 | tr -d '\r')

        if [ -n "$tx_hash" ]; then
            echo "    ✅ Found $chain_name TX: $tx_hash (block $block, nonce $target_nonce)" >&2
            # Output ONLY the hash on stdout
            echo "$tx_hash"
            return 0
        fi

        # Progress every 100 blocks
        if [ $((block % 100)) -eq 0 ]; then
            echo "      ... searching block $block" >&2
        fi
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
echo "  Origin: $origin_before_dec"
echo "  Dest: $dest_before_dec"

# Send intent using oif-demo with EIP-3009
echo "📤 Sending EIP-3009 intent..."
./oif-demo intent test escrow eip3009 A2B > /dev/null 2>&1

echo "⏳ Waiting for transaction processing..."
sleep 22  # Wait longer for complete processing

# Get final nonces
origin_nonce_after=$(cast nonce "$SOLVER_ADDR" --rpc-url http://localhost:8545)
dest_nonce_after=$(cast nonce "$SOLVER_ADDR" --rpc-url http://localhost:8546)
origin_after_dec=$(cast to-dec "$origin_nonce_after")
dest_after_dec=$(cast to-dec "$dest_nonce_after")

echo "📊 Nonces after processing:"
echo "  Origin: $origin_before_dec → $origin_after_dec"
echo "  Dest: $dest_before_dec → $dest_after_dec"

# Calculate transaction counts
origin_tx_count=$((origin_after_dec - origin_before_dec))
dest_tx_count=$((dest_after_dec - dest_before_dec))

if [ $origin_tx_count -eq 0 ] && [ $dest_tx_count -eq 0 ]; then
    echo "❌ ERROR: No transactions detected! Make sure solver is running."
    exit 1
fi

echo "🔍 Expected: $origin_tx_count origin + $dest_tx_count dest transactions"

# Systematically find each transaction by its expected nonce - NO FALLBACKS
echo "🔍 Finding transactions systematically (NO fallbacks allowed)..."

origin_txs=""
dest_txs=""
all_found=true

# Find origin transactions (prepare and claim)
echo "  🎯 Origin chain transactions:"
for nonce in $(seq $origin_before_dec $((origin_after_dec-1))); do
    tx_hash=$(find_tx_by_nonce $nonce "http://localhost:8545" "origin" | tail -n1 | tr -d ' \n\r')
    if [ -n "$tx_hash" ]; then
        # Get REAL gas for this transaction
        echo "    📊 Getting gas from receipt..."
        gas_hex=$(cast receipt "$tx_hash" --json --rpc-url http://localhost:8545 | jq -r '.gasUsed')
        gas_dec=$(cast to-dec "$gas_hex")
        echo "      ✅ Real gas: $gas_dec"
        origin_txs="$origin_txs $gas_dec"
    else
        echo "      ❌ Failed to find transaction for nonce $nonce"
        all_found=false
    fi
done

# Find dest transactions (fill)
echo "  🎯 Dest chain transactions:"
for nonce in $(seq $dest_before_dec $((dest_after_dec-1))); do
    tx_hash=$(find_tx_by_nonce $nonce "http://localhost:8546" "dest" | tail -n1 | tr -d ' \n\r')
    if [ -n "$tx_hash" ]; then
        # Get REAL gas for this transaction
        echo "    📊 Getting gas from receipt..."
        gas_hex=$(cast receipt "$tx_hash" --json --rpc-url http://localhost:8546 | jq -r '.gasUsed')
        gas_dec=$(cast to-dec "$gas_hex")
        echo "      ✅ Real gas: $gas_dec"
        dest_txs="$dest_txs $gas_dec"
    else
        echo "      ❌ Failed to find transaction for nonce $nonce"
        all_found=false
    fi
done

# Parse results
origin_array=($origin_txs)
dest_array=($dest_txs)

echo
echo "📊 Systematic discovery results:"
echo "  Origin: ${origin_array[*]:-} (${#origin_array[@]} transactions)"
echo "  Dest: ${dest_array[*]:-} (${#dest_array[@]} transactions)"

# STRICT validation - ALL transactions must be found
if [ "$all_found" = false ] || [ ${#origin_array[@]} -ne $origin_tx_count ] || [ ${#dest_array[@]} -ne $dest_tx_count ]; then
    echo "❌ SYSTEMATIC FAILURE: Could not find all solver transactions!"
    echo "   Expected: $origin_tx_count origin + $dest_tx_count dest transactions"
    echo "   Found: ${#origin_array[@]} origin + ${#dest_array[@]} dest transactions"
    echo ""
    echo "🔧 Debug information:"
    echo "   Origin nonces: $origin_before_dec → $origin_after_dec"
    echo "   Dest nonces: $dest_before_dec → $dest_after_dec"
    echo ""
    echo "💡 The solver executed transactions (nonces increased) but they are not discoverable"
    echo "   in the scanned blocks. Increase search range or capture hashes at source."
    echo ""
    echo "❌ REFUSING to use fallback values. Fix the discovery logic or run again."
    exit 1
fi

# Only proceed if we have REAL gas from ALL transactions
prepare_gas=${origin_array[0]}
fill_gas=${dest_array[0]}
claim_gas=${origin_array[1]}

echo "✅ Successfully found ALL transactions with REAL gas values:"
if [ -n "$prepare_gas" ]; then echo "  Prepare: $prepare_gas gas (from solver transaction)"; fi
if [ -n "$fill_gas" ]; then echo "  Fill: $fill_gas gas (from solver transaction)"; fi
if [ -n "$claim_gas" ]; then echo "  Claim: $claim_gas gas (from solver transaction)"; fi

echo
echo "📊 Gas Results:"
echo "  Prepare: $prepare_gas gas"
echo "  Fill: $fill_gas gas"
echo "  Claim: $claim_gas gas"

total_gas=$((prepare_gas + fill_gas + claim_gas))
echo "  Total: $total_gas gas"

# Create REAL gas snapshot (ONLY with systematically captured data)
mkdir -p snapshots
timestamp=$(date +%s)

cat > snapshots/gas_snapshots_real_eip3009_e2e.json << EOF
{
  "version": "1.0.0",
  "snapshots": {
    "eip3009-escrow_31337": [
      {
        "flow": "eip3009-escrow",
        "chain_id": 31337,
        "open_gas": $prepare_gas,
        "fill_gas": $fill_gas,
        "finalize_gas": $claim_gas,
        "created_at": $timestamp,
        "metadata": {
          "capture_method": "systematic_solver_execution",
          "description": "Gas captured systematically from actual solver transactions using EIP-3009",
          "validation": "All transactions found via nonce tracking and receipt extraction",
          "nonce_ranges": "Origin $origin_before_dec -> $origin_after_dec, Dest $dest_before_dec -> $dest_after_dec",
          "transaction_counts": "Origin: $origin_tx_count, Dest: $dest_tx_count"
        }
      }
    ]
  },
  "last_updated": $timestamp,
  "metadata": {
    "source": "Systematic Solver Execution",
    "methodology": "Gas extracted from solver transactions found via systematic nonce-based discovery for EIP-3009 escrow",
    "guarantee": "All gas values are from actual on-chain transaction receipts - NO estimates or fallbacks"
  }
}
EOF

echo
echo "✅ SYSTEMATIC gas snapshot created: snapshots/gas_snapshots_real_eip3009_e2e.json"

echo "🎉 SUCCESS! You now have REAL gas measurements from systematic solver transaction discovery for EIP-3009!"

echo "💡 Integration:"
echo '  let cost_engine = CostEngine::new_with_snapshots("snapshots/gas_snapshots_real_eip3009_e2e.json");'

echo "🔧 Systematic approach summary:"
echo "  • Tracked solver nonces before/after EIP-3009 intent submission"
echo "  • Found ALL transactions by their specific nonce values"
echo "  • Extracted gas from actual transaction receipts"
echo "  • NO fallbacks or estimates used"

echo "📋 To capture gas for other flows:"
echo "  Run estimate_gas_permit2_escrow.sh for Permit2 escrow gas"
echo "  Run estimate_gas_compact_resource_lock.sh for Compact Resource Lock gas"