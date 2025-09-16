#!/bin/bash
# Compact Resource Lock gas estimation - systematically get real gas from solver transactions
# This script captures REAL gas values for the compact flow (no open on origin)

SOLVER_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

echo "🚀 Systematic Gas Estimation (Compact Resource Lock)"
echo "===================================================="
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
echo "  Origin: $origin_before_dec"
echo "  Dest: $dest_before_dec"

# Send compact intent using oif-demo
echo "📤 Sending Compact Resource Lock intent..."
./oif-demo intent test compact permit2 A2B > /dev/null 2>&1

echo "⏳ Waiting for transaction processing..."
sleep 22

# Get final nonces
origin_nonce_after=$(cast nonce "$SOLVER_ADDR" --rpc-url http://localhost:8545)
dest_nonce_after=$(cast nonce "$SOLVER_ADDR" --rpc-url http://localhost:8546)
origin_after_dec=$(cast to-dec "$origin_nonce_after")
dest_after_dec=$(cast to-dec "$dest_nonce_after")

echo "📊 Nonces after processing:"
echo "  Origin: $origin_before_dec → $origin_after_dec"
echo "  Dest: $dest_before_dec → $dest_after_dec"

# Calculate transaction counts (expected compact: origin 1, dest 1)
origin_tx_count=$((origin_after_dec - origin_before_dec))
dest_tx_count=$((dest_after_dec - dest_before_dec))

if [ $origin_tx_count -eq 0 ] && [ $dest_tx_count -eq 0 ]; then
    echo "❌ ERROR: No transactions detected! Make sure solver is running."
    exit 1
fi

echo "🔍 Expected: $origin_tx_count origin + $dest_tx_count dest transactions"

echo "🔍 Finding transactions systematically (NO fallbacks)..."
origin_txs=""
dest_txs=""
all_found=true

# Find origin transaction(s) (finalize/claim only for compact)
echo "  🎯 Origin chain transactions (finalize):"
for nonce in $(seq $origin_before_dec $((origin_after_dec-1))); do
    tx_hash=$(find_tx_by_nonce $nonce "http://localhost:8545" "origin" | tail -n1 | tr -d ' \n\r')
    if [ -n "$tx_hash" ]; then
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

# Find dest transaction(s) (fill)
echo "  🎯 Dest chain transactions (fill):"
for nonce in $(seq $dest_before_dec $((dest_after_dec-1))); do
    tx_hash=$(find_tx_by_nonce $nonce "http://localhost:8546" "dest" | tail -n1 | tr -d ' \n\r')
    if [ -n "$tx_hash" ]; then
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
echo "📊 Systematic discovery results (compact):"
echo "  Origin (finalize): ${origin_array[*]:-} (${#origin_array[@]} transactions)"
echo "  Dest (fill): ${dest_array[*]:-} (${#dest_array[@]} transactions)"

# STRICT validation - ALL observed txs must be found
if [ "$all_found" = false ] || [ ${#origin_array[@]} -ne $origin_tx_count ] || [ ${#dest_array[@]} -ne $dest_tx_count ]; then
    echo "❌ SYSTEMATIC FAILURE: Could not find all solver transactions (compact)!"
    echo "   Expected: $origin_tx_count origin + $dest_tx_count dest"
    echo "   Found: ${#origin_array[@]} origin + ${#dest_array[@]} dest"
    exit 1
fi

# Assign compact metrics: open=0, fill=dest[0], finalize=origin[0]
open_gas=0
fill_gas=${dest_array[0]}
finalize_gas=${origin_array[0]}

echo "✅ Successfully found ALL transactions with REAL gas values (compact):"
echo "  Open: $open_gas gas"
echo "  Fill: $fill_gas gas"
echo "  Finalize: $finalize_gas gas"

total_gas=$((open_gas + fill_gas + finalize_gas))
echo "  Total: $total_gas gas"

# Create REAL gas snapshot for compact
mkdir -p snapshots
timestamp=$(date +%s)

cat > snapshots/gas_snapshots_compact_e2e.json << EOF
{
  "version": "1.0.0",
  "snapshots": {
    "compact-resource-lock_31337": [
      {
        "flow": "compact-resource-lock",
        "chain_id": 31337,
        "open_gas": $open_gas,
        "fill_gas": $fill_gas,
        "finalize_gas": $finalize_gas,
        "created_at": $timestamp,
        "metadata": {
          "capture_method": "systematic_solver_execution",
          "description": "Gas captured systematically from actual solver transactions (compact)",
          "nonce_ranges": "Origin $origin_before_dec -> $origin_after_dec, Dest $dest_before_dec -> $dest_after_dec",
          "transaction_counts": "Origin: $origin_tx_count, Dest: $dest_tx_count"
        }
      }
    ]
  },
  "last_updated": $timestamp,
  "metadata": {
    "source": "Systematic Solver Execution",
    "methodology": "Gas extracted via nonce-based discovery and receipts (compact)",
    "guarantee": "All gas values are from actual on-chain transaction receipts - NO estimates or fallbacks"
  }
}
EOF

echo
echo "✅ SYSTEMATIC compact gas snapshot created: snapshots/gas_snapshots_compact_e2e.json"