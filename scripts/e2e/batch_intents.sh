#!/bin/bash
# Sequential Batch Intent Processor for Testnet Testing
# Processes intents one by one, waiting for each response before continuing
#
# Usage: ./batch_intents.sh [test_intents.json] [--dry-run] [--continue-on-error]
#
# Options:
#   --dry-run            Validate intents without executing
#                        • Parses JSON and validates configurations
#                        • Shows what would be processed
#                        • No actual API calls or transactions
#                        • Safe for testing intent configurations
#
#   --continue-on-error  Continue processing after failures
#                        • Processes all intents even if some fail
#                        • Shows summary of successful/failed intents
#                        • Useful for batch testing multiple scenarios
#                        • Default: stops on first failure
#
# Examples:
#   ./batch_intents.sh test_intents.json                    # Process all intents, stop on first error
#   ./batch_intents.sh test_intents.json --dry-run          # Validate configurations only
#   ./batch_intents.sh test_intents.json --continue-on-error # Process all intents, continue on failures

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔄 Sequential Batch Intent Processor${NC}"
echo "====================================="

# Default options
DRY_RUN=false
CONTINUE_ON_ERROR=false
INTENTS_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --continue-on-error)
            CONTINUE_ON_ERROR=true
            shift
            ;;
        --help)
            echo "Usage: $0 [intents.json] [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dry-run            Validate intents without executing"
            echo "  --continue-on-error  Continue processing after failures"
            echo "  --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 testnet_intents.json"
            echo "  $0 testnet_intents.json --dry-run"
            echo "  $0 testnet_intents.json --continue-on-error"
            exit 0
            ;;
        *)
            if [[ -z "$INTENTS_FILE" ]]; then
                INTENTS_FILE="$1"
            fi
            shift
            ;;
    esac
done

# Validate inputs
if [[ -z "$INTENTS_FILE" ]]; then
    echo -e "${RED}❌ No intents file specified${NC}"
    echo "Usage: $0 [intents.json]"
    exit 1
fi

if [[ ! -f "$INTENTS_FILE" ]]; then
    echo -e "${RED}❌ Intents file not found: $INTENTS_FILE${NC}"
    exit 1
fi

if ! jq empty "$INTENTS_FILE" 2>/dev/null; then
    echo -e "${RED}❌ Invalid JSON in intents file${NC}"
    exit 1
fi

if [ ! -f "config/testnet.toml" ] || [ ! -f "config/testnet/networks.toml" ]; then
    echo -e "${RED}❌ Testnet configuration not found!${NC}"
    exit 1
fi

# Configuration
MAIN_CONFIG="config/testnet.toml"
NETWORKS_CONFIG="config/testnet/networks.toml"

# Load account info
SOLVER_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'solver = ' | cut -d'"' -f2)
USER_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'user = ' | cut -d'"' -f2)
USER_PRIVATE_KEY=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'user_private_key = ' | cut -d'"' -f2)
RECIPIENT_ADDR=$(grep -A 4 '\[accounts\]' $MAIN_CONFIG | grep 'recipient = ' | cut -d'"' -f2)

# Dynamic config functions
get_network_config() {
    local chain_id=$1
    local config_type=$2
    
    case $config_type in
        "input_settler")
            grep -A 5 "\[networks\.${chain_id}\]" $NETWORKS_CONFIG | grep 'input_settler_address = ' | cut -d'"' -f2
            ;;
        "output_settler")
            grep -A 5 "\[networks\.${chain_id}\]" $NETWORKS_CONFIG | grep 'output_settler_address = ' | cut -d'"' -f2
            ;;
        "rpc_url")
            awk "/\[\[networks\.${chain_id}\.rpc_urls\]\]/{f=1} f && /^http = /{print; exit}" $NETWORKS_CONFIG | cut -d'"' -f2
            ;;
        "oracle")
            grep -A5 '\[settlement.implementations.direct.oracles\]' $MAIN_CONFIG | grep 'input = ' | sed "s/.*${chain_id} = \[\"\([^\"]*\)\".*/\1/"
            ;;
    esac
}

format_amount() {
    local amount=$1
    local decimals=$2
    echo "scale=${decimals}; $amount / 10^$decimals" | bc -l
}

# Process single intent sequentially
process_intent() {
    local intent_json="$1"
    local intent_index="$2"
    
    echo -e "${PURPLE}━━━ Processing Intent $intent_index ━━━${NC}"
    
    # Extract intent data
    local description=$(echo "$intent_json" | jq -r '.description // "Unnamed Intent"')
    local enabled=$(echo "$intent_json" | jq -r '.enabled // false')
    local origin_chain=$(echo "$intent_json" | jq -r '.origin_chain_id')
    local dest_chain=$(echo "$intent_json" | jq -r '.dest_chain_id')
    local origin_token_addr=$(echo "$intent_json" | jq -r '.origin_token.address')
    local origin_token_decimals=$(echo "$intent_json" | jq -r '.origin_token.decimals')
    local dest_token_addr=$(echo "$intent_json" | jq -r '.dest_token.address')
    local dest_token_decimals=$(echo "$intent_json" | jq -r '.dest_token.decimals')
    local input_amount=$(echo "$intent_json" | jq -r '.amounts.input')
    local output_amount=$(echo "$intent_json" | jq -r '.amounts.output')
    
    # Skip if disabled
    if [[ "$enabled" != "true" ]]; then
        echo -e "${YELLOW}⏭️  Skipped (disabled)${NC}"
        return 0
    fi
    
    # Get network configuration
    local origin_input_settler=$(get_network_config "$origin_chain" "input_settler")
    local dest_output_settler=$(get_network_config "$dest_chain" "output_settler")
    local origin_rpc=$(get_network_config "$origin_chain" "rpc_url")
    local oracle=$(get_network_config "$origin_chain" "oracle")
    
    echo -e "${BLUE}📋 Intent Details:${NC}"
    echo "   Description: $description"
    echo "   Route: Chain $origin_chain → Chain $dest_chain"
    echo "   Input: $(format_amount $input_amount $origin_token_decimals) (decimals: $origin_token_decimals)"
    echo "   Output: $(format_amount $output_amount $dest_token_decimals) (decimals: $dest_token_decimals)"
    echo "   Input Settler: $origin_input_settler"
    echo "   Output Settler: $dest_output_settler"
    echo "   Oracle: $oracle"
    
    # Validate configuration
    if [[ -z "$origin_input_settler" || -z "$dest_output_settler" || -z "$origin_rpc" || -z "$oracle" ]]; then
        echo -e "${RED}❌ Missing network configuration for chains $origin_chain → $dest_chain${NC}"
        return 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${GREEN}✅ Would be processed (dry-run mode)${NC}"
        return 0
    fi
    
    # Set API URL
    local api_url="http://localhost:3000/api/orders"
    
    echo -e "${YELLOW}🔗 API Endpoint: $api_url${NC}"
    
    # Check/Approve Permit2
    local PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"
    echo -e "${BLUE}🔐 Checking Permit2 allowance...${NC}"
    
    local current_allowance=$(cast call "$origin_token_addr" \
        "allowance(address,address)" \
        "$USER_ADDR" \
        "$PERMIT2_ADDRESS" \
        --rpc-url $origin_rpc 2>/dev/null || echo "0x0")
    
    if [ "$current_allowance" = "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
        echo -e "${BLUE}   Approving Permit2...${NC}"
        if cast send "$origin_token_addr" \
            "approve(address,uint256)" \
            "$PERMIT2_ADDRESS" \
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
            --private-key "$USER_PRIVATE_KEY" \
            --rpc-url $origin_rpc > /dev/null 2>&1; then
            echo -e "${GREEN}   ✅ Permit2 approved${NC}"
        else
            echo -e "${RED}   ❌ Permit2 approval failed${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}   ✅ Permit2 already approved${NC}"
    fi
    
    # Generate order data
    echo -e "${YELLOW}🔄 Building order data...${NC}"
    
    local current_time=$(date +%s)
    local nonce=$(perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000')
    local fill_deadline=$((current_time + 3600))
    local expiry=$fill_deadline
    
    # Convert addresses to bytes32 (remove 0x prefix first)
    local output_settler_bytes32="0x000000000000000000000000${dest_output_settler#0x}"
    local dest_token_bytes32="0x000000000000000000000000${dest_token_addr#0x}"
    local recipient_bytes32="0x000000000000000000000000${RECIPIENT_ADDR#0x}"
    local zero_bytes32="0x0000000000000000000000000000000000000000000000000000000000000000"
    
    # Build StandardOrder
    local standard_order_abi_type='f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))'
    local order_data=$(cast abi-encode "$standard_order_abi_type" \
        "(${USER_ADDR},${nonce},${origin_chain},${expiry},${fill_deadline},${oracle},[[$origin_token_addr,$input_amount]],[($zero_bytes32,$output_settler_bytes32,${dest_chain},$dest_token_bytes32,$output_amount,$recipient_bytes32,0x,0x)])")
    
    # Generate EIP-712 signature
    echo -e "${YELLOW}🔏 Generating EIP-712 signature...${NC}"
    
    # Type hashes
    local mandate_output_type="MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
    local mandate_output_type_hash=$(cast keccak "$mandate_output_type")
    
    local permit2_witness_type="Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)${mandate_output_type}"
    local permit2_witness_type_hash=$(cast keccak "$permit2_witness_type")
    
    local token_permissions_type="TokenPermissions(address token,uint256 amount)"
    local token_permissions_type_hash=$(cast keccak "$token_permissions_type")
    
    # Domain separator
    local domain_type_hash=$(cast keccak "EIP712Domain(string name,uint256 chainId,address verifyingContract)")
    local permit2_name_hash=$(cast keccak "Permit2")
    local domain_separator=$(cast abi-encode "f(bytes32,bytes32,uint256,address)" "$domain_type_hash" "$permit2_name_hash" "$origin_chain" "$PERMIT2_ADDRESS")
    local domain_separator_hash=$(cast keccak "$domain_separator")
    
    # Build hashes
    local mandate_output_encoded=$(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32,bytes32)" \
        "$mandate_output_type_hash" \
        "$zero_bytes32" \
        "$output_settler_bytes32" \
        "$dest_chain" \
        "$dest_token_bytes32" \
        "$output_amount" \
        "$recipient_bytes32" \
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" \
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    local mandate_output_hash=$(cast keccak "$mandate_output_encoded")
    local outputs_hash=$(cast keccak "$mandate_output_hash")
    
    local permit2_witness_encoded=$(cast abi-encode "f(bytes32,uint32,address,bytes32)" \
        "$permit2_witness_type_hash" \
        "$expiry" \
        "$oracle" \
        "$outputs_hash")
    local permit2_witness_hash=$(cast keccak "$permit2_witness_encoded")
    
    local token_perm_encoded=$(cast abi-encode "f(bytes32,address,uint256)" \
        "$token_permissions_type_hash" \
        "$origin_token_addr" \
        "$input_amount")
    local token_perm_hash=$(cast keccak "$token_perm_encoded")
    
    # Final hash
    local witness_type_string="Permit2Witness witness)${mandate_output_type}${token_permissions_type}Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)"
    local permit_batch_witness_string="PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,${witness_type_string}"
    local permit_batch_witness_type_hash=$(cast keccak "$permit_batch_witness_string")
    
    local permitted_array_hash=$(cast keccak "$token_perm_hash")
    local main_struct_encoded=$(cast abi-encode "f(bytes32,bytes32,address,uint256,uint256,bytes32)" \
        "$permit_batch_witness_type_hash" \
        "$permitted_array_hash" \
        "$origin_input_settler" \
        "$nonce" \
        "$fill_deadline" \
        "$permit2_witness_hash")
    local main_struct_hash=$(cast keccak "$main_struct_encoded")
    
    local digest="0x1901${domain_separator_hash:2}${main_struct_hash:2}"
    local final_digest=$(cast keccak "$digest")
    
    # Sign
    local signature=$(cast wallet sign --no-hash --private-key "$USER_PRIVATE_KEY" "$final_digest" 2>/dev/null)
    
    if [[ -z "$signature" ]]; then
        echo -e "${RED}❌ Signing failed${NC}"
        return 1
    fi
    
    # Create JSON payload
    local prefixed_signature="0x00${signature:2}"
    local json_payload=$(cat <<EOF
{
  "order": "$order_data",
  "sponsor": "$USER_ADDR",
  "signature": "$prefixed_signature"
}
EOF
)
    
    # Send request and wait for response
    echo -e "${YELLOW}🚀 Sending intent to API...${NC}"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$api_url" \
      -H "Content-Type: application/json" \
      -d "$json_payload" 2>/dev/null)
    
    local http_code=$(echo "$response" | tail -n1)
    local response_body=$(echo "$response" | sed '$d')
    
    # Process response
    if [ "$http_code" = "200" ]; then
        echo -e "${GREEN}✅ Intent processed successfully!${NC}"
        
        # Extract order ID if available
        local order_id=$(echo "$response_body" | grep -o '"order_id":"[^"]*"' | cut -d'"' -f4 2>/dev/null)
        if [ -n "$order_id" ]; then
            echo -e "${BLUE}   Order ID: $order_id${NC}"
        else
            echo -e "${BLUE}   Response: $response_body${NC}"
        fi
        return 0
    else
        echo -e "${RED}❌ Intent processing failed${NC}"
        echo -e "${RED}   HTTP Status: $http_code${NC}"
        echo -e "${RED}   Response: $response_body${NC}"
        return 1
    fi
}

# Main sequential processing function
process_batch_sequential() {
    local total_intents=$(jq '.intents | length' "$INTENTS_FILE")
    local successful=0
    local failed=0
    local skipped=0
    local successful_ids=()
    local failed_ids=()
    local skipped_ids=()
    
    echo -e "${BLUE}📊 Found $total_intents intents to process sequentially${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}🔍 Running in dry-run mode${NC}"
    fi
    
    echo ""
    
    # Process each intent sequentially
    for ((i=0; i<total_intents; i++)); do
        local intent=$(jq ".intents[$i]" "$INTENTS_FILE")
        local intent_num=$((i+1))
        
        echo -e "${BLUE}[$intent_num/$total_intents]${NC}"
        
        if process_intent "$intent" "$intent_num"; then
            if [[ $(echo "$intent" | jq -r '.enabled // false') == "true" ]]; then
                ((successful++))
                successful_ids+=("$intent_num")
            else
                ((skipped++))
                skipped_ids+=("$intent_num")
            fi
        else
            ((failed++))
            failed_ids+=("$intent_num")
            if [[ "$CONTINUE_ON_ERROR" != "true" ]]; then
                echo -e "${RED}🛑 Stopping batch processing due to failure${NC}"
                break
            fi
        fi
        
        # Brief pause between intents for better logging
        if [[ $intent_num -lt $total_intents ]]; then
            echo ""
            sleep 1
        fi
    done
    
    # Final summary
    echo ""
    echo -e "${BLUE}📊 Sequential Processing Complete!${NC}"
    echo "================================="
    echo "   Total Intents: $total_intents"
    echo "   Successful: $successful"
    echo "   Failed: $failed"
    echo "   Skipped: $skipped"
    echo ""
    
    # Show detailed results with IDs (comma-separated)
    if [[ ${#successful_ids[@]} -gt 0 ]]; then
        local successful_list=$(IFS=,; echo "${successful_ids[*]}")
        echo -e "${GREEN}✅ Successful Intents: ${successful_list}${NC}"
    fi
    
    if [[ ${#failed_ids[@]} -gt 0 ]]; then
        local failed_list=$(IFS=,; echo "${failed_ids[*]}")
        echo -e "${RED}❌ Failed Intents: ${failed_list}${NC}"
    fi
    
    if [[ ${#skipped_ids[@]} -gt 0 ]]; then
        local skipped_list=$(IFS=,; echo "${skipped_ids[*]}")
        echo -e "${YELLOW}⏭️  Skipped Intents: ${skipped_list}${NC}"
    fi
    
    if [[ $failed -gt 0 ]]; then
        exit 1
    fi
}

# Execute main function
process_batch_sequential

echo -e "${GREEN}🎉 All intents processed!${NC}"