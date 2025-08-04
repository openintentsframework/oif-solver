#!/bin/bash
# Advanced transaction debugging script for OIF solvers
# 
# This script provides comprehensive debugging capabilities for failed transactions
# by extracting contract metadata, analyzing call data, and decoding errors.
#
# Key features:
# - Transaction trace analysis with detailed error decoding
# - Contract metadata extraction (errors, functions, events)
# - Error code lookup across multiple sources
# - Transaction replay with cast call
#
# Usage:
#   ./debug_transaction.sh <subcommand> [options]
#
# Subcommands:
#   inspect-contracts    - Extract and display contract metadata (errors, functions, events)
#   analyze-tx <hash>    - Analyze a specific transaction by hash
#   simulate-openfor     - Simulate an openFor transaction with detailed tracing
#   decode-error <code>  - Decode a specific error code
#   compare-calldata     - Compare expected vs actual call data

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Load configuration
load_config() {
    if [ ! -f "config/demo.toml" ]; then
        echo -e "${RED}❌ Configuration not found!${NC}"
        echo -e "${YELLOW}💡 Run './setup_local_anvil.sh' first${NC}"
        exit 1
    fi

    # Extract addresses from config
    INPUT_SETTLER_ADDRESS=$(grep 'input_settler_address = ' config/demo.toml | cut -d'"' -f2)
    OUTPUT_SETTLER_ADDRESS=$(grep 'output_settler_address = ' config/demo.toml | cut -d'"' -f2)
    ORACLE_ADDRESS=$(grep 'oracle_address = ' config/demo.toml | cut -d'"' -f2)
    ORIGIN_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.origin\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
    DEST_TOKEN_ADDRESS=$(grep -A 10 '\[contracts.destination\]' config/demo.toml | grep 'token = ' | cut -d'"' -f2)
    USER_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'user = ' | cut -d'"' -f2)
    RECIPIENT_ADDR=$(grep -A 10 '\[accounts\]' config/demo.toml | grep 'recipient = ' | cut -d'"' -f2)
    SOLVER_KEY=$(grep 'solver_private_key = ' config/demo.toml | cut -d'"' -f2)
    SOLVER_ADDR=$(grep 'solver_address = ' config/demo.toml | cut -d'"' -f2)
}

# Extract and display contract metadata using forge inspect
# This helps understand available functions, errors, and events
inspect_contracts() {
    echo -e "${BLUE}🔍 Inspecting Contract Metadata${NC}"
    echo "===================================="
    
    # Create a temporary directory for storing metadata
    mkdir -p /tmp/oif-debug
    
    # Function to extract and format contract metadata
    extract_contract_metadata() {
        local contract_name=$1
        local contract_address=$2
        local output_file=$3
        
        echo -e "\n${CYAN}📋 $contract_name ($contract_address)${NC}"
        echo "----------------------------------------"
        
        # Extract errors
        echo -e "${YELLOW}Errors:${NC}"
        # Determine contracts directory relative to this script
        CONTRACTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../oif-solvers/oif-contracts" && pwd)"
        cd "$CONTRACTS_DIR"
        
        # Try to find the contract file
        local contract_file=""
        if [[ "$contract_name" == "InputSettlerEscrow" ]]; then
            contract_file="src/input/escrow/InputSettlerEscrow.sol:InputSettlerEscrow"
        elif [[ "$contract_name" == "OutputSettler7683" ]]; then
            contract_file="src/output/coin/OutputSettler7683.sol:OutputInputSettlerEscrow"
        fi
        
        if [ -n "$contract_file" ]; then
            # First, let's build the contracts to ensure artifacts exist
            echo "  Building contract..."
            forge build --silent 2>/dev/null || true
            
            # Extract errors with their selectors
            echo -e "\n  Extracting errors..."
            local errors_output=$(forge inspect "$contract_file" errors 2>&1)
            
            # Check if it's table format (newer forge) or JSON (older forge)
            if [[ "$errors_output" == *"╭"* ]]; then
                # Table format - parse it
                echo "$errors_output" | grep -E "^\|[^|]+\|[^|]+\|$" | grep -v "Error" | grep -v "===" | while read line; do
                    local error_name=$(echo "$line" | cut -d'|' -f2 | xargs)
                    local selector=$(echo "$line" | cut -d'|' -f3 | xargs)
                    if [[ -n "$error_name" && -n "$selector" ]]; then
                        echo "    $error_name: $selector"
                    fi
                done
                
                # Save in JSON format for later lookup
                echo "{" > "$output_file.errors.json"
                local first=true
                echo "$errors_output" | grep -E "^\|[^|]+\|[^|]+\|$" | grep -v "Error" | grep -v "===" | while read line; do
                    local error_name=$(echo "$line" | cut -d'|' -f2 | xargs)
                    local selector=$(echo "$line" | cut -d'|' -f3 | xargs)
                    if [[ -n "$error_name" && -n "$selector" ]]; then
                        if [[ "$first" == "true" ]]; then
                            echo "  \"$error_name\": \"$selector\"" >> "$output_file.errors.json"
                            first=false
                        else
                            echo ", \"$error_name\": \"$selector\"" >> "$output_file.errors.json"
                        fi
                    fi
                done
                echo "}" >> "$output_file.errors.json"
            elif [[ "$errors_output" == *"{"* ]]; then
                # JSON format
                echo "$errors_output" | jq -r 'to_entries[] | "    \(.key): \(.value)"' 2>/dev/null || echo "    Failed to parse errors"
                echo "$errors_output" > "$output_file.errors.json"
            else
                echo "    No errors found or forge inspect failed"
            fi
            
            echo -e "\n${YELLOW}Functions:${NC}"
            # Extract function selectors
            local methods_output=$(forge inspect "$contract_file" methods 2>&1)
            
            # Check format
            if [[ "$methods_output" == *"╭"* ]]; then
                # Table format
                echo "$methods_output" | grep -E "^\|[^|]+\|[^|]+\|$" | grep -v "Function" | grep -v "===" | head -20 | while read line; do
                    local func_name=$(echo "$line" | cut -d'|' -f2 | xargs)
                    local selector=$(echo "$line" | cut -d'|' -f3 | xargs)
                    if [[ -n "$func_name" && -n "$selector" ]]; then
                        echo "    $func_name: $selector"
                    fi
                done
                
                # Save for later lookup
                echo "{" > "$output_file.methods.json"
                local first=true
                echo "$methods_output" | grep -E "^\|[^|]+\|[^|]+\|$" | grep -v "Function" | grep -v "===" | while read line; do
                    local func_name=$(echo "$line" | cut -d'|' -f2 | xargs)
                    local selector=$(echo "$line" | cut -d'|' -f3 | xargs)
                    if [[ -n "$func_name" && -n "$selector" ]]; then
                        if [[ "$first" == "true" ]]; then
                            echo "  \"$func_name\": \"$selector\"" >> "$output_file.methods.json"
                            first=false
                        else
                            echo ", \"$func_name\": \"$selector\"" >> "$output_file.methods.json"
                        fi
                    fi
                done
                echo "}" >> "$output_file.methods.json"
            elif [[ "$methods_output" == *"{"* ]]; then
                echo "$methods_output" | jq -r 'to_entries[] | "    \(.key): \(.value)"' 2>/dev/null | head -20 || echo "    Failed to parse methods"
                echo "$methods_output" > "$output_file.methods.json"
            else
                echo "    No methods found or forge inspect failed"
            fi
            
            echo -e "\n${YELLOW}Events:${NC}"
            # Extract event signatures
            local events_json=$(forge inspect "$contract_file" events 2>&1)
            if [[ "$events_json" == *"{"* ]]; then
                echo "$events_json" | jq -r 'to_entries[] | "    \(.key): \(.value)"' 2>/dev/null | head -10 || echo "    Failed to parse events"
                echo "$events_json" > "$output_file.events.json"
            else
                echo "    No events found or forge inspect failed"
            fi
            
            # Alternative: Try to get the ABI and extract information from there
            echo -e "\n${YELLOW}Alternative: Checking ABI...${NC}"
            local abi_json=$(forge inspect "$contract_file" abi 2>&1)
            if [[ "$abi_json" == "["* ]]; then
                # Extract custom errors from ABI
                echo "  Custom errors from ABI:"
                echo "$abi_json" | jq -r '.[] | select(.type == "error") | "    \(.name)"' 2>/dev/null || true
                
                # Extract function names
                echo -e "\n  Functions from ABI:"
                echo "$abi_json" | jq -r '.[] | select(.type == "function") | "    \(.name)(\(.inputs | map(.type) | join(",")))"' 2>/dev/null | head -10 || true
            fi
        else
            echo "  Contract file not found"
        fi
        
        cd - > /dev/null
    }
    
    # Extract metadata for both contracts
    extract_contract_metadata "InputSettlerEscrow" "$INPUT_SETTLER_ADDRESS" "/tmp/oif-debug/input_settler"
    extract_contract_metadata "OutputSettler7683" "$OUTPUT_SETTLER_ADDRESS" "/tmp/oif-debug/output_settler"
    
    echo -e "\n${GREEN}✅ Metadata extracted to /tmp/oif-debug/${NC}"
}

# ====== MAIN FUNCTIONS ======

# Analyze a specific transaction by hash
analyze_tx() {
    local tx_hash=$1
    
    if [ -z "$tx_hash" ]; then
        echo -e "${RED}❌ Please provide a transaction hash${NC}"
        echo "Usage: $0 analyze-tx <transaction_hash>"
        exit 1
    fi
    
    echo -e "${BLUE}🔍 Analyzing Transaction: $tx_hash${NC}"
    echo "===================================="
    
    # ====== TRANSACTION DETAILS SECTION ======
    echo -e "\n${CYAN}📋 Transaction Details:${NC}"
    TX_DATA=$(cast tx "$tx_hash" --rpc-url http://localhost:8545 --json 2>/dev/null || echo "{}")
    
    if [ "$TX_DATA" = "{}" ]; then
        echo -e "${RED}❌ Transaction not found${NC}"
        exit 1
    fi
    
    # Extract key fields
    FROM=$(echo "$TX_DATA" | jq -r '.from')
    TO=$(echo "$TX_DATA" | jq -r '.to')
    VALUE=$(echo "$TX_DATA" | jq -r '.value')
    INPUT=$(echo "$TX_DATA" | jq -r '.input')
    GAS=$(echo "$TX_DATA" | jq -r '.gas')
    
    echo "  From: $FROM"
    echo "  To: $TO"
    echo "  Value: $VALUE"
    echo "  Gas: $GAS"
    echo "  Input data length: $((${#INPUT} / 2 - 1)) bytes"
    
    # ====== TRANSACTION RECEIPT SECTION ======
    echo -e "\n${CYAN}📋 Transaction Receipt:${NC}"
    RECEIPT=$(cast receipt "$tx_hash" --rpc-url http://localhost:8545 --json 2>/dev/null || echo "{}")
    
    STATUS=$(echo "$RECEIPT" | jq -r '.status')
    GAS_USED=$(echo "$RECEIPT" | jq -r '.gasUsed')
    
    echo "  Status: $STATUS"
    echo "  Gas Used: $GAS_USED"
    
    # If transaction failed, try to decode the error
    if [ "$STATUS" = "0x0" ] || [ "$STATUS" = "false" ]; then
        echo -e "\n${RED}❌ Transaction Failed${NC}"
        
        # ====== ERROR ANALYSIS SECTION ======
        echo -e "\n${CYAN}🔍 Attempting to get revert reason...${NC}"
        
        # Extract function selector (first 4 bytes of input)
        SELECTOR=${INPUT:0:10}
        echo "  Function selector: $SELECTOR"
        
        # Try to decode based on selector
        decode_calldata "$INPUT" "$TO"
        
        # ====== TRANSACTION TRACE SECTION ======
        # Use cast run to get a detailed execution trace
        echo -e "\n${CYAN}🔍 Running transaction trace with cast run...${NC}"
        
        # Use cast run to get detailed trace
        echo "  Executing: cast run $tx_hash --rpc-url http://localhost:8545"
        echo ""
        
        # Run the trace and capture output
        TRACE_OUTPUT=$(cast run "$tx_hash" --rpc-url http://localhost:8545 2>&1)
        
        # Check if trace contains revert
        if [[ "$TRACE_OUTPUT" == *"Revert"* ]] || [[ "$TRACE_OUTPUT" == *"revert"* ]]; then
            echo -e "${YELLOW}Transaction reverted. Analyzing trace...${NC}"
            
            # Show the last few lines which usually contain the revert reason
            echo "$TRACE_OUTPUT" | tail -20
            
            # Try to extract error code from trace - look for "custom error 0x"
            if [[ "$TRACE_OUTPUT" =~ "custom error "(0x[0-9a-fA-F]{8}) ]]; then
                ERROR_CODE="${BASH_REMATCH[1]}"
                echo -e "\n${YELLOW}Detected error code in trace: $ERROR_CODE${NC}"
                
                # Automatically decode the error
                echo -e "\n${CYAN}🔍 Decoding error...${NC}"
                decode_error "$ERROR_CODE"
            elif [[ "$TRACE_OUTPUT" =~ "Revert] "(0x[0-9a-fA-F]{8}) ]]; then
                # Alternative pattern
                ERROR_CODE="${BASH_REMATCH[1]}"
                echo -e "\n${YELLOW}Detected error code in trace: $ERROR_CODE${NC}"
                
                # Automatically decode the error
                echo -e "\n${CYAN}🔍 Decoding error...${NC}"
                decode_error "$ERROR_CODE"
            else
                echo -e "\n${YELLOW}No specific error code found in trace${NC}"
            fi
        else
            # Show full trace for successful or other outcomes
            echo "$TRACE_OUTPUT" | head -50
            echo -e "\n${YELLOW}... (trace truncated, showing first 50 lines)${NC}"
        fi
        
        # ====== TRANSACTION REPLAY SECTION ======
        # Attempt to replay the transaction using cast call to get more error details
        echo -e "\n${CYAN}🔍 Additional replay with cast call...${NC}"
        
        # Check if cast is available
        if ! command -v cast &> /dev/null; then
            echo "  Cast command not found. Please install Foundry."
            return
        fi
        
        # Execute cast call in background to enable timeout control
        (
            if [[ "$VALUE" == "0x0" || -z "$VALUE" ]]; then
                # No value transfer - standard call
                cast call "$TO" "$INPUT" --from "$FROM" --rpc-url http://localhost:8545 2>&1
            else
                # Value transfer - convert hex to decimal as cast expects decimal
                local VALUE_DECIMAL=$(cast --to-dec "$VALUE" 2>/dev/null || echo "0")
                cast call "$TO" "$INPUT" --from "$FROM" --value "$VALUE_DECIMAL" --rpc-url http://localhost:8545 2>&1
            fi
        ) &
        
        # Capture background process PID for timeout control
        CAST_PID=$!
        
        # Implement 5-second timeout
        SECONDS=0
        while kill -0 $CAST_PID 2>/dev/null && [ $SECONDS -lt 5 ]; do
            sleep 0.1
        done
        
        # Handle timeout or completion
        if kill -0 $CAST_PID 2>/dev/null; then
            # Process still running after 5 seconds - force termination
            kill -9 $CAST_PID 2>/dev/null
            wait $CAST_PID 2>/dev/null
            echo "  Cast call timed out after 5 seconds"
            echo "  This might indicate the RPC endpoint is not responding"
        else
            # Process completed naturally
            wait $CAST_PID
            REPLAY_EXIT_CODE=$?
            # Output was printed directly by the background process
        fi
    else
        echo -e "\n${GREEN}✅ Transaction Successful${NC}"
    fi
    
    # Decode logs if any
    LOGS=$(echo "$RECEIPT" | jq -r '.logs')
    if [ "$LOGS" != "[]" ] && [ "$LOGS" != "null" ]; then
        echo -e "\n${CYAN}📋 Events Emitted:${NC}"
        echo "$RECEIPT" | jq -r '.logs[] | "  Topic0: \(.topics[0])"'
    fi
}

# Helper function to decode call data based on function selector
decode_calldata() {
    local calldata=$1
    local to_address=$2
    
    echo -e "\n${CYAN}📋 Decoding Call Data:${NC}"
    
    # Extract function selector
    local selector=${calldata:0:10}
    
    # Check known selectors
    case "$selector" in
        "0x5e4268ea")  # openFor(bytes,address,bytes)
            echo "  Function: openFor(bytes order, address sponsor, bytes signature)"
            
            # Decode the call data
            # Remove function selector and decode
            local data_without_selector="0x${calldata:10}"
            
            # This is complex ABI decoding, so we'll use cast
            echo -e "\n  ${YELLOW}Attempting to decode parameters...${NC}"
            
            # For openFor, we expect: bytes order, address sponsor, bytes signature
            # The actual decoding would require proper ABI decoding
            ;;
            
        "0x7f500490")  # Example: might be another function
            echo "  Function: Unknown selector $selector"
            ;;
            
        *)
            echo "  Unknown function selector: $selector"
            
            # Try to match against known methods
            if [ -f "/tmp/oif-debug/input_settler.methods.json" ]; then
                echo -e "\n  ${YELLOW}Checking against known methods...${NC}"
                MATCHED=$(jq -r --arg sel "${selector:2}" 'to_entries[] | select(.value == $sel) | .key' /tmp/oif-debug/input_settler.methods.json 2>/dev/null || echo "")
                if [ -n "$MATCHED" ]; then
                    echo "  Matched function: $MATCHED"
                fi
            fi
            ;;
    esac
}

# Helper function to decode error codes using multiple sources
decode_error() {
    local error_code=$1
    
    if [ -z "$error_code" ]; then
        echo -e "${RED}❌ Please provide an error code${NC}"
        echo "Usage: $0 decode-error <error_code>"
        exit 1
    fi
    
    echo -e "${BLUE}🔍 Decoding Error: $error_code${NC}"
    echo "===================================="
    
    # Normalize error code (remove 0x prefix if present)
    error_code=${error_code#0x}
    
    # Check against known errors
    echo -e "\n${CYAN}📋 Checking known error codes...${NC}"
    
    # Check InputSettler errors
    if [ -f "/tmp/oif-debug/input_settler.errors.json" ]; then
        echo -e "\n${YELLOW}InputSettler Errors:${NC}"
        MATCHED=$(jq -r --arg err "$error_code" 'to_entries[] | select(.value == $err) | .key' /tmp/oif-debug/input_settler.errors.json 2>/dev/null || echo "")
        if [ -n "$MATCHED" ]; then
            echo -e "  ${GREEN}✅ Matched: $MATCHED${NC}"
        else
            echo "  No match in InputSettler"
        fi
    fi
    
    # Check OutputSettler errors
    if [ -f "/tmp/oif-debug/output_settler.errors.json" ]; then
        echo -e "\n${YELLOW}OutputSettler Errors:${NC}"
        MATCHED=$(jq -r --arg err "$error_code" 'to_entries[] | select(.value == $err) | .key' /tmp/oif-debug/output_settler.errors.json 2>/dev/null || echo "")
        if [ -n "$MATCHED" ]; then
            echo -e "  ${GREEN}✅ Matched: $MATCHED${NC}"
        else
            echo "  No match in OutputSettler"
        fi
    fi
    
    # Common Solidity errors
    echo -e "\n${YELLOW}Common Solidity Errors:${NC}"
    case "$error_code" in
        "4e487b71")
            echo "  Panic(uint256)"
            ;;
        "08c379a0")
            echo "  Error(string)"
            ;;
        *)
            echo "  Custom error (not a standard Solidity error)"
            ;;
    esac
    
    # Try to decode using cast 4byte
    echo -e "\n${YELLOW}Attempting to decode with cast 4byte...${NC}"
    local fourByte_result=$(cast 4byte $error_code 2>&1 || echo "")
    if [[ -n "$fourByte_result" && "$fourByte_result" != *"Not found"* && "$fourByte_result" != *"error"* ]]; then
        echo -e "  ${GREEN}✅ Found in 4byte directory: $fourByte_result${NC}"
    else
        echo "  Not found in 4byte.directory"
        
        # Additional attempt - check if it's from a known library
        echo -e "\n${YELLOW}Checking known library errors...${NC}"
        case "$error_code" in
            "8baa579f")
                echo -e "  ${PURPLE}Possible match: InvalidSignature() or similar signature validation error${NC}"
                echo "  This often comes from signature validation libraries"
                ;;
            *)
                echo "  Unknown error code"
                ;;
        esac
    fi
}

# Simulate openFor transaction with detailed analysis
# Useful for testing order creation and signature validation
simulate_openfor() {
    echo -e "${BLUE}🔍 Simulating openFor Transaction${NC}"
    echo "===================================="
    
    # Generate fresh order data
    local amount="1000000000000000000"
    local current_time=$(date +%s)
    local expiry=$((current_time + 3600))
    local fill_deadline=$((current_time + 3600))
    local nonce=$(date +%s)
    
    echo -e "\n${CYAN}📋 Order Parameters:${NC}"
    echo "  User: $USER_ADDR"
    echo "  Nonce: $nonce"
    echo "  Expiry: $expiry"
    echo "  Fill Deadline: $fill_deadline"
    echo "  Amount: 1.0 tokens"
    
    # Build order data
    local output_settler_bytes32="0x000000000000000000000000${OUTPUT_SETTLER_ADDRESS:2}"
    local dest_token_bytes32="0x000000000000000000000000${DEST_TOKEN_ADDRESS:2}"
    local recipient_bytes32="0x000000000000000000000000${RECIPIENT_ADDR:2}"
    
    ORDER_DATA=$(cast abi-encode "f((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))" \
        "(${USER_ADDR},${nonce},31337,${expiry},${fill_deadline},${ORACLE_ADDRESS},[[$ORIGIN_TOKEN_ADDRESS,$amount]],[($output_settler_bytes32,$output_settler_bytes32,31338,$dest_token_bytes32,$amount,$recipient_bytes32,0x,0x)])")
    
    echo -e "\n${CYAN}📋 Generated Order Data:${NC}"
    echo "  Length: $((${#ORDER_DATA} / 2 - 1)) bytes"
    echo "  Hash: $(cast keccak $ORDER_DATA)"
    
    # Test orderIdentifier first
    echo -e "\n${CYAN}🔍 Testing orderIdentifier...${NC}"
    ORDER_ID=$(cast call "$INPUT_SETTLER_ADDRESS" "orderIdentifier(bytes)" "$ORDER_DATA" --rpc-url http://localhost:8545 2>&1)
    if [[ $ORDER_ID == *"0x"* ]]; then
        echo -e "  ${GREEN}✅ Order ID: $ORDER_ID${NC}"
    else
        echo -e "  ${RED}❌ Failed to get order ID: $ORDER_ID${NC}"
    fi
    
    # Create a proper signature (for testing, we'll create a dummy one)
    local dummy_signature="0x" 
    for i in {1..65}; do dummy_signature="${dummy_signature}00"; done
    
    # Build the complete call data
    echo -e "\n${CYAN}📋 Building openFor call data...${NC}"
    CALLDATA=$(cast calldata "openFor(bytes,address,bytes)" "$ORDER_DATA" "$USER_ADDR" "$dummy_signature")
    echo "  Call data: ${CALLDATA:0:10}..."
    echo "  Total length: $((${#CALLDATA} / 2 - 1)) bytes"
    
    # Try to estimate gas first
    echo -e "\n${CYAN}🔍 Estimating gas...${NC}"
    GAS_ESTIMATE=$(cast estimate "$INPUT_SETTLER_ADDRESS" "$CALLDATA" --from "$SOLVER_ADDR" --rpc-url http://localhost:8545 2>&1)
    
    if [[ $GAS_ESTIMATE =~ ^[0-9]+$ ]]; then
        echo -e "  ${GREEN}✅ Gas estimate: $GAS_ESTIMATE${NC}"
    else
        echo -e "  ${RED}❌ Gas estimation failed${NC}"
        echo "  Error: $GAS_ESTIMATE"
        
        # Try to extract error code
        if [[ $GAS_ESTIMATE =~ "0x"([0-9a-fA-F]+) ]]; then
            ERROR_CODE="${BASH_REMATCH[1]}"
            echo -e "\n${YELLOW}Detected error code: 0x$ERROR_CODE${NC}"
            decode_error "0x$ERROR_CODE"
        fi
    fi
    
    # Try static call to get more details
    echo -e "\n${CYAN}🔍 Attempting static call...${NC}"
    STATIC_RESULT=$(cast call "$INPUT_SETTLER_ADDRESS" "$CALLDATA" --from "$SOLVER_ADDR" --rpc-url http://localhost:8545 2>&1)
    echo "  Result: $STATIC_RESULT"
}

# Compare expected vs actual call data structure
# Helps debug encoding issues
compare_calldata() {
    echo -e "${BLUE}🔍 Comparing Call Data${NC}"
    echo "===================================="
    
    # Read the last order from send_offchain_intent.sh output
    echo -e "\n${CYAN}📋 Expected Order Structure:${NC}"
    echo "  StandardOrder {"
    echo "    user: address"
    echo "    nonce: uint256" 
    echo "    originChainId: uint256"
    echo "    expires: uint32"
    echo "    fillDeadline: uint32"
    echo "    inputOracle: address"
    echo "    inputs: uint256[2][]"
    echo "    outputs: MandateOutput[]"
    echo "  }"
    
    echo -e "\n${CYAN}📋 Expected Signature Structure:${NC}"
    echo "  Permit2Witness signature (65 bytes)"
    echo "  - Must be valid EIP-712 signature"
    echo "  - Signed by the order's user"
    echo "  - Includes witness data with expires, inputOracle, and outputs"
    
    # If we have a recent transaction hash, analyze it
    if [ -n "$1" ]; then
        echo -e "\n${CYAN}📋 Analyzing actual transaction: $1${NC}"
        analyze_tx "$1"
    fi
}

# Show usage
usage() {
    echo "Usage: $0 <subcommand> [options]"
    echo ""
    echo "Subcommands:"
    echo "  inspect-contracts    - Extract and display contract metadata"
    echo "  analyze-tx <hash>    - Analyze a specific transaction"
    echo "  simulate-openfor     - Simulate an openFor transaction"
    echo "  decode-error <code>  - Decode a specific error code"
    echo "  compare-calldata     - Compare expected vs actual call data"
    echo ""
    echo "Examples:"
    echo "  $0 inspect-contracts"
    echo "  $0 analyze-tx 0x7c5004904608e3baf6ebd6e9d6bad1e9aa0b4f9f425fb89583215eab6fddd7ef"
    echo "  $0 decode-error 0x8baa579f"
    echo "  $0 simulate-openfor"
}

# Main script logic
load_config

# Parse command
case "$1" in
    "inspect-contracts")
        inspect_contracts
        ;;
    "analyze-tx")
        analyze_tx "$2"
        ;;
    "simulate-openfor")
        simulate_openfor
        ;;
    "decode-error")
        decode_error "$2"
        ;;
    "compare-calldata")
        compare_calldata "$2"
        ;;
    *)
        usage
        exit 1
        ;;
esac