#!/bin/bash
# Validation functions for setup script

# Validate a private key (64 hex characters)
validate_private_key() {
    local key="$1"
    local key_name="$2"
    
    if [ -z "$key" ]; then
        echo -e "${RED}❌ Error: $key_name not set${NC}"
        return 1
    fi
    
    # Remove 0x prefix if present
    local key_to_validate="${key#0x}"
    
    # Check length (should be 64 hex chars for Ethereum)
    if [ ${#key_to_validate} -ne 64 ]; then
        echo -e "${RED}❌ Error: $key_name has wrong length${NC}"
        echo "  Expected: 64 characters (32 bytes)"
        echo "  Got: ${#key_to_validate} characters"
        return 1
    fi
    
    # Check if it's valid hex
    if ! [[ "$key_to_validate" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo -e "${RED}❌ Error: $key_name contains invalid characters${NC}"
        echo "  Private keys must be 64 hexadecimal characters"
        return 1
    fi
    
    return 0
}

# Validate an Ethereum address
validate_address() {
    local address="$1"
    local address_name="$2"
    
    if [ -z "$address" ]; then
        echo -e "${YELLOW}⚠️  Warning: $address_name not set${NC}"
        return 1
    fi
    
    # Check format (0x followed by 40 hex chars)
    if ! [[ "$address" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
        echo -e "${RED}❌ Error: $address_name has invalid format${NC}"
        echo "  Expected: 0x followed by 40 hex characters"
        echo "  Got: $address"
        return 1
    fi
    
    return 0
}

# Validate all required private keys
validate_private_keys() {
    local all_valid=true
    
    # Required keys
    if ! validate_private_key "$DEPLOYMENT_PRIVATE_KEY" "DEPLOYMENT_PRIVATE_KEY"; then
        all_valid=false
    fi
    
    if ! validate_private_key "$SOLVER_PRIVATE_KEY" "SOLVER_PRIVATE_KEY"; then
        all_valid=false
    fi
    
    # Optional key (only validate if set)
    if [ -n "$USER_PRIVATE_KEY" ]; then
        if ! validate_private_key "$USER_PRIVATE_KEY" "USER_PRIVATE_KEY"; then
            echo -e "${YELLOW}⚠️  USER_PRIVATE_KEY is invalid (optional, only needed for demos)${NC}"
        fi
    fi
    
    if [ "$all_valid" = false ]; then
        echo
        echo -e "${YELLOW}To fix private key issues:${NC}"
        echo "  1. Ensure your .env file contains valid private keys"
        echo "  2. Private keys should be 64 hex characters"
        echo "  3. Can be with or without 0x prefix"
        echo "  4. Example: DEPLOYMENT_PRIVATE_KEY=abc123...def456"
        return 1
    fi
    
    echo -e "${GREEN}✓${NC} All private keys validated"
    return 0
}

# Validate all configured addresses
validate_addresses() {
    local all_valid=true
    
    if ! validate_address "$SOLVER_ADDRESS" "Solver address"; then
        all_valid=false
    fi
    
    # Optional addresses
    if [ -n "$USER_ADDRESS" ]; then
        validate_address "$USER_ADDRESS" "User address" || true
    fi
    
    if [ -n "$RECIPIENT_ADDRESS" ]; then
        validate_address "$RECIPIENT_ADDRESS" "Recipient address" || true
    fi
    
    if [ "$all_valid" = false ]; then
        echo
        echo -e "${YELLOW}To fix address issues:${NC}"
        echo "  1. Update addresses in testnet-config.json"
        echo "  2. Addresses must start with 0x and have 40 hex characters"
        return 1
    fi
    
    echo -e "${GREEN}✓${NC} All addresses validated"
    return 0
}

# Validate RPC connectivity
validate_rpc_connection() {
    local rpc_url="$1"
    local chain_name="$2"
    
    echo -n "  Testing $chain_name RPC... "
    
    if cast chain-id --rpc-url "$rpc_url" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}Failed${NC}"
        echo "  Could not connect to: $rpc_url"
        return 1
    fi
}

# Validate chain configuration
validate_chain_config() {
    local chain="$1"
    
    # Check if chain exists in testnet_chains.json
    if ! get_chain_config "$chain" "chain_id" > /dev/null 2>&1; then
        echo -e "${RED}❌ Error: Unknown chain '$chain'${NC}"
        echo "Available chains:"
        list_available_chains
        return 1
    fi
    
    return 0
}

# Validate that required tools are installed
validate_tools() {
    local all_tools_present=true
    
    # Check for required tools
    local required_tools=("cast" "forge" "jq" "bc")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}❌ Error: '$tool' is not installed${NC}"
            all_tools_present=false
        fi
    done
    
    if [ "$all_tools_present" = false ]; then
        echo
        echo -e "${YELLOW}Please install missing tools:${NC}"
        echo "  - cast & forge: Install Foundry from https://getfoundry.sh/"
        echo "  - jq: JSON processor (brew install jq)"
        echo "  - bc: Calculator (usually pre-installed)"
        return 1
    fi
    
    echo -e "${GREEN}✓${NC} All required tools present"
    return 0
}

# Validate minimum balances for deployment
validate_balances() {
    local origin_rpc="$1"
    local dest_rpc="$2"
    local deployer_address="$3"
    
    # Check ETH balances for gas
    local origin_balance=$(cast balance "$deployer_address" --rpc-url "$origin_rpc" --ether 2>/dev/null || echo "0")
    local dest_balance=$(cast balance "$deployer_address" --rpc-url "$dest_rpc" --ether 2>/dev/null || echo "0")
    
    # Convert to number for comparison (remove scientific notation if any)
    local origin_bal_num=$(echo "$origin_balance" | awk '{print $1}')
    local dest_bal_num=$(echo "$dest_balance" | awk '{print $1}')
    
    local has_issues=false
    
    # Minimum ETH needed for deployment (rough estimate)
    local min_eth="0.01"
    
    if (( $(echo "$origin_bal_num < $min_eth" | bc -l) )); then
        echo -e "${YELLOW}⚠️  Low ETH balance on origin chain: $origin_balance ETH${NC}"
        echo "  Recommended: At least $min_eth ETH for contract deployment"
        has_issues=true
    fi
    
    if (( $(echo "$dest_bal_num < $min_eth" | bc -l) )); then
        echo -e "${YELLOW}⚠️  Low ETH balance on destination chain: $dest_balance ETH${NC}"
        echo "  Recommended: At least $min_eth ETH for contract deployment"
        has_issues=true
    fi
    
    if [ "$has_issues" = true ]; then
        echo
        echo -e "${YELLOW}Note: You may need to fund your deployer address:${NC}"
        echo "  $deployer_address"
        return 1
    fi
    
    echo -e "${GREEN}✓${NC} Sufficient balances for deployment"
    return 0
}

# Main validation function that runs all checks
validate_setup() {
    echo -e "${YELLOW}Running validation checks...${NC}"
    echo
    
    local all_valid=true
    
    # Check tools first
    if ! validate_tools; then
        return 1
    fi
    
    # Validate private keys
    if ! validate_private_keys; then
        all_valid=false
    fi
    
    # Validate addresses
    if ! validate_addresses; then
        all_valid=false
    fi
    
    if [ "$all_valid" = false ]; then
        echo
        echo -e "${RED}❌ Validation failed. Please fix the issues above.${NC}"
        return 1
    fi
    
    echo
    echo -e "${GREEN}✅ All validations passed${NC}"
    return 0
}