#!/bin/bash
# Contract deployment functions

# Clone or update OIF contracts repository
prepare_contracts_repo() {
    local repo_url=$(get_config ".infrastructure.oif_contracts_repo" \
        "https://github.com/openintentsframework/oif-contracts.git")
    local commit=$(get_config ".infrastructure.oif_contracts_commit" "main")
    
    if [ ! -d "oif-contracts" ]; then
        echo -n "  Cloning oif-contracts... "
        if git clone "$repo_url" oif-contracts > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}Failed${NC}"
            return 1
        fi
    fi
    
    cd oif-contracts
    echo -n "  Checking out commit ${commit}... "
    if git fetch origin > /dev/null 2>&1 && git checkout "$commit" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}Failed${NC}"
        cd ..
        return 1
    fi
    
    return 0
}

# Deploy a single contract
deploy_contract() {
    local contract_path="$1"
    local rpc_url="$2"
    local private_key="$3"
    local contract_name="$4"
    
    echo -n "  Deploying $contract_name... "
    
    # Ensure private key has 0x prefix for forge
    if [[ ! "$private_key" =~ ^0x ]]; then
        private_key="0x$private_key"
    fi
    
    local output=$(forge create "$contract_path" \
        --rpc-url "$rpc_url" \
        --private-key "$private_key" \
        --broadcast 2>&1)
    
    local deployed_address=$(echo "$output" | grep "Deployed to:" | awk '{print $3}')
    
    if [ -z "$deployed_address" ]; then
        echo -e "${RED}Failed${NC}"
        echo "  Error output: $output"
        return 1
    fi
    
    echo -e "${GREEN}✓${NC} $deployed_address"
    # Return address via variable instead of echo to avoid capture issues
    LAST_DEPLOYED_ADDRESS="$deployed_address"
    return 0
}

# Deploy all required contracts
deploy_all_contracts() {
    local origin_rpc="$1"
    local dest_rpc="$2"
    local deployment_key="$3"
    
    # Check if deployment is enabled
    if ! is_enabled ".deployment.deploy_contracts"; then
        echo "  Contract deployment disabled in config"
        return 0
    fi
    
    echo -e "${YELLOW}Deploying contracts...${NC}"
    
    # Prepare contracts repository
    if ! prepare_contracts_repo; then
        echo -e "${RED}Failed to prepare contracts repository${NC}"
        return 1
    fi
    
    # Clear any existing address variables to ensure clean state
    unset ORACLE_ADDRESS_ORIGIN ORACLE_ADDRESS_DEST INPUT_SETTLER_ADDRESS_ORIGIN INPUT_SETTLER_ADDRESS_DEST OUTPUT_SETTLER_ADDRESS_ORIGIN OUTPUT_SETTLER_ADDRESS_DEST
    
    # Track deployed addresses for both chains
    local oracle_address_origin=""
    local oracle_address_dest=""
    local input_settler_address_origin=""
    local input_settler_address_dest=""
    local output_settler_address_origin=""
    local output_settler_address_dest=""
    
    # Deploy contracts based on configuration
    local num_contracts=$(get_config ".deployment.contracts | length" "0")
    
    for ((i=0; i<$num_contracts; i++)); do
        local name=$(get_config ".deployment.contracts[$i].name")
        local contract=$(get_config ".deployment.contracts[$i].contract")
        local chain=$(get_config ".deployment.contracts[$i].chain")
        
        local rpc_url=""
        if [ "$chain" = "origin" ]; then
            rpc_url="$origin_rpc"
            echo -e "${BLUE}=== Origin Chain Deployment ===${NC}"
        elif [ "$chain" = "destination" ]; then
            rpc_url="$dest_rpc"
            echo -e "${BLUE}=== Destination Chain Deployment ===${NC}"
        else
            echo -e "${RED}Unknown chain type: $chain${NC}"
            continue
        fi
        
        deploy_contract "$contract" "$rpc_url" "$deployment_key" "$name"
        
        if [ $? -eq 0 ]; then
            # Store addresses for later use (from LAST_DEPLOYED_ADDRESS variable)
            local address="$LAST_DEPLOYED_ADDRESS"
            case "$name" in
                "AlwaysYesOracle_Origin")
                    oracle_address_origin="$address"
                    export ORACLE_ADDRESS_ORIGIN="$address"
                    ;;
                "AlwaysYesOracle_Destination")
                    oracle_address_dest="$address"
                    export ORACLE_ADDRESS_DEST="$address"
                    ;;
                "InputSettlerEscrow_Origin")
                    input_settler_address_origin="$address"
                    export INPUT_SETTLER_ADDRESS_ORIGIN="$address"
                    ;;
                "InputSettlerEscrow_Destination")
                    input_settler_address_dest="$address"
                    export INPUT_SETTLER_ADDRESS_DEST="$address"
                    ;;
                "OutputSettlerSimple_Origin")
                    output_settler_address_origin="$address"
                    export OUTPUT_SETTLER_ADDRESS_ORIGIN="$address"
                    ;;
                "OutputSettlerSimple_Destination")
                    output_settler_address_dest="$address"
                    export OUTPUT_SETTLER_ADDRESS_DEST="$address"
                    ;;
            esac
        else
            cd ..
            return 1
        fi
    done
    
    cd ..
    
    echo -e "${GREEN}✅ All contracts deployed successfully${NC}"
    return 0
}

# Deploy Hyperlane oracle contracts if needed
deploy_hyperlane_oracles() {
    local origin="$1"
    local dest="$2"
    local deployment_key="$3"
    
    if ! is_settlement_supported "hyperlane" "$origin" "$dest"; then
        return 0
    fi
    
    echo -e "${YELLOW}Checking Hyperlane oracle deployment...${NC}"
    
    # Check if oracles are already deployed
    local origin_oracle=$(get_config ".settlement.eip7683.implementations.hyperlane.supported_chains.\"$origin\".oracle")
    local origin_deployed=$(get_config ".settlement.eip7683.implementations.hyperlane.supported_chains.\"$origin\".oracle_deployed" "false")
    
    local dest_oracle=$(get_config ".settlement.eip7683.implementations.hyperlane.supported_chains.\"$dest\".oracle")
    local dest_deployed=$(get_config ".settlement.eip7683.implementations.hyperlane.supported_chains.\"$dest\".oracle_deployed" "false")
    
    if [ "$origin_deployed" = "false" ] || [ "$dest_deployed" = "false" ]; then
        echo -e "${YELLOW}⚠️  Hyperlane oracles not deployed${NC}"
        echo "  To use Hyperlane settlement, you must:"
        echo "  1. Deploy HyperlaneOracle contracts on both chains"
        echo "  2. Update oracle addresses in testnet-config.json"
        echo "  3. Set oracle_deployed to true for each chain"
        return 1
    fi
    
    echo -e "${GREEN}✓${NC} Hyperlane oracles configured"
    return 0
}

# Verify deployed contracts
verify_contracts() {
    local origin_rpc="$1"
    local dest_rpc="$2"
    
    echo -e "${YELLOW}Verifying deployed contracts...${NC}"
    
    local all_valid=true
    
    # Check contracts on origin chain
    echo "  Origin chain contracts:"
    if [ -n "$ORACLE_ADDRESS_ORIGIN" ]; then
        echo -n "    Oracle... "
        if cast code "$ORACLE_ADDRESS_ORIGIN" --rpc-url "$origin_rpc" 2>/dev/null | grep -q "0x"; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}Not found${NC}"
            all_valid=false
        fi
    fi
    
    if [ -n "$INPUT_SETTLER_ADDRESS_ORIGIN" ]; then
        echo -n "    InputSettler... "
        if cast code "$INPUT_SETTLER_ADDRESS_ORIGIN" --rpc-url "$origin_rpc" 2>/dev/null | grep -q "0x"; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}Not found${NC}"
            all_valid=false
        fi
    fi
    
    if [ -n "$OUTPUT_SETTLER_ADDRESS_ORIGIN" ]; then
        echo -n "    OutputSettler... "
        if cast code "$OUTPUT_SETTLER_ADDRESS_ORIGIN" --rpc-url "$origin_rpc" 2>/dev/null | grep -q "0x"; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}Not found${NC}"
            all_valid=false
        fi
    fi
    
    # Check contracts on destination chain
    echo "  Destination chain contracts:"
    if [ -n "$ORACLE_ADDRESS_DEST" ]; then
        echo -n "    Oracle... "
        if cast code "$ORACLE_ADDRESS_DEST" --rpc-url "$dest_rpc" 2>/dev/null | grep -q "0x"; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}Not found${NC}"
            all_valid=false
        fi
    fi
    
    if [ -n "$INPUT_SETTLER_ADDRESS_DEST" ]; then
        echo -n "    InputSettler... "
        if cast code "$INPUT_SETTLER_ADDRESS_DEST" --rpc-url "$dest_rpc" 2>/dev/null | grep -q "0x"; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}Not found${NC}"
            all_valid=false
        fi
    fi
    
    if [ -n "$OUTPUT_SETTLER_ADDRESS_DEST" ]; then
        echo -n "    OutputSettler... "
        if cast code "$OUTPUT_SETTLER_ADDRESS_DEST" --rpc-url "$dest_rpc" 2>/dev/null | grep -q "0x"; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}Not found${NC}"
            all_valid=false
        fi
    fi
    
    if [ "$all_valid" = false ]; then
        echo -e "${RED}❌ Some contracts are not deployed${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ All contracts verified${NC}"
    return 0
}