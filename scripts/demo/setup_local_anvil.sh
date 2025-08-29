#!/bin/bash

# OIF Solver Demo Environment Setup Script
# =========================================
#
# This script sets up a complete local testing environment for the OIF cross-chain solver.
# It performs the following operations:
#
# 1. Starts two Anvil instances simulating different blockchain networks:
#    - Origin chain on port 8545 (chain ID: 31337)
#    - Destination chain on port 8546 (chain ID: 31338)
#
# 2. Deploys smart contracts on both chains:
#    - ERC20 test tokens for simulating asset transfers
#    - InputSettlerEscrow on the origin chain (handles deposits)
#    - OutputSettler on the destination chain (handles fills)
#    - Mock Oracle contract for intent validation
#
# 3. Configures the test environment:
#    - Funds test accounts with ETH and tokens
#    - Sets up token approvals for the settler contracts
#    - Generates configuration file (config/demo.toml) for the solver
#
# 4. Prepares the environment for testing:
#    - Creates deterministic addresses for all participants
#    - Sets up proper permissions and allowances
#    - Ensures contracts are ready to process intents
#
# After running this script, you can:
# - Start the solver with: cargo run --bin solver -- --config config/demo.toml
# - Send onchain test intents using: ./scripts/demo/send_onchain_intent.sh
# - Send offchain test intents using: ./scripts/demo/send_offchain_intent.sh
#
# NOTE: This script has been tested on macOS systems only.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Helper to extract clean addresses (strip ANSI & whitespace)
addr_from_output() {
  echo "$1" | perl -pe 's/\e\[[0-9;]*[a-zA-Z]//g' | grep -Eo '0x[a-fA-F0-9]{40}' | head -n1
}
# Helper to specifically extract the "Deployed to:" address
deployed_addr_from_output() {
  echo "$1" | perl -pe 's/\e\[[0-9;]*[a-zA-Z]//g' | grep -E "Deployed to:" | awk '{print $3}' | head -n1
}

# Chain configuration
ORIGIN_PORT=8545
DEST_PORT=8546
ORIGIN_CHAIN_ID=31337
DEST_CHAIN_ID=31338

# Account configuration
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
SOLVER_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
USER_ADDRESS="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
USER_PRIVATE_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
RECIPIENT_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

# These will be set during deployment
ORIGIN_COMPACT_ADDRESS=""
ORIGIN_PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"
DEST_PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"
OIF_PINNED_COMMIT="f2a9e8ab9d652894a090814421a7acb9a0547737"

echo -e "${BLUE}🔧 Simple Dual-Chain Anvil Setup${NC}"
echo "======================================"

# Step 1: Clean up
echo -e "${YELLOW}1. Cleaning up...${NC}"
pkill -9 anvil
rm -f origin_anvil.log destination_anvil.log origin.pid destination.pid
sleep 2

# Step 2: Start Anvil chains
start_anvil() {
    local name=$1
    local port=$2
    local chain_id=$3
    
    echo -e "${YELLOW}2. Starting $name chain on port $port...${NC}"
    anvil --chain-id $chain_id --port $port --block-time 2 > ${name}_anvil.log 2>&1 &
    echo $! > ${name}.pid
    sleep 3
}

start_anvil "origin" $ORIGIN_PORT $ORIGIN_CHAIN_ID
start_anvil "destination" $DEST_PORT $DEST_CHAIN_ID

# Check if both are running
if ! curl -s http://localhost:$ORIGIN_PORT > /dev/null || ! curl -s http://localhost:$DEST_PORT > /dev/null; then
    echo -e "${RED}Failed to start Anvil chains${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Both chains running${NC}"
echo

# Step 3: Deploy contracts
echo -e "${YELLOW}3. Deploying contracts...${NC}"

# Define deploy_permit2 function first
deploy_permit2() {
    local chain_name=$1
    local rpc_url=$2
    local permit2_address="0x000000000022D473030F116dDEE9F6B43aC78BA3"
    
    echo -n "  Deploying Permit2 on $chain_name... "
    
    # Check if Permit2 is already deployed
    local permit2_code=$(cast code $permit2_address --rpc-url $rpc_url 2>&1)
    if [ "$permit2_code" = "0x" ] || [ -z "$permit2_code" ]; then
        # Get Permit2 bytecode from mainnet
        local mainnet_permit2_code=$(cast code $permit2_address --rpc-url https://ethereum-rpc.publicnode.com 2>/dev/null | grep "^0x" | head -n1)
        
        if [ ! -z "$mainnet_permit2_code" ] && [ "$mainnet_permit2_code" != "0x" ]; then
            # Deploy using mainnet bytecode
            cast rpc anvil_setCode $permit2_address "$mainnet_permit2_code" --rpc-url $rpc_url > /dev/null 2>&1
            
            # Verify deployment
            local new_code=$(cast code $permit2_address --rpc-url $rpc_url 2>&1)
            if [ ! -z "$new_code" ] && [ "$new_code" != "0x" ]; then
                echo -e "${GREEN}✓${NC} $permit2_address"
            else
                echo -e "${RED}Failed${NC}"
                exit 1
            fi
        else
            echo -e "${RED}Failed to fetch Permit2 bytecode from mainnet${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✓${NC} $permit2_address (already deployed)"
    fi
}

# Prepare contract sources for TokenA and TokenB with EIP-3009 support
cat > /tmp/TokenA.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TokenA {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(bytes32 => bool) public authorizationState;
    
    string public name = "Token A";
    string public symbol = "TOKA";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    // EIP-712 Domain Separator
    bytes32 public DOMAIN_SEPARATOR;
    
    // EIP-3009 type hashes
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = 
        keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            block.chainid,
            address(this)
        ));
    }
    
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
        return true;
    }
    
    // EIP-3009: receiveWithAuthorization
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        require(block.timestamp > validAfter, "Authorization not yet valid");
        require(block.timestamp < validBefore, "Authorization expired");
        require(!authorizationState[nonce], "Authorization already used");
        require(signature.length == 65, "Invalid signature length");
        
        // Extract v, r, s from signature
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            ))
        ));
        
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress == from, "Invalid signature");
        
        authorizationState[nonce] = true;
        require(balanceOf[from] >= value, "Insufficient balance");
        
        balanceOf[from] -= value;
        balanceOf[to] += value;
        
        emit Transfer(from, to, value);
        emit AuthorizationUsed(from, nonce);
    }
    
    // EIP-165: Interface detection
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0xef55bec6; // receiveWithAuthorization selector
    }
}
EOF

cat > /tmp/TokenB.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TokenB {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(bytes32 => bool) public authorizationState;
    
    string public name = "Token B";
    string public symbol = "TOKB";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    // EIP-712 Domain Separator
    bytes32 public DOMAIN_SEPARATOR;
    
    // EIP-3009 type hashes
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = 
        keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            block.chainid,
            address(this)
        ));
    }
    
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
        return true;
    }
    
    // EIP-3009: receiveWithAuthorization
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        require(block.timestamp > validAfter, "Authorization not yet valid");
        require(block.timestamp < validBefore, "Authorization expired");
        require(!authorizationState[nonce], "Authorization already used");
        require(signature.length == 65, "Invalid signature length");
        
        // Extract v, r, s from signature
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            ))
        ));
        
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress == from, "Invalid signature");
        
        authorizationState[nonce] = true;
        require(balanceOf[from] >= value, "Insufficient balance");
        
        balanceOf[from] -= value;
        balanceOf[to] += value;
        
        emit Transfer(from, to, value);
        emit AuthorizationUsed(from, nonce);
    }
    
    // EIP-165: Interface detection
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0xef55bec6; // receiveWithAuthorization selector
    }
}
EOF

# Clone or update oif-contracts (needed for contracts)
echo -e "${BLUE}=== Setting up OIF contracts ===${NC}"

# Clone or update oif-contracts to specific commit
if [ ! -d "oif-contracts" ]; then
    echo -n "  Cloning oif-contracts... "
    git clone https://github.com/openintentsframework/oif-contracts.git > /dev/null 2>&1
    echo -e "${GREEN}✓${NC}"
fi

cd oif-contracts
echo -n "  Checking out oif-contracts commit ${OIF_PINNED_COMMIT}... "
git fetch origin > /dev/null 2>&1
git checkout ${OIF_PINNED_COMMIT} > /dev/null 2>&1
echo -e "${GREEN}✓${NC}"

# Install dependencies for Compact support
echo -n "  Installing oif-contracts dependencies... "
~/.foundry/bin/forge install > /dev/null 2>&1
echo -e "${GREEN}✓${NC}"

# Build project to ensure all dependencies are properly resolved
echo -n "  Building oif-contracts project... "
~/.foundry/bin/forge build > /dev/null 2>&1
echo -e "${GREEN}✓${NC}"

# Deploy contracts in the same order on both chains for deterministic addresses
echo
echo -e "${BLUE}=== Deploying Contracts ===${NC}"

# Deploy Permit2 on both chains first
deploy_permit2 "origin" "http://localhost:$ORIGIN_PORT"
deploy_permit2 "destination" "http://localhost:$DEST_PORT"

# Deploy TokenA (Contract #1 - same address on both chains)
echo -n "  Deploying TokenA on both chains... "
TOKENA_OUTPUT=$(~/.foundry/bin/forge create /tmp/TokenA.sol:TokenA \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKENA=$(echo "$TOKENA_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$TOKENA" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

TOKENA_DEST_OUTPUT=$(~/.foundry/bin/forge create /tmp/TokenA.sol:TokenA \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKENA_DEST_CHECK=$(echo "$TOKENA_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$TOKENA" != "$TOKENA_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $TOKENA"

# Deploy TokenB (Contract #2 - same address on both chains)
echo -n "  Deploying TokenB on both chains... "
TOKENB_OUTPUT=$(~/.foundry/bin/forge create /tmp/TokenB.sol:TokenB \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKENB=$(echo "$TOKENB_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$TOKENB" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

TOKENB_DEST_OUTPUT=$(~/.foundry/bin/forge create /tmp/TokenB.sol:TokenB \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
TOKENB_DEST_CHECK=$(echo "$TOKENB_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$TOKENB" != "$TOKENB_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $TOKENB"

# Deploy InputSettlerEscrow (Contract #4 - same address on both chains)
echo -n "  Deploying InputSettlerEscrow on both chains... "
INPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/input/escrow/InputSettlerEscrow.sol:InputSettlerEscrow \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
INPUT_SETTLER=$(echo "$INPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$INPUT_SETTLER" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

INPUT_SETTLER_DEST_OUTPUT=$(~/.foundry/bin/forge create src/input/escrow/InputSettlerEscrow.sol:InputSettlerEscrow \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
INPUT_SETTLER_DEST_CHECK=$(echo "$INPUT_SETTLER_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$INPUT_SETTLER" != "$INPUT_SETTLER_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $INPUT_SETTLER"

echo -n "  Deploying OutputSettler on both chains... "
OUTPUT_SETTLER_OUTPUT=$(~/.foundry/bin/forge create src/output/coin/OutputSettler7683.sol:OutputInputSettlerEscrow \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
OUTPUT_SETTLER=$(echo "$OUTPUT_SETTLER_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$OUTPUT_SETTLER" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

OUTPUT_SETTLER_DEST_OUTPUT=$(~/.foundry/bin/forge create src/output/coin/OutputSettler7683.sol:OutputInputSettlerEscrow \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
OUTPUT_SETTLER_DEST_CHECK=$(echo "$OUTPUT_SETTLER_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$OUTPUT_SETTLER" != "$OUTPUT_SETTLER_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $OUTPUT_SETTLER"

# Deploy Oracle on both chains (Contract #4 - same address on both chains)
echo -n "  Deploying AlwaysYesOracle on both chains... "
ORACLE_OUTPUT=$(~/.foundry/bin/forge create test/mocks/AlwaysYesOracle.sol:AlwaysYesOracle \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
ORACLE=$(echo "$ORACLE_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ -z "$ORACLE" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

ORACLE_DEST_OUTPUT=$(~/.foundry/bin/forge create test/mocks/AlwaysYesOracle.sol:AlwaysYesOracle \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
ORACLE_DEST_CHECK=$(echo "$ORACLE_DEST_OUTPUT" | grep "Deployed to:" | awk '{print $3}')
if [ "$ORACLE" != "$ORACLE_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $ORACLE"

# Deploy TheCompact (Contract #5 - same address on both chains)
echo -n "  Deploying TheCompact on both chains... "
COMPACT_OUTPUT=$(~/.foundry/bin/forge create lib/the-compact/src/TheCompact.sol:TheCompact \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
THE_COMPACT=$(deployed_addr_from_output "$COMPACT_OUTPUT")
if [ -z "$THE_COMPACT" ]; then
    echo -e "${RED}Failed on origin${NC}"
    echo "---- forge output ----"
    echo "$COMPACT_OUTPUT"
    echo "----------------------"
    exit 1
fi

COMPACT_DEST_OUTPUT=$(~/.foundry/bin/forge create lib/the-compact/src/TheCompact.sol:TheCompact \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
COMPACT_DEST_CHECK=$(deployed_addr_from_output "$COMPACT_DEST_OUTPUT")
if [ "$THE_COMPACT" != "$COMPACT_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    echo "---- forge output (dest) ----"
    echo "$COMPACT_DEST_OUTPUT"
    echo "-----------------------------"
    exit 1
fi
echo -e "${GREEN}✓${NC} $THE_COMPACT"

echo -n "  Deploying AlwaysOKAllocator on both chains... "
# Deploy AlwaysOKAllocator via forge 
ALLOC_OUTPUT=$(~/.foundry/bin/forge create lib/the-compact/src/test/AlwaysOKAllocator.sol:AlwaysOKAllocator \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
ALLOCATOR_ADDR=$(deployed_addr_from_output "$ALLOC_OUTPUT")
if [ -z "$ALLOCATOR_ADDR" ]; then
    echo -e "${RED}Failed on origin${NC}"
    exit 1
fi

# Deploy on destination chain for deterministic address
ALLOC_DEST_OUTPUT=$(~/.foundry/bin/forge create lib/the-compact/src/test/AlwaysOKAllocator.sol:AlwaysOKAllocator \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1)
ALLOCATOR_DEST_CHECK=$(deployed_addr_from_output "$ALLOC_DEST_OUTPUT")
if [ "$ALLOCATOR_ADDR" != "$ALLOCATOR_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} $ALLOCATOR_ADDR"

# Register allocator with TheCompact on both chains
echo -n "  Registering AlwaysOKAllocator with TheCompact... "

# Register the allocator and extract the ID from logs (like test file approach)
REGISTRATION_OUTPUT=$(cast send $THE_COMPACT "__registerAllocator(address,bytes)" $ALLOCATOR_ADDR "0x" \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY 2>&1)

# Extract allocator ID from the AllocatorRegistered event logs  
# Event data format: allocatorId (uint96, 32 bytes padded) + allocatorAddress (address, 32 bytes padded)
# The allocatorId is in the first 64 hex chars, with the actual ID in the last 24 chars
ALLOCATOR_ID_FROM_LOGS=$(echo "$REGISTRATION_OUTPUT" | grep -o '"data":"0x[^"]*"' | sed 's/"data":"0x//' | sed 's/"//' | cut -c41-64)

if [ -n "$ALLOCATOR_ID_FROM_LOGS" ] && [ ${#ALLOCATOR_ID_FROM_LOGS} -eq 24 ]; then
    ALWAYS_OK_ALLOCATOR_LOCK_TAG="0x${ALLOCATOR_ID_FROM_LOGS}"
    echo -e "${GREEN}✓${NC} Extracted Lock Tag: $ALWAYS_OK_ALLOCATOR_LOCK_TAG"
elif echo "$REGISTRATION_OUTPUT" | grep -q "AllocatorAlreadyRegistered"; then
    # If already registered, use the known deterministic value
    ALWAYS_OK_ALLOCATOR_LOCK_TAG="0x00a9beca4e685f962f0cf6c9" 
    echo -e "${GREEN}✓${NC} Already registered, using known Lock Tag: $ALWAYS_OK_ALLOCATOR_LOCK_TAG"
else
    # Check if registration succeeded but we couldn't extract
    if echo "$REGISTRATION_OUTPUT" | grep -q "status.*1.*success"; then
        ALWAYS_OK_ALLOCATOR_LOCK_TAG="0x00a9beca4e685f962f0cf6c9"
        echo -e "${GREEN}✓${NC} Registration succeeded, using known Lock Tag: $ALWAYS_OK_ALLOCATOR_LOCK_TAG"
    else
        echo -e "${RED}❌ Registration failed${NC}"
        echo "$REGISTRATION_OUTPUT"
        exit 1
    fi
fi

ALLOCATOR_ID_HEX=$ALWAYS_OK_ALLOCATOR_LOCK_TAG

# Also register on destination chain for consistency
cast send $THE_COMPACT "__registerAllocator(address,bytes)" $ALLOCATOR_ADDR "0x" \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY > /dev/null 2>&1

# Note: Token deposit into TheCompact will happen after token minting

# Deploy InputSettlerCompact (Contract #6 - same address on both chains)
INPUT_SETTLER_COMPACT_OUTPUT=$(env -u ETH_FROM ~/.foundry/bin/forge create src/input/compact/InputSettlerCompact.sol:InputSettlerCompact \
    --constructor-args $THE_COMPACT \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1 || true)
INPUT_SETTLER_COMPACT=$(deployed_addr_from_output "$INPUT_SETTLER_COMPACT_OUTPUT")
if [ -z "$INPUT_SETTLER_COMPACT" ]; then
    echo -e "${YELLOW}Forge create failed; retrying via cast...${NC}"
    ORIG_BYTECODE=$(~/.foundry/bin/forge inspect src/input/compact/InputSettlerCompact.sol:InputSettlerCompact bytecode)
    ORIG_ARGS=$(cast abi-encode "constructor(address)" "$THE_COMPACT" | cut -c3-)
    # Use unlocked account and capture tx hash, then receipt to get contract address
    TX_HASH=$(cast send --create "${ORIG_BYTECODE}${ORIG_ARGS}" --rpc-url http://localhost:$ORIGIN_PORT --unlocked --from $SOLVER_ADDRESS 2>&1 | grep -Eo '0x[0-9a-fA-F]{64}' | head -n1)
    if [ -n "$TX_HASH" ]; then
        RECEIPT_JSON=$(cast receipt $TX_HASH --rpc-url http://localhost:$ORIGIN_PORT --json 2>/dev/null)
        INPUT_SETTLER_COMPACT=$(echo "$RECEIPT_JSON" | jq -r '.contractAddress' 2>/dev/null)
    fi
fi
if [ -z "$INPUT_SETTLER_COMPACT" ] || [ "$INPUT_SETTLER_COMPACT" = "null" ]; then
    echo -e "${YELLOW}Cast send failed; retrying via raw eth_sendTransaction...${NC}"
    ORIG_BYTECODE=$(~/.foundry/bin/forge inspect src/input/compact/InputSettlerCompact.sol:InputSettlerCompact bytecode)
    ORIG_ARGS=$(cast abi-encode "constructor(address)" "$THE_COMPACT" | cut -c3-)
    INITCODE="${ORIG_BYTECODE}${ORIG_ARGS}"
    TX_HASH=$(cast rpc --rpc-url http://localhost:$ORIGIN_PORT eth_sendTransaction "{\"from\":\"$SOLVER_ADDRESS\",\"data\":\"$INITCODE\"}" 2>&1 | grep -Eo '0x[0-9a-fA-F]{64}' | head -n1)
    if [ -n "$TX_HASH" ]; then
        RECEIPT_JSON=$(cast receipt $TX_HASH --rpc-url http://localhost:$ORIGIN_PORT --json 2>/dev/null)
        INPUT_SETTLER_COMPACT=$(echo "$RECEIPT_JSON" | jq -r '.contractAddress' 2>/dev/null)
    fi
fi
if [ -z "$INPUT_SETTLER_COMPACT" ] || [ "$INPUT_SETTLER_COMPACT" = "null" ]; then
    echo -e "${RED}Failed on origin${NC}"
    echo "---- forge/cast output ----"
    echo "$INPUT_SETTLER_COMPACT_OUTPUT"
    echo "TX: $TX_HASH"
    echo "---------------------------"
    exit 1
fi

INPUT_SETTLER_COMPACT_DEST_OUTPUT=$(env -u ETH_FROM ~/.foundry/bin/forge create src/input/compact/InputSettlerCompact.sol:InputSettlerCompact \
    --constructor-args $THE_COMPACT \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY \
    --broadcast 2>&1 || true)
INPUT_SETTLER_COMPACT_DEST_CHECK=$(deployed_addr_from_output "$INPUT_SETTLER_COMPACT_DEST_OUTPUT")
if [ -z "$INPUT_SETTLER_COMPACT_DEST_CHECK" ]; then
    echo -e "${YELLOW}Forge create (dest) failed; retrying via cast...${NC}"
    DEST_BYTECODE=$(~/.foundry/bin/forge inspect src/input/compact/InputSettlerCompact.sol:InputSettlerCompact bytecode)
    DEST_ARGS=$(cast abi-encode "constructor(address)" "$THE_COMPACT" | cut -c3-)
    TX_HASH_DEST=$(cast send --create "${DEST_BYTECODE}${DEST_ARGS}" --rpc-url http://localhost:$DEST_PORT --unlocked --from $SOLVER_ADDRESS 2>&1 | grep -Eo '0x[0-9a-fA-F]{64}' | head -n1)
    if [ -n "$TX_HASH_DEST" ]; then
        RECEIPT_JSON_DEST=$(cast receipt $TX_HASH_DEST --rpc-url http://localhost:$DEST_PORT --json 2>/dev/null)
        INPUT_SETTLER_COMPACT_DEST_CHECK=$(echo "$RECEIPT_JSON_DEST" | jq -r '.contractAddress' 2>/dev/null)
    fi
fi
if [ -z "$INPUT_SETTLER_COMPACT_DEST_CHECK" ] || [ "$INPUT_SETTLER_COMPACT_DEST_CHECK" = "null" ]; then
    echo -e "${YELLOW}Cast send (dest) failed; retrying via raw eth_sendTransaction...${NC}"
    DEST_BYTECODE=$(~/.foundry/bin/forge inspect src/input/compact/InputSettlerCompact.sol:InputSettlerCompact bytecode)
    DEST_ARGS=$(cast abi-encode "constructor(address)" "$THE_COMPACT" | cut -c3-)
    INITCODE_DEST="${DEST_BYTECODE}${DEST_ARGS}"
    TX_HASH_DEST=$(cast rpc --rpc-url http://localhost:$DEST_PORT eth_sendTransaction "{\"from\":\"$SOLVER_ADDRESS\",\"data\":\"$INITCODE_DEST\"}" 2>&1 | grep -Eo '0x[0-9a-fA-F]{64}' | head -n1)
    if [ -n "$TX_HASH_DEST" ]; then
        RECEIPT_JSON_DEST=$(cast receipt $TX_HASH_DEST --rpc-url http://localhost:$DEST_PORT --json 2>/dev/null)
        INPUT_SETTLER_COMPACT_DEST_CHECK=$(echo "$RECEIPT_JSON_DEST" | jq -r '.contractAddress' 2>/dev/null)
    fi
fi
if [ "$INPUT_SETTLER_COMPACT" != "$INPUT_SETTLER_COMPACT_DEST_CHECK" ]; then
    echo -e "${RED}Address mismatch!${NC}"
    echo "---- forge output (dest) ----"
    echo "$INPUT_SETTLER_COMPACT_DEST_OUTPUT"
    echo "-----------------------------"
    exit 1
fi
echo -e "${GREEN}✓${NC} $INPUT_SETTLER_COMPACT"

cd ..

# Step 4: Setup tokens
echo
echo -e "${YELLOW}4. Setting up tokens...${NC}"

# Mint TokenA on origin chain (100 to user)
echo -n "  Minting 100 TokenA to user on origin... "
cast send $TOKENA "mint(address,uint256)" $USER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Mint TokenA on destination chain (100 to solver)
echo -n "  Minting 100 TokenA to solver on destination... "
cast send $TOKENA "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Also mint TokenA to solver on origin chain for bidirectional testing
echo -n "  Minting 100 TokenA to solver on origin... "
cast send $TOKENA "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Mint TokenB on origin chain (100 to user)
echo -n "  Minting 100 TokenB to user on origin... "
cast send $TOKENB "mint(address,uint256)" $USER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Mint TokenB on destination chain (100 to solver)
echo -n "  Minting 100 TokenB to solver on destination... "
cast send $TOKENB "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$DEST_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Also mint TokenB to solver on origin chain for bidirectional testing
echo -n "  Minting 100 TokenB to solver on origin... "
cast send $TOKENB "mint(address,uint256)" $SOLVER_ADDRESS 100000000000000000000 \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Approve Permit2 to spend user's TokenA on origin chain
echo -n "  Approving Permit2 to spend user's TokenA on origin... "
cast send $TOKENA "approve(address,uint256)" $ORIGIN_PERMIT2_ADDRESS "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --from $USER_ADDRESS \
    --private-key $USER_PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Approve Permit2 to spend user's TokenB on origin chain
echo -n "  Approving Permit2 to spend user's TokenB on origin... "
cast send $TOKENB "approve(address,uint256)" $ORIGIN_PERMIT2_ADDRESS "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --from $USER_ADDRESS \
    --private-key $USER_PRIVATE_KEY > /dev/null
echo -e "${GREEN}✓${NC}"

# Now deposit tokens into TheCompact for resource lock (after user has tokens)
echo -n "  Depositing tokens into TheCompact for resource lock... "
DEMO_DEPOSIT_AMOUNT=5000000000000000000  # 5 tokens

# Approve TheCompact to pull user's tokens
APPROVE_RESULT=$(env -u ETH_FROM -u ETH_KEYSTORE_DIR -u ETH_KEYSTORE_PASSWORD_FILE ~/.foundry/bin/cast send $TOKENA "approve(address,uint256)" $THE_COMPACT $DEMO_DEPOSIT_AMOUNT \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $USER_PRIVATE_KEY 2>&1)

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to approve TheCompact${NC}"
    echo "Error: $APPROVE_RESULT"
    exit 1
fi

# Deposit ERC20 to create resource lock
DEPOSIT_RESULT=$(env -u ETH_FROM -u ETH_KEYSTORE_DIR -u ETH_KEYSTORE_PASSWORD_FILE ~/.foundry/bin/cast send $THE_COMPACT "depositERC20(address,bytes12,uint256,address)" $TOKENA $ALWAYS_OK_ALLOCATOR_LOCK_TAG $DEMO_DEPOSIT_AMOUNT $USER_ADDRESS \
    --rpc-url http://localhost:$ORIGIN_PORT \
    --private-key $USER_PRIVATE_KEY 2>&1)

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to deposit into TheCompact${NC}"
    echo "Error: $DEPOSIT_RESULT"
    exit 1
fi

# Compute tokenId (lockTag || token)
TOKEN_ID_HEX=0x$(echo $ALWAYS_OK_ALLOCATOR_LOCK_TAG | cut -c3-)$(echo $TOKENA | cut -c3-)

# Verify the deposit was successful
BALANCE=$(env -u ETH_FROM -u ETH_KEYSTORE_DIR -u ETH_KEYSTORE_PASSWORD_FILE ~/.foundry/bin/cast call $THE_COMPACT "balanceOf(address,uint256)" $USER_ADDRESS $(env -u ETH_FROM ~/.foundry/bin/cast to-dec $TOKEN_ID_HEX) --rpc-url http://localhost:$ORIGIN_PORT)
BALANCE_DEC=$(env -u ETH_FROM ~/.foundry/bin/cast to-dec $BALANCE 2>/dev/null || echo "0")

if [ "$BALANCE_DEC" -lt "$DEMO_DEPOSIT_AMOUNT" ]; then
    echo -e "${RED}Deposit verification failed${NC}"
    echo "Expected: $DEMO_DEPOSIT_AMOUNT, Got: $BALANCE_DEC"
    exit 1
fi

echo -e "${GREEN}✓${NC} Deposited $(echo "scale=1; $BALANCE_DEC / 1000000000000000000" | bc -l) tokens"
echo -e "${GREEN}✓${NC} Resource lock ID: $TOKEN_ID_HEX"

# Step 5: Create config files (modular structure)
echo
echo -e "${YELLOW}5. Creating modular config files...${NC}"

mkdir -p config/demo

# Create main config file with includes
cat > config/demo.toml << EOF
# OIF Solver Configuration - Main File

include = [
    "demo/networks.toml",
    "demo/api.toml",
    "demo/gas.toml"
]

[solver]
id = "oif-solver-demo"
monitoring_timeout_minutes = 5

# ============================================================================
# STORAGE
# ============================================================================
[storage]
primary = "file"
cleanup_interval_seconds = 60

[storage.implementations.memory]
# Memory storage has no configuration

[storage.implementations.file]
storage_path = "./data/storage"
ttl_orders = 300                  # 5 minutes
ttl_intents = 120                 # 2 minutes
ttl_order_by_tx_hash = 300        # 5 minutes

# ============================================================================
# ACCOUNT
# ============================================================================
[account]
primary = "local"

[account.implementations.local]
private_key = "\${ETH_PRIVATE_KEY:-$PRIVATE_KEY}"

# ============================================================================
# DELIVERY
# ============================================================================
[delivery]
min_confirmations = 1

[delivery.implementations.evm_alloy]
network_ids = [$ORIGIN_CHAIN_ID, $DEST_CHAIN_ID]

# ============================================================================
# DISCOVERY
# ============================================================================
[discovery]

[discovery.implementations.onchain_eip7683]
network_ids = [$ORIGIN_CHAIN_ID, $DEST_CHAIN_ID]
polling_interval_secs = 0  # Use WebSocket subscriptions instead of polling

[discovery.implementations.offchain_eip7683]
api_host = "127.0.0.1"
api_port = 8081
network_ids = [$ORIGIN_CHAIN_ID]

# ============================================================================
# ORDER
# ============================================================================
[order]

[order.implementations.eip7683]

[order.strategy]
primary = "simple"

[order.strategy.implementations.simple]
max_gas_price_gwei = 100

# ============================================================================
# SETTLEMENT
# ============================================================================
[settlement]

[settlement.domain]
chain_id = 1
address = "$INPUT_SETTLER"

[settlement.implementations.direct]
order = "eip7683"
network_ids = [$ORIGIN_CHAIN_ID, $DEST_CHAIN_ID]
dispute_period_seconds = 1
# Oracle selection strategy when multiple oracles are available (First, RoundRobin, Random)
oracle_selection_strategy = "First"

# Oracle configuration with multiple oracle support
[settlement.implementations.direct.oracles]
# Input oracles (on origin chains)
input = { $ORIGIN_CHAIN_ID = ["$ORACLE"], $DEST_CHAIN_ID = ["$ORACLE"] }
# Output oracles (on destination chains)
output = { $ORIGIN_CHAIN_ID = ["$ORACLE"], $DEST_CHAIN_ID = ["$ORACLE"] }

# Valid routes: from origin chain -> to destination chains
[settlement.implementations.direct.routes]
$ORIGIN_CHAIN_ID = [$DEST_CHAIN_ID]  # Can go from origin to destination
$DEST_CHAIN_ID = [$ORIGIN_CHAIN_ID]  # Can go from destination to origin


# ============================================================================
# DEMO SCRIPT CONFIGURATION
# The following sections are used by demo scripts (send_onchain_intent.sh, etc.)
# and are NOT required by the solver itself. The solver only needs the
# configurations above.
# ============================================================================

# Contract addresses for testing (used by demo scripts)
[contracts.origin]
tokenA = "$TOKENA"
tokenB = "$TOKENB"
permit2 = "$ORIGIN_PERMIT2_ADDRESS"

[contracts.destination]
tokenA = "$TOKENA"
tokenB = "$TOKENB"
permit2 = "$DEST_PERMIT2_ADDRESS"

# Test accounts (used by demo scripts)
[accounts]
solver = "$SOLVER_ADDRESS"
user = "$USER_ADDRESS"
user_private_key = "$USER_PRIVATE_KEY"
recipient = "$RECIPIENT_ADDR"
EOF

# Create networks.toml
cat > config/demo/networks.toml << EOF
# Network Configuration
# Defines all supported blockchain networks and their tokens

[networks.$ORIGIN_CHAIN_ID]
input_settler_address = "$INPUT_SETTLER"
input_settler_compact_address = "$INPUT_SETTLER_COMPACT"
the_compact_address = "$THE_COMPACT"
allocator_address = "$ALLOCATOR_ADDR"
output_settler_address = "$OUTPUT_SETTLER"

# RPC endpoints with both HTTP and WebSocket URLs for each network
[[networks.$ORIGIN_CHAIN_ID.rpc_urls]]
http = "http://localhost:$ORIGIN_PORT"
ws = "ws://localhost:$ORIGIN_PORT"

[[networks.$ORIGIN_CHAIN_ID.tokens]]
address = "$TOKENA"
symbol = "TOKA"
decimals = 18

[[networks.$ORIGIN_CHAIN_ID.tokens]]
address = "$TOKENB"
symbol = "TOKB"
decimals = 18

[networks.$DEST_CHAIN_ID]
input_settler_address = "$INPUT_SETTLER"
input_settler_compact_address = "$INPUT_SETTLER_COMPACT"
the_compact_address = "$THE_COMPACT"
allocator_address = "$ALLOCATOR_ADDR"
output_settler_address = "$OUTPUT_SETTLER"

# RPC endpoints with both HTTP and WebSocket URLs for each network
[[networks.$DEST_CHAIN_ID.rpc_urls]]
http = "http://localhost:$DEST_PORT"
ws = "ws://localhost:$DEST_PORT"

[[networks.$DEST_CHAIN_ID.tokens]]
address = "$TOKENA"
symbol = "TOKA"
decimals = 18

[[networks.$DEST_CHAIN_ID.tokens]]
address = "$TOKENB"
symbol = "TOKB"
decimals = 18
EOF

# Create api.toml
cat > config/demo/api.toml << EOF
# API Server Configuration
# Configures the HTTP API for receiving off-chain intents

[api]
enabled = true
host = "127.0.0.1"
port = 3000
timeout_seconds = 30
max_request_size = 1048576  # 1MB

[api.implementations]
discovery = "offchain_eip7683"
EOF

echo -e "  ${GREEN}✓${NC} Created modular config files:"
echo -e "    - config/demo.toml (main config with includes)"
echo -e "    - config/demo/networks.toml (network configurations)"
echo -e "    - config/demo/api.toml (API server settings)"

# Generate compact.env in root for the send script
cat > compact.env << EOF
ALWAYS_OK_ALLOCATOR_LOCK_TAG="$ALWAYS_OK_ALLOCATOR_LOCK_TAG"
TOKEN_ID_HEX="$TOKEN_ID_HEX"
ALLOCATOR_ID_HEX="$ALLOCATOR_ID_HEX"
DEMO_DEPOSIT_AMOUNT="$DEMO_DEPOSIT_AMOUNT"
EOF

echo -e "${GREEN}✓${NC} Updated compact.env with:"
echo -e "    ALWAYS_OK_ALLOCATOR_LOCK_TAG=$ALWAYS_OK_ALLOCATOR_LOCK_TAG"
echo -e "    TOKEN_ID_HEX=$TOKEN_ID_HEX"
echo -e "    Deposited: $(echo "scale=1; $DEMO_DEPOSIT_AMOUNT / 1000000000000000000" | bc -l) tokens"

# Done!
echo
echo -e "${GREEN}✅ Setup complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo -e "${BLUE}🔗 Networks:${NC}"
echo "  Origin:      http://localhost:$ORIGIN_PORT (chain $ORIGIN_CHAIN_ID)"
echo "  Destination: http://localhost:$DEST_PORT (chain $DEST_CHAIN_ID)"
echo
echo -e "${BLUE}📋 Contracts (same addresses on both chains):${NC}"
echo "  TokenA:        $TOKENA"
echo "  TokenB:        $TOKENB"
echo "  TheCompact:    $THE_COMPACT"
echo "  AlwaysOKAllocator: $ALLOCATOR_ADDR"
echo "  InputSettler (Escrow):   $INPUT_SETTLER"
echo "  InputSettler (Compact):  $INPUT_SETTLER_COMPACT"
echo "  OutputSettler: $OUTPUT_SETTLER"
echo "  Oracle:        $ORACLE"
echo "  Permit2:       $ORIGIN_PERMIT2_ADDRESS"
echo
echo -e "${BLUE}💰 Token Balances:${NC}"
echo "  User:   100 TOKA and 100 TOKB on origin chain (Permit2 approved)"
echo "  Solver: 100 TOKA and 100 TOKB on both chains"
echo
echo -e "${BLUE}📋 Configuration:${NC}"
echo "  Main config: config/demo.toml (with modular includes)"
echo "  Modules: config/demo/networks.toml, config/demo/api.toml"
echo
echo -e "${YELLOW}To start the solver:${NC}"
echo "  cargo run --bin solver -- --config config/demo.toml"
echo
echo -e "${YELLOW}Press Ctrl+C to stop Anvil chains${NC}"

# Keep running
while true; do
    sleep 10
done