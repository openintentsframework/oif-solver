#!/usr/bin/env bash
#
# ==============================================================================
# Deployment Module - Environment Setup and Contract Management
# ==============================================================================
#
# This module manages the complete local development environment including
# Anvil chain deployment, smart contract deployment, and configuration generation.
#
# Key Features:
# - Multi-chain Anvil setup and management
# - Smart contract deployment orchestration
# - Configuration file generation
# - Process lifecycle management
# - Environment cleanup and reset
# - Health checks and status monitoring
#
# Deployment Workflow:
# 1. Start Anvil chains (origin and destination)
# 2. Deploy test tokens (TokenA, TokenB)
# 3. Deploy settler contracts (Escrow and Compact)
# 4. Deploy oracle and auxiliary contracts
# 5. Initialize token balances and approvals
# 6. Generate configuration files
#
# Contract Types:
# - Test Tokens: ERC20 tokens for testing
# - Escrow Settlers: Traditional escrow-based settlement
# - Compact Settlers: ResourceLock-based settlement
# - Oracle: Attestation and verification
# - TheCompact/Allocator: Compact protocol infrastructure
#
# Dependencies:
# - anvil: Local Ethereum node
# - forge: Smart contract deployment
# - cast: Blockchain interactions
# - jq: JSON processing
#
# Usage:
#   env_up        # Start complete environment
#   env_down      # Stop all chains
#   env_status    # Check environment status
#   env_reset     # Clean reset of environment
#
# ==============================================================================

# -----------------------------------------------------------------------------
# Configuration Constants
# -----------------------------------------------------------------------------
# Default block time for Anvil
DEFAULT_BLOCK_TIME=2

# PID files for process management
ANVIL_PIDS_DIR="${SCRIPT_DIR}/.pids"

# Log files
ANVIL_LOGS_DIR="${SCRIPT_DIR}/.logs"

# Contract addresses (filled during deployment)
declare -gA DEPLOYED_CONTRACTS
DEPLOYED_CONTRACTS[origin_tokena]=""
DEPLOYED_CONTRACTS[origin_tokenb]=""
DEPLOYED_CONTRACTS[dest_tokena]=""
DEPLOYED_CONTRACTS[dest_tokenb]=""
DEPLOYED_CONTRACTS[input_settler_escrow]=""
DEPLOYED_CONTRACTS[input_settler_compact]=""
DEPLOYED_CONTRACTS[output_settler]=""
DEPLOYED_CONTRACTS[oracle]=""
DEPLOYED_CONTRACTS[the_compact]=""
DEPLOYED_CONTRACTS[allocator]=""

# Fixed addresses
PERMIT2_ADDRESS="0x000000000022D473030F116dDEE9F6B43aC78BA3"

# Initialize deployment environment
init_deployment_env() {
    ensure_dir "$ANVIL_PIDS_DIR"
    ensure_dir "$ANVIL_LOGS_DIR"
    
    print_debug "Deployment environment initialized"
    print_debug "PID directory: $ANVIL_PIDS_DIR"
    print_debug "Log directory: $ANVIL_LOGS_DIR"
}

# Check if anvil is available
check_anvil() {
    if ! command -v anvil &> /dev/null; then
        print_error "Anvil not found!"
        print_info "Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
        return 1
    fi
    
    print_debug "Anvil found: $(which anvil)"
    return 0
}

# Start single anvil instance
start_anvil_instance() {
    local name="$1"
    local port="$2"
    local chain_id="$3"
    local block_time="${4:-$DEFAULT_BLOCK_TIME}"
    local pid_file="$5"
    local log_file="$6"
    
    if ! check_anvil; then
        return 1
    fi
    
    print_info "Starting $name anvil on port $port (chain $chain_id)..."
    
    # Check if port is already in use
    if nc -z localhost "$port" 2>/dev/null; then
        print_warning "Port $port is already in use"
        
        # Check if it's our anvil process
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if is_process_running "$pid"; then
                print_info "$name anvil already running (PID: $pid)"
                return 0
            else
                print_debug "Removing stale PID file"
                rm -f "$pid_file"
            fi
        fi
    fi
    
    # Start anvil in background
    anvil --chain-id "$chain_id" --port "$port" --block-time "$block_time" \
          > "$log_file" 2>&1 &
    
    local anvil_pid=$!
    echo "$anvil_pid" > "$pid_file"
    
    print_debug "$name anvil started with PID: $anvil_pid"
    print_debug "Log file: $log_file"
    
    # Wait for anvil to be ready
    local timeout=30
    local elapsed=0
    
    while ! nc -z localhost "$port" 2>/dev/null; do
        if [ $elapsed -ge $timeout ]; then
            print_error "$name anvil failed to start within ${timeout}s"
            kill "$anvil_pid" 2>/dev/null || true
            rm -f "$pid_file"
            return 1
        fi
        
        if ! is_process_running "$anvil_pid"; then
            print_error "$name anvil process died"
            print_debug "Check log: $log_file"
            rm -f "$pid_file"
            return 1
        fi
        
        sleep 1
        elapsed=$((elapsed + 1))
    done
    
    # Verify anvil is responding
    if ! curl -s -X POST -H "Content-Type: application/json" \
         -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
         "http://localhost:$port" > /dev/null; then
        print_error "$name anvil not responding to RPC calls"
        kill "$anvil_pid" 2>/dev/null || true
        rm -f "$pid_file"
        return 1
    fi
    
    print_success "$name anvil ready on http://localhost:$port"
    return 0
}

# Start all configured anvil chains
start_anvil_chains() {
    # Get configured networks
    local -a network_ids
    IFS=' ' read -ra network_ids <<< "$(config_get_network_ids)"
    
    if [ ${#network_ids[@]} -eq 0 ]; then
        print_error "No networks configured"
        return 1
    fi
    
    init_deployment_env
    
    print_header "Starting Anvil Chains"
    
    local success=true
    for chain_id in "${network_ids[@]}"; do
        local rpc_url=$(config_get_network "$chain_id" "rpc_url")
        local port
        
        # Extract port from RPC URL
        if [[ "$rpc_url" =~ :([0-9]+) ]]; then
            port="${BASH_REMATCH[1]}"
        else
            print_error "Cannot extract port from RPC URL: $rpc_url"
            success=false
            continue
        fi
        
        local name=$(config_get_network "$chain_id" "name" || echo "chain-$chain_id")
        local block_time=$(config_get_network "$chain_id" "block_time" || echo "2")
        local pid_file="${ANVIL_PIDS_DIR}/anvil_${chain_id}.pid"
        local log_file="${ANVIL_LOGS_DIR}/anvil_${chain_id}.log"
        
        if ! start_anvil_instance "$name" "$port" "$chain_id" \
                                 "$block_time" "$pid_file" "$log_file"; then
            success=false
        fi
    done
    
    if [ "$success" = true ]; then
        print_success "All configured anvil chains started successfully"
        return 0
    else
        print_error "Some anvil chains failed to start"
        return 1
    fi
    
    return 0
}

# Stop anvil instance
stop_anvil_instance() {
    local name="$1"
    local pid_file="$2"
    
    if [ ! -f "$pid_file" ]; then
        print_debug "No PID file for $name anvil"
        return 0
    fi
    
    local pid=$(cat "$pid_file")
    if is_process_running "$pid"; then
        print_info "Stopping $name anvil (PID: $pid)..."
        kill "$pid"
        
        # Wait for graceful shutdown
        local timeout=10
        local elapsed=0
        
        while is_process_running "$pid" && [ $elapsed -lt $timeout ]; do
            sleep 1
            elapsed=$((elapsed + 1))
        done
        
        # Force kill if still running
        if is_process_running "$pid"; then
            print_warning "Force killing $name anvil"
            kill -9 "$pid" 2>/dev/null || true
        fi
        
        print_success "$name anvil stopped"
    else
        print_debug "$name anvil not running"
    fi
    
    rm -f "$pid_file"
}

# Kill processes running on a specific port
kill_processes_on_port() {
    local port="$1"
    
    # Use lsof to find processes using the port
    local pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
    
    if [ -n "$pids" ]; then
        print_info "Found processes on port $port: $pids"
        
        # Try graceful shutdown first
        for pid in $pids; do
            if is_process_running "$pid"; then
                print_debug "Sending TERM signal to process $pid on port $port"
                kill "$pid" 2>/dev/null || true
            fi
        done
        
        # Wait a moment for graceful shutdown
        sleep 2
        
        # Force kill any remaining processes
        local remaining_pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
        if [ -n "$remaining_pids" ]; then
            print_warning "Force killing processes on port $port: $remaining_pids"
            for pid in $remaining_pids; do
                if is_process_running "$pid"; then
                    kill -9 "$pid" 2>/dev/null || true
                fi
            done
        fi
        
        print_success "Cleared port $port"
    else
        print_debug "No processes found on port $port"
    fi
}

# Stop all configured anvil chains
stop_anvil_chains() {
    print_header "Stopping Anvil Chains"
    
    # Get configured networks
    local -a network_ids
    IFS=' ' read -ra network_ids <<< "$(config_get_network_ids)"
    
    # First try to stop using PID files
    for chain_id in "${network_ids[@]}"; do
        local name=$(config_get_network "$chain_id" "name" || echo "chain-$chain_id")
        local pid_file="${ANVIL_PIDS_DIR}/anvil_${chain_id}.pid"
        stop_anvil_instance "$name" "$pid_file"
    done
    
    # Kill any remaining anvil processes using ps and port detection
    print_info "Checking for remaining anvil processes..."
    
    # Kill processes on specific ports (8545, 8546) - common anvil ports
    for port in 8545 8546; do
        kill_processes_on_port "$port"
    done
    
    # Also check configured ports
    for chain_id in "${network_ids[@]}"; do
        local rpc_url=$(config_get_network "$chain_id" "rpc_url")
        if [[ "$rpc_url" =~ :([0-9]+) ]]; then
            local port="${BASH_REMATCH[1]}"
            kill_processes_on_port "$port"
        fi
    done
    
    # Final cleanup: kill any anvil processes by name
    local anvil_pids=$(pgrep -f "anvil" 2>/dev/null || true)
    if [ -n "$anvil_pids" ]; then
        print_info "Killing remaining anvil processes: $anvil_pids"
        echo "$anvil_pids" | xargs kill -9 2>/dev/null || true
    fi
    
    print_success "All anvil processes stopped"
}

# Check anvil chains status
check_anvil_status() {
    print_header "Anvil Status"
    
    # Get configured networks
    local -a network_ids
    IFS=' ' read -ra network_ids <<< "$(config_get_network_ids)"
    
    if [ ${#network_ids[@]} -eq 0 ]; then
        print_warning "No networks configured"
        return 1
    fi
    
    local all_running=true
    for chain_id in "${network_ids[@]}"; do
        local name=$(config_get_network "$chain_id" "name" || echo "chain-$chain_id")
        local rpc_url=$(config_get_network "$chain_id" "rpc_url")
        local status="stopped"
        
        # Extract port from RPC URL
        if [[ "$rpc_url" =~ :([0-9]+) ]]; then
            local port="${BASH_REMATCH[1]}"
            local pid_file="${ANVIL_PIDS_DIR}/anvil_${chain_id}.pid"
            
            if [ -f "$pid_file" ]; then
                local pid=$(cat "$pid_file")
                if is_process_running "$pid" && nc -z localhost "$port" 2>/dev/null; then
                    status="running"
                fi
            elif nc -z localhost "$port" 2>/dev/null; then
                # Port is in use but no PID file - external anvil
                status="running (external)"
            fi
        fi
        
        if [[ "$status" == "running"* ]]; then
            echo -e "[${GREEN}✓${NC}] $name (chain $chain_id, port $port) - ${GREEN}$status${NC}"
        else
            echo -e "[${RED}✗${NC}] $name (chain $chain_id, port $port) - ${RED}$status${NC}"
        fi
        
        if [ "$status" != "running" ]; then
            all_running=false
        fi
    done
    
    if [ "$all_running" = true ]; then
        return 0
    else
        return 1
    fi
}

# Deploy Permit2 contract
deploy_permit2() {
    local chain_name="$1"
    local rpc_url="$2"
    local private_key="${3:-$(config_get_account solver private_key)}"
    
    print_info "Deploying Permit2 on $chain_name..."
    
    # Check if already deployed
    local existing_code=$(cast_code "$PERMIT2_ADDRESS" "$rpc_url" 2>/dev/null || echo "0x")
    if [ "$existing_code" != "0x" ]; then
        print_success "Permit2 already deployed at $PERMIT2_ADDRESS"
        return 0
    fi
    
    # Get Permit2 bytecode from mainnet
    print_debug "Fetching Permit2 bytecode from mainnet..."
    local permit2_code
    permit2_code=$(cast_code "$PERMIT2_ADDRESS" "https://ethereum-rpc.publicnode.com" 2>/dev/null || echo "")
    
    if [ -z "$permit2_code" ] || [ "$permit2_code" = "0x" ]; then
        print_error "Failed to fetch Permit2 bytecode from mainnet"
        return 1
    fi
    
    # Deploy using anvil_setCode
    if cast_rpc "anvil_setCode" "$rpc_url" "$PERMIT2_ADDRESS" "$permit2_code" > /dev/null; then
        print_success "Permit2 deployed at $PERMIT2_ADDRESS"
        return 0
    else
        print_error "Failed to deploy Permit2"
        return 1
    fi
}

# Create ERC20 token contract with EIP-3009 support
create_token_contract() {
    local token_name="$1"
    local token_symbol="$2"
    local contract_file="/tmp/${token_name}.sol"
    
    # Create token contract with EIP-3009 support for gasless transfers
    cat > "$contract_file" << EOF
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract $token_name {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(bytes32 => bool) public authorizationState;
    
    string public name = "$token_name";
    string public symbol = "$token_symbol";
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
            "\\x19\\x01",
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
    
    echo "$contract_file"
}

# Deploy token contracts
deploy_tokens() {
    local origin_rpc="$1"
    local dest_rpc="$2"
    local private_key="${3:-$(config_get_account solver private_key)}"
    
    print_info "Deploying token contracts..."
    
    # Create token contracts
    local tokena_file=$(create_token_contract "TokenA" "TOKA")
    local tokenb_file=$(create_token_contract "TokenB" "TOKB")
    
    # Deploy TokenA on both chains (same address)
    print_debug "Deploying TokenA..."
    local tokena_origin=$(forge_deploy "$tokena_file" "TokenA" "$origin_rpc" "$private_key")
    if [ -z "$tokena_origin" ]; then
        return 1
    fi
    
    local tokena_dest=$(forge_deploy "$tokena_file" "TokenA" "$dest_rpc" "$private_key")
    if [ "$tokena_origin" != "$tokena_dest" ]; then
        print_error "TokenA address mismatch between chains"
        return 1
    fi
    
    DEPLOYED_CONTRACTS[origin_tokena]="$tokena_origin"
    DEPLOYED_CONTRACTS[dest_tokena]="$tokena_dest"
    print_debug "Stored TokenA in DEPLOYED_CONTRACTS: origin=${DEPLOYED_CONTRACTS[origin_tokena]}, dest=${DEPLOYED_CONTRACTS[dest_tokena]}"
    
    # Deploy TokenB on both chains (same address)
    print_debug "Deploying TokenB..."
    local tokenb_origin=$(forge_deploy "$tokenb_file" "TokenB" "$origin_rpc" "$private_key")
    if [ -z "$tokenb_origin" ]; then
        return 1
    fi
    
    local tokenb_dest=$(forge_deploy "$tokenb_file" "TokenB" "$dest_rpc" "$private_key")
    if [ "$tokenb_origin" != "$tokenb_dest" ]; then
        print_error "TokenB address mismatch between chains"
        return 1
    fi
    
    DEPLOYED_CONTRACTS[origin_tokenb]="$tokenb_origin"
    DEPLOYED_CONTRACTS[dest_tokenb]="$tokenb_dest"
    print_debug "Stored TokenB in DEPLOYED_CONTRACTS: origin=${DEPLOYED_CONTRACTS[origin_tokenb]}, dest=${DEPLOYED_CONTRACTS[dest_tokenb]}"
    
    # Cleanup temp files
    rm -f "$tokena_file" "$tokenb_file"
    
    print_success "Token contracts deployed"
    print_info "TokenA: $tokena_origin"
    print_info "TokenB: $tokenb_origin"
    
    return 0
}

# Deploy OIF contracts
deploy_oif_contracts() {
    local origin_rpc="$1"
    local dest_rpc="$2"
    local private_key="${3:-$(config_get_account solver private_key)}"
    local contracts_dir="${4:-./oif-contracts}"
    
    print_info "Deploying OIF contracts..."
    
    if [ ! -d "$contracts_dir" ]; then
        print_error "OIF contracts directory not found: $contracts_dir"
        return 1
    fi
    
    local original_dir=$(pwd)
    cd "$contracts_dir" || return 1
    
    # Build contracts
    if ! forge_build; then
        print_error "Failed to build OIF contracts"
        return 1
    fi
    
    # Deploy InputSettlerEscrow
    print_debug "Deploying InputSettlerEscrow..."
    local input_settler=$(forge_deploy "src/input/escrow/InputSettlerEscrow.sol" \
                         "InputSettlerEscrow" "$origin_rpc" "$private_key")
    if [ -z "$input_settler" ]; then
        return 1
    fi
    DEPLOYED_CONTRACTS[input_settler_escrow]="$input_settler"
    
    # Deploy on dest chain for deterministic address
    forge_deploy "src/input/escrow/InputSettlerEscrow.sol" \
                "InputSettlerEscrow" "$dest_rpc" "$private_key" > /dev/null
    
    # Deploy OutputSettler
    print_debug "Deploying OutputSettler..."
    local output_settler=$(forge_deploy "src/output/simple/OutputSettlerSimple.sol" \
                          "OutputSettlerSimple" "$origin_rpc" "$private_key")
    if [ -z "$output_settler" ]; then
        return 1
    fi
    DEPLOYED_CONTRACTS[output_settler]="$output_settler"
    
    # Deploy on dest chain for deterministic address
    forge_deploy "src/output/simple/OutputSettlerSimple.sol" \
                "OutputSettlerSimple" "$dest_rpc" "$private_key" > /dev/null
    
    # Deploy Oracle
    print_debug "Deploying AlwaysYesOracle..."
    local oracle=$(forge_deploy "test/mocks/AlwaysYesOracle.sol" \
                  "AlwaysYesOracle" "$origin_rpc" "$private_key")
    if [ -z "$oracle" ]; then
        return 1
    fi
    DEPLOYED_CONTRACTS[oracle]="$oracle"
    
    # Deploy on dest chain for deterministic address
    forge_deploy "test/mocks/AlwaysYesOracle.sol" \
                "AlwaysYesOracle" "$dest_rpc" "$private_key" > /dev/null
    
    # Deploy TheCompact
    print_debug "Deploying TheCompact..."
    local the_compact=$(forge_deploy "lib/the-compact/src/TheCompact.sol" \
                       "TheCompact" "$origin_rpc" "$private_key")
    if [ -z "$the_compact" ]; then
        return 1
    fi
    DEPLOYED_CONTRACTS[the_compact]="$the_compact"
    
    # Deploy on dest chain for deterministic address
    forge_deploy "lib/the-compact/src/TheCompact.sol" \
                "TheCompact" "$dest_rpc" "$private_key" > /dev/null
    
    # Deploy AlwaysOKAllocator
    print_debug "Deploying AlwaysOKAllocator..."
    local allocator=$(forge_deploy "lib/the-compact/src/test/AlwaysOKAllocator.sol" \
                     "AlwaysOKAllocator" "$origin_rpc" "$private_key")
    if [ -z "$allocator" ]; then
        return 1
    fi
    DEPLOYED_CONTRACTS[allocator]="$allocator"
    
    # Deploy on dest chain for deterministic address
    forge_deploy "lib/the-compact/src/test/AlwaysOKAllocator.sol" \
                "AlwaysOKAllocator" "$dest_rpc" "$private_key" > /dev/null
    
    # Register allocator with TheCompact
    print_debug "Registering allocator..."
    print_debug "TheCompact address: $the_compact"
    print_debug "Allocator address: $allocator"
    
    # Register on origin chain
    print_debug "Registering allocator on origin chain..."
    if ! cast_send "$the_compact" "__registerAllocator(address,bytes)" \
                  "$origin_rpc" "$private_key" "$allocator" "0x" > /dev/null 2>&1; then
        print_error "Failed to register allocator on origin chain"
        return 1
    fi
    
    # Register on destination chain
    print_debug "Registering allocator on destination chain..."
    if ! cast_send "$the_compact" "__registerAllocator(address,bytes)" \
                  "$dest_rpc" "$private_key" "$allocator" "0x" > /dev/null 2>&1; then
        print_error "Failed to register allocator on destination chain"
        return 1
    fi
    
    print_success "Allocator registered successfully"
    
    # Deploy InputSettlerCompact
    print_info "Deploying InputSettlerCompact..."
    local input_settler_compact_origin=$(forge_deploy "src/input/compact/InputSettlerCompact.sol" "InputSettlerCompact" "$origin_rpc" "$private_key" "$the_compact")
    if [ -z "$input_settler_compact_origin" ]; then
        print_warning "Failed to deploy InputSettlerCompact on origin"
        DEPLOYED_CONTRACTS[input_settler_compact]=""
    else
        print_info "Deploying InputSettlerCompact..."
        local input_settler_compact_dest=$(forge_deploy "src/input/compact/InputSettlerCompact.sol" "InputSettlerCompact" "$dest_rpc" "$private_key" "$the_compact")
        if [ "$input_settler_compact_origin" != "$input_settler_compact_dest" ]; then
            print_warning "InputSettlerCompact address mismatch between chains"
            DEPLOYED_CONTRACTS[input_settler_compact]=""
        else
            DEPLOYED_CONTRACTS[input_settler_compact]="$input_settler_compact_origin"
        fi
    fi
    
    cd "$original_dir" > /dev/null
    
    print_success "OIF contracts deployed"
    return 0
}

# Setup tokens (mint and approve)
setup_tokens() {
    local origin_rpc="$1"
    local dest_rpc="$2"
    local user_addr="${3:-$(config_get_account user address)}"
    local user_key="${4:-$(config_get_account user private_key)}"
    local solver_addr="${5:-$(config_get_account solver address)}"
    local solver_key="${6:-$(config_get_account solver private_key)}"
    
    print_info "Setting up token balances and approvals..."
    print_debug "setup_tokens: DEPLOYED_CONTRACTS keys: ${!DEPLOYED_CONTRACTS[@]}"
    print_debug "setup_tokens: DEPLOYED_CONTRACTS values: ${DEPLOYED_CONTRACTS[@]}"
    
    # Validate required parameters are provided
    if [ -z "$user_addr" ]; then
        print_error "User address is required"
        return 1
    fi
    if [ -z "$user_key" ]; then
        print_error "User private key is required"
        return 1
    fi
    if [ -z "$solver_addr" ]; then
        print_error "Solver address is required"
        return 1
    fi
    if [ -z "$solver_key" ]; then
        print_error "Solver private key is required"
        return 1
    fi
    
    local tokena="${DEPLOYED_CONTRACTS[origin_tokena]}"
    local tokenb="${DEPLOYED_CONTRACTS[origin_tokenb]}"
    local amount="100000000000000000000"  # 100 tokens
    
    print_debug "TokenA address: $tokena"
    print_debug "TokenB address: $tokenb"
    
    if [ -z "$tokena" ] || [ -z "$tokenb" ]; then
        print_error "Token addresses not found in DEPLOYED_CONTRACTS"
        print_debug "DEPLOYED_CONTRACTS keys: ${!DEPLOYED_CONTRACTS[@]}"
        print_debug "DEPLOYED_CONTRACTS values: ${DEPLOYED_CONTRACTS[@]}"
        return 1
    fi
    
    # Mint tokens to user on origin
    print_debug "Minting tokens to user on origin..."
    cast_send "$tokena" "mint(address,uint256)" \
              "$origin_rpc" "$solver_key" "$user_addr" "$amount" > /dev/null
    cast_send "$tokenb" "mint(address,uint256)" \
              "$origin_rpc" "$solver_key" "$user_addr" "$amount" > /dev/null
    
    # Mint tokens to solver on destination
    print_debug "Minting tokens to solver on destination..."
    cast_send "$tokena" "mint(address,uint256)" \
              "$dest_rpc" "$solver_key" "$solver_addr" "$amount" > /dev/null
    cast_send "$tokenb" "mint(address,uint256)" \
              "$dest_rpc" "$solver_key" "$solver_addr" "$amount" > /dev/null
    
    # Approve Permit2 for user tokens
    print_debug "Approving Permit2 for user tokens..."
    cast_send "$tokena" "approve(address,uint256)" \
              "$origin_rpc" "$user_key" "$PERMIT2_ADDRESS" \
              "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" > /dev/null
    cast_send "$tokenb" "approve(address,uint256)" \
              "$origin_rpc" "$user_key" "$PERMIT2_ADDRESS" \
              "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" > /dev/null
    
    # Setup compact resource locks if TheCompact is deployed
    local the_compact="${DEPLOYED_CONTRACTS[the_compact]}"
    local allocator="${DEPLOYED_CONTRACTS[allocator]}"
    
    if [ -n "$the_compact" ] && [ -n "$allocator" ]; then
        print_debug "Setting up compact resource locks..."
        print_debug "TheCompact address: $the_compact"
        print_debug "Allocator address: $allocator"
        
        # Verify the allocator is registered (but don't deposit)
        print_debug "Verifying allocator registration..."
        local is_registered=$(cast call "$the_compact" "allocators(address)" "$allocator" --rpc-url "$origin_rpc" 2>/dev/null || echo "0x0")
        print_debug "Allocator registration status: $is_registered"
        
        if [ "$is_registered" = "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
            print_warning "Allocator not registered, attempting to register..."
            if ! cast_send "$the_compact" "__registerAllocator(address,bytes)" \
                          "$origin_rpc" "$solver_key" "$allocator" "0x"; then
                print_error "Failed to register allocator"
                return 1
            fi
            sleep 2  # Wait for registration to be mined
            print_success "Allocator registered successfully"
        else
            print_success "Allocator already registered"
        fi
        
        print_success "Compact setup completed (ready for intent creation)"
    else
        print_debug "Skipping compact setup (TheCompact or Allocator not deployed)"
    fi
    
    print_success "Token setup completed"
    return 0
}

# Full deployment workflow
deploy_full_environment() {
    local contracts_dir="${1:-./oif-contracts}"
    
    print_header "Full Environment Deployment"
    
    # Stop any existing chains
    stop_anvil_chains
    
    # Start anvil chains
    if ! start_anvil_chains; then
        return 1
    fi
    
    # Get configured networks
    local -a network_ids
    IFS=' ' read -ra network_ids <<< "$(config_get_network_ids)"
    
    # Deploy on all networks
    for chain_id in "${network_ids[@]}"; do
        local rpc_url=$(config_get_network "$chain_id" "rpc_url")
        local name=$(config_get_network "$chain_id" "name" || echo "chain-$chain_id")
        
        # Deploy Permit2
        if ! deploy_permit2 "$name" "$rpc_url"; then
            return 1
        fi
    done
    
    # For now, deploy tokens and contracts on first two networks (origin/dest pattern)
    if [ ${#network_ids[@]} -ge 2 ]; then
        local origin_id="${network_ids[0]}"
        local dest_id="${network_ids[1]}"
        local origin_rpc=$(config_get_network "$origin_id" "rpc_url")
        local dest_rpc=$(config_get_network "$dest_id" "rpc_url")
        
        # Deploy tokens
        if ! deploy_tokens "$origin_rpc" "$dest_rpc"; then
            return 1
        fi
        
        # Deploy OIF contracts
        if ! deploy_oif_contracts "$origin_rpc" "$dest_rpc" "" "$contracts_dir"; then
            return 1
        fi
        
        # Setup token balances - get account info from config
        local user_addr=$(config_get_account "user" "address")
        local user_key=$(config_get_account "user" "private_key")
        local solver_addr=$(config_get_account "solver" "address")
        local solver_key=$(config_get_account "solver" "private_key")
        
        if ! setup_tokens "$origin_rpc" "$dest_rpc" "$user_addr" "$user_key" "$solver_addr" "$solver_key"; then
            return 1
        fi
    else
        print_warning "Need at least 2 networks configured for full deployment"
    fi
    
    print_success "Full environment deployed successfully!"
    
    # Export contract addresses
    export_contract_addresses
    
    return 0
}

# Export deployed contract addresses to environment
export_contract_addresses() {
    for contract in "${!DEPLOYED_CONTRACTS[@]}"; do
        local env_var="$(echo $contract | tr '[:lower:]' '[:upper:]')_ADDRESS"
        export "$env_var"="${DEPLOYED_CONTRACTS[$contract]}"
    done
    
    export PERMIT2_ADDRESS="$PERMIT2_ADDRESS"
}

# Get deployed contract address
get_contract_address() {
    local contract_name="$1"
    echo "${DEPLOYED_CONTRACTS[$contract_name]}"
}

# Show deployment summary
show_deployment_summary() {
    print_header "Deployment Summary"
    
    print_info "Networks:"
    
    # Get configured networks
    local -a network_ids
    IFS=' ' read -ra network_ids <<< "$(config_get_network_ids)"
    
    for chain_id in "${network_ids[@]}"; do
        local name=$(config_get_network "$chain_id" "name" || echo "chain-$chain_id")
        local rpc_url=$(config_get_network "$chain_id" "rpc_url")
        print_info "  $name: $rpc_url (chain $chain_id)"
    done
    
    print_info "Contracts:"
    print_info "  TokenA: ${DEPLOYED_CONTRACTS[origin_tokena]}"
    print_info "  TokenB: ${DEPLOYED_CONTRACTS[origin_tokenb]}"
    print_info "  Permit2: $PERMIT2_ADDRESS"
    print_info "  InputSettlerEscrow: ${DEPLOYED_CONTRACTS[input_settler_escrow]}"
    print_info "  InputSettlerCompact: ${DEPLOYED_CONTRACTS[input_settler_compact]}"
    print_info "  OutputSettler: ${DEPLOYED_CONTRACTS[output_settler]}"
    print_info "  Oracle: ${DEPLOYED_CONTRACTS[oracle]}"
    print_info "  TheCompact: ${DEPLOYED_CONTRACTS[the_compact]}"
    print_info "  Allocator: ${DEPLOYED_CONTRACTS[allocator]}"
    
    print_separator
}

# Cleanup deployment
cleanup_deployment() {
    print_header "Cleaning up deployment"
    
    stop_anvil_chains
    
    # Clean up log and PID files
    rm -rf "$ANVIL_PIDS_DIR" "$ANVIL_LOGS_DIR"
    
    # Clear contract addresses
    for contract in "${!DEPLOYED_CONTRACTS[@]}"; do
        DEPLOYED_CONTRACTS[$contract]=""
    done
    
    print_success "Deployment cleanup completed"
}

# Export functions
export -f init_deployment_env
export -f check_anvil
export -f start_anvil_chains
export -f stop_anvil_chains
export -f check_anvil_status
export -f deploy_tokens
export -f deploy_oif_contracts
export -f setup_tokens
export -f deploy_full_environment
export -f get_contract_address
export -f show_deployment_summary
export -f cleanup_deployment

# Deploy and setup all contracts (based on setup_local_anvil.sh)
deploy_and_setup_contracts() {
    local ORIGIN_PORT=$1
    local DEST_PORT=$2
    local ORIGIN_CHAIN_ID=$3
    local DEST_CHAIN_ID=$4
    
    # Account configuration - use Anvil default accounts
    # These are deterministic accounts from anvil's known mnemonic
    local PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil account 0
    local SOLVER_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"                        # anvil account 0
    local USER_ADDRESS="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"                           # anvil account 1
    local USER_PRIVATE_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # anvil account 1
    local RECIPIENT_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"                         # anvil account 2
    
    # Initialize directories
    ensure_dir "$ANVIL_PIDS_DIR"
    ensure_dir "$ANVIL_LOGS_DIR"
    
    # Deploy Permit2 on both chains
    deploy_permit2 "origin" "http://localhost:$ORIGIN_PORT"
    deploy_permit2 "destination" "http://localhost:$DEST_PORT"
    
    # Deploy tokens
    local origin_rpc="http://localhost:$ORIGIN_PORT"
    local dest_rpc="http://localhost:$DEST_PORT"
    
    if ! deploy_tokens "$origin_rpc" "$dest_rpc" "$PRIVATE_KEY"; then
        return 1
    fi
    
    # Deploy OIF contracts (requires oif-contracts repo)
    # Use specific commit from common.sh for consistency
    
    if [ ! -d "oif-contracts" ]; then
        print_info "Cloning oif-contracts..."
        git clone https://github.com/openintentsframework/oif-contracts.git > /dev/null 2>&1
        cd oif-contracts
        git checkout "$OIF_CONTRACTS_COMMIT" > /dev/null 2>&1
        cd ..
    else
        print_info "Updating oif-contracts to commit $OIF_CONTRACTS_COMMIT..."
        cd oif-contracts
        git fetch origin > /dev/null 2>&1
        git checkout "$OIF_CONTRACTS_COMMIT" > /dev/null 2>&1
        cd ..
    fi
    
    if ! deploy_oif_contracts "$origin_rpc" "$dest_rpc" "$PRIVATE_KEY" "oif-contracts"; then
        return 1
    fi
    
    # Setup token balances and approvals
    if ! setup_tokens "$origin_rpc" "$dest_rpc" "$USER_ADDRESS" "$USER_PRIVATE_KEY" "$SOLVER_ADDRESS" "$PRIVATE_KEY"; then
        return 1
    fi
    
    # Contract addresses are already stored in DEPLOYED_CONTRACTS array
    # No need to echo them
    
    return 0
}

# Generate demo config from deployment
generate_demo_config_from_deployment() {
    local CONFIG_DIR="${SCRIPT_DIR}/config"
    mkdir -p "$CONFIG_DIR/demo"
    
    # Account configuration - use Anvil default accounts
    # These are deterministic accounts from anvil's known mnemonic
    local PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil account 0
    local SOLVER_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"                        # anvil account 0
    local USER_ADDRESS="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"                           # anvil account 1
    local USER_PRIVATE_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # anvil account 1
    local RECIPIENT_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"                         # anvil account 2
    
    # Use the deployed contract addresses
    local TOKENA="${DEPLOYED_CONTRACTS[origin_tokena]}"
    local TOKENB="${DEPLOYED_CONTRACTS[origin_tokenb]}"
    local INPUT_SETTLER="${DEPLOYED_CONTRACTS[input_settler_escrow]}"
    local INPUT_SETTLER_COMPACT="${DEPLOYED_CONTRACTS[input_settler_compact]}"
    local OUTPUT_SETTLER="${DEPLOYED_CONTRACTS[output_settler]}"
    local THE_COMPACT="${DEPLOYED_CONTRACTS[the_compact]}"
    local ALLOCATOR="${DEPLOYED_CONTRACTS[allocator]}"
    
    # Create main config file - EXACTLY matching original
    cat > "$CONFIG_DIR/demo.toml" <<EOF
# OIF Solver Configuration - Main File

include = [
    "demo/networks.toml",
    "demo/api.toml",
    "demo/cli.toml",
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
private_key = "$PRIVATE_KEY"

# ============================================================================
# DELIVERY
# ============================================================================
[delivery]
min_confirmations = 1

[delivery.implementations.evm_alloy]
network_ids = [31337, 31338]

# ============================================================================
# DISCOVERY
# ============================================================================
[discovery]

[discovery.implementations.onchain_eip7683]
network_ids = [31337, 31338]
polling_interval_secs = 0  # Use WebSocket subscriptions instead of polling

[discovery.implementations.offchain_eip7683]
api_host = "127.0.0.1"
api_port = 8081
network_ids = [31337]

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
# PRICING
# ============================================================================
[pricing]
primary = "mock"

[pricing.implementations.mock]
# Uses default ETH/USD price of 4615.16

# ============================================================================
# SETTLEMENT
# ============================================================================
[settlement]

[settlement.domain]
chain_id = 1
EOF
    
    # Append settlement address dynamically
    echo "address = \"$INPUT_SETTLER\"" >> "$CONFIG_DIR/demo.toml"
    
    # Continue with rest of config
    cat >> "$CONFIG_DIR/demo.toml" <<EOF

[settlement.implementations.direct]
order = "eip7683"
network_ids = [31337, 31338]
dispute_period_seconds = 1
# Oracle selection strategy when multiple oracles are available (First, RoundRobin, Random)
oracle_selection_strategy = "First"

# Oracle configuration with multiple oracle support
[settlement.implementations.direct.oracles]
# Input oracles (on origin chains)
input = { 31337 = ["0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"], 31338 = ["0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"] }
# Output oracles (on destination chains)
output = { 31337 = ["0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"], 31338 = ["0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"] }

# Valid routes: from origin chain -> to destination chains
[settlement.implementations.direct.routes]
31337 = [31338]  # Can go from origin to destination
31338 = [31337]  # Can go from destination to origin
EOF
    
    # Create networks.toml with deployed addresses
    cat > "$CONFIG_DIR/demo/networks.toml" <<EOF
# Network Configuration
# Defines all supported blockchain networks and their tokens

[networks.31337]
input_settler_address = "$INPUT_SETTLER"
input_settler_compact_address = "$INPUT_SETTLER_COMPACT"
the_compact_address = "$THE_COMPACT"
allocator_address = "$ALLOCATOR"
output_settler_address = "$OUTPUT_SETTLER"

# RPC endpoints with both HTTP and WebSocket URLs for each network
[[networks.31337.rpc_urls]]
http = "http://localhost:8545"
ws = "ws://localhost:8545"

[[networks.31337.tokens]]
address = "$TOKENA"
symbol = "TOKA"
decimals = 18

[[networks.31337.tokens]]
address = "$TOKENB"
symbol = "TOKB"
decimals = 18

[networks.31338]
input_settler_address = "$INPUT_SETTLER"
input_settler_compact_address = "$INPUT_SETTLER_COMPACT"
the_compact_address = "$THE_COMPACT"
allocator_address = "$ALLOCATOR"
output_settler_address = "$OUTPUT_SETTLER"

# RPC endpoints with both HTTP and WebSocket URLs for each network
[[networks.31338.rpc_urls]]
http = "http://localhost:8546"
ws = "ws://localhost:8546"

[[networks.31338.tokens]]
address = "$TOKENA"
symbol = "TOKA"
decimals = 18

[[networks.31338.tokens]]
address = "$TOKENB"
symbol = "TOKB"
decimals = 18
EOF
    
    # Create api.toml
    cat > "$CONFIG_DIR/demo/api.toml" <<'EOF'
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
    
    # Create cli.toml
    cat > "$CONFIG_DIR/demo/cli.toml" <<EOF
# CLI Configuration for Demo Scripts
# These settings are used by the demo CLI tools

[accounts]
user_address = "$USER_ADDRESS"
user_private_key = "$USER_PRIVATE_KEY"
solver_address = "$SOLVER_ADDRESS"
recipient_address = "$RECIPIENT_ADDR"
EOF
    
    # Create gas.toml
    cat > "$CONFIG_DIR/demo/gas.toml" <<'EOF'
[gas]

[gas.flows.compact_resource_lock]
# Gas units captured by scripts/e2e/estimate_gas_compact.sh on local anvil
open = 0
fill = 76068
claim = 121995

[gas.flows.permit2_escrow]
# Gas units captured by scripts/e2e/estimate_gas_permit2_escrow.sh on local anvil
open = 143116
fill = 76068 
claim = 59953
EOF
    
    print_success "Configuration files generated:"
    print_info "  - $CONFIG_DIR/demo.toml"
    print_info "  - $CONFIG_DIR/demo/networks.toml"
    print_info "  - $CONFIG_DIR/demo/api.toml"
    print_info "  - $CONFIG_DIR/demo/cli.toml"
    print_info "  - $CONFIG_DIR/demo/gas.toml"
}

# Environment management functions for CLI
env_up() {
    print_header "Setting up OIF Demo Environment"
    
    # Define default ports and chain IDs
    local ORIGIN_PORT=8545
    local DEST_PORT=8546
    local ORIGIN_CHAIN_ID=31337
    local DEST_CHAIN_ID=31338
    
    # Ensure directories exist
    ensure_dir "$ANVIL_PIDS_DIR"
    ensure_dir "$ANVIL_LOGS_DIR"
    
    # Stop any existing chains first
    print_info "Cleaning up any existing Anvil chains..."
    pkill -9 anvil 2>/dev/null || true
    sleep 2
    
    # Start Anvil chains with fixed configuration
    print_info "Starting Anvil chains..."
    
    # Start origin chain
    anvil --chain-id $ORIGIN_CHAIN_ID --port $ORIGIN_PORT --block-time 2 > "${ANVIL_LOGS_DIR}/anvil_origin.log" 2>&1 &
    echo $! > "${ANVIL_PIDS_DIR}/anvil_${ORIGIN_CHAIN_ID}.pid"
    
    # Start destination chain  
    anvil --chain-id $DEST_CHAIN_ID --port $DEST_PORT --block-time 2 > "${ANVIL_LOGS_DIR}/anvil_destination.log" 2>&1 &
    echo $! > "${ANVIL_PIDS_DIR}/anvil_${DEST_CHAIN_ID}.pid"
    
    # Wait for chains to be ready
    sleep 3
    
    if ! nc -z localhost $ORIGIN_PORT 2>/dev/null || ! nc -z localhost $DEST_PORT 2>/dev/null; then
        print_error "Failed to start Anvil chains"
        return 1
    fi
    
    print_success "Both Anvil chains started"
    
    # Deploy contracts and setup environment
    print_info "Deploying contracts..."
    
    # Deploy and setup all contracts
    if ! deploy_and_setup_contracts $ORIGIN_PORT $DEST_PORT $ORIGIN_CHAIN_ID $DEST_CHAIN_ID; then
        print_error "Contract deployment failed"
        return 1
    fi
    
    # Generate configuration files with deployed addresses
    print_info "Generating configuration files..."
    generate_demo_config_from_deployment
    
    print_success "Environment setup complete!"
    print_info "Configuration saved to: ${CONFIG_DIR}/demo.toml"
    print_info "Run 'cargo run --bin solver -- --config config/demo.toml' to start the solver"
    
    return 0
}

env_down() {
    # Try to stop configured chains first if config is available
    if config_is_loaded 2>/dev/null; then
        stop_anvil_chains
    else
        # Fallback: kill processes on default ports without configuration
        print_header "Stopping Anvil Chains"
        print_info "No configuration loaded, using default ports..."
        
        # Kill processes on default anvil ports
        for port in 8545 8546 31337 31338; do
            kill_processes_on_port "$port"
        done
        
        # Kill any remaining anvil processes
        local anvil_pids=$(pgrep -f "anvil" 2>/dev/null || true)
        if [ -n "$anvil_pids" ]; then
            print_info "Killing remaining anvil processes: $anvil_pids"
            echo "$anvil_pids" | xargs kill -9 2>/dev/null || true
        fi
        
        print_success "All anvil processes stopped"
    fi
}

env_status() {
    print_header "Anvil Status"
    
    # Check fixed chain IDs/ports
    local origin_status="stopped"
    local dest_status="stopped"
    
    # Check origin chain (31337 on port 8545)
    if [ -f "${ANVIL_PIDS_DIR}/anvil_31337.pid" ]; then
        local origin_pid=$(cat "${ANVIL_PIDS_DIR}/anvil_31337.pid")
        if is_process_running "$origin_pid" && nc -z localhost 8545 2>/dev/null; then
            origin_status="running"
        fi
    elif nc -z localhost 8545 2>/dev/null; then
        origin_status="running (external)"
    fi
    
    # Check destination chain (31338 on port 8546)
    if [ -f "${ANVIL_PIDS_DIR}/anvil_31338.pid" ]; then
        local dest_pid=$(cat "${ANVIL_PIDS_DIR}/anvil_31338.pid")
        if is_process_running "$dest_pid" && nc -z localhost 8546 2>/dev/null; then
            dest_status="running"
        fi
    elif nc -z localhost 8546 2>/dev/null; then
        dest_status="running (external)"
    fi
    
    # Display status
    if [[ "$origin_status" == "running"* ]]; then
        echo -e "[${GREEN}✓${NC}] Origin (chain 31337, port 8545) - ${GREEN}$origin_status${NC}"
    else
        echo -e "[${RED}✗${NC}] Origin (chain 31337, port 8545) - ${RED}$origin_status${NC}"
    fi
    
    if [[ "$dest_status" == "running"* ]]; then
        echo -e "[${GREEN}✓${NC}] Destination (chain 31338, port 8546) - ${GREEN}$dest_status${NC}"
    else
        echo -e "[${RED}✗${NC}] Destination (chain 31338, port 8546) - ${RED}$dest_status${NC}"
    fi
    
    # Return success if both are running
    if [[ "$origin_status" == "running"* ]] && [[ "$dest_status" == "running"* ]]; then
        return 0
    else
        return 1
    fi
}

env_reset() {
    print_info "Resetting environment..."
    
    # Stop all chains using the enhanced env_down
    env_down
    
    # Clean up files
    rm -rf "${ANVIL_PIDS_DIR}" "${ANVIL_LOGS_DIR}"
    rm -rf "${SCRIPT_DIR}/data"
    rm -rf "${OUTPUT_DIR}"
    
    # Additional cleanup: remove any generated config files
    rm -f "${CONFIG_DIR}/demo.toml"
    
    print_success "Environment reset complete"
}

# Export environment management functions
export -f env_up
export -f env_down
export -f env_status
export -f env_reset
export -f kill_processes_on_port
export -f deploy_and_setup_contracts
export -f generate_demo_config_from_deployment