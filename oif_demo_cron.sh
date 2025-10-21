#!/bin/bash
# Ultra-simple OIF Demo Cron Job Script
# Executes the 4 specified commands every X minutes
# Usage: ./oif_demo_cron.sh [interval_minutes]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default interval
DEFAULT_INTERVAL=5  # minutes
INTERVAL_MINUTES=${1:-$DEFAULT_INTERVAL}

# Validate interval
if ! [[ "$INTERVAL_MINUTES" =~ ^[0-9]+$ ]] || [ "$INTERVAL_MINUTES" -lt 1 ]; then
    echo -e "${RED}❌ Invalid interval: $INTERVAL_MINUTES. Must be a positive integer.${NC}"
    exit 1
fi

# Function to log with timestamp (console only)
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message"
}

# Function to execute command and wait for completion
execute_command() {
    local step="$1"
    local command="$2"

    log "INFO" "${BLUE}Step $step: Executing command...${NC}"
    echo "  → $command"

    # Execute command and wait for it to complete
    if $command; then
        log "INFO" "${GREEN}✅ Step $step completed successfully${NC}"
        return 0
    else
        log "ERROR" "${RED}❌ Step $step failed${NC}"
        return 1
    fi
}

# Function to execute the complete workflow
execute_workflow() {
    local cycle_num="$1"

    log "INFO" "${YELLOW}━━━ Starting Cycle $cycle_num ━━━${NC}"

    # Execute the 4 commands in sequence, waiting for each to complete

    # Step 1: Build intent
    if ! execute_command "1" "cargo run --bin solver-demo -- intent build --from-chain 11155420 --to-chain 84532 --from-token USDC --to-token USDC --amount 0.3 --settlement escrow --auth permit2"; then
        log "ERROR" "Workflow cycle $cycle_num failed at step 1"
        return 1
    fi

    # Step 2: Get quote (wait for step 1 to complete)
    if ! execute_command "2" "cargo run --bin solver-demo -- quote get .oif-demo/requests/get_quote.req.json"; then
        log "ERROR" "Workflow cycle $cycle_num failed at step 2"
        return 1
    fi

    # Step 3: Sign quote (wait for step 2 to complete)
    if ! execute_command "3" "cargo run --bin solver-demo -- quote sign .oif-demo/requests/get_quote.res.json"; then
        log "ERROR" "Workflow cycle $cycle_num failed at step 3"
        return 1
    fi

    # Step 4: Submit intent (wait for step 3 to complete)
    if ! execute_command "4" "cargo run --bin solver-demo -- intent submit .oif-demo/requests/post_order.req.json"; then
        log "ERROR" "Workflow cycle $cycle_num failed at step 4"
        return 1
    fi

    log "INFO" "${GREEN}🎉 Workflow cycle $cycle_num completed successfully${NC}"
    return 0
}

# Function to cleanup on exit
cleanup() {
    log "INFO" "${YELLOW}🛑 Cron job stopping...${NC}"
    log "INFO" "${BLUE}📊 Total cycles completed: $cycle_count${NC}"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Main execution
main() {
    echo -e "${BLUE}🔄 OIF Demo Cron Job Starting${NC}"
    echo "   Interval: $INTERVAL_MINUTES minutes"
    echo "   Commands will execute sequentially, waiting for each to complete"
    echo ""

    # Basic validation
    if [ ! -f "Cargo.toml" ]; then
        echo -e "${RED}❌ Not in OIF solvers workspace directory${NC}"
        exit 1
    fi

    # Initialize counter
    cycle_count=0

    log "INFO" "${GREEN}🚀 Cron job started${NC}"

    # Main loop
    while true; do
        cycle_count=$((cycle_count + 1))

        if execute_workflow "$cycle_count"; then
            log "INFO" "${GREEN}✅ Cycle $cycle_count successful${NC}"
        else
            log "ERROR" "${RED}❌ Cycle $cycle_count failed. Continuing...${NC}"
        fi

        local next_time=$(date -d "+$INTERVAL_MINUTES minutes" '+%Y-%m-%d %H:%M:%S')
        log "INFO" "${BLUE}⏰ Next execution at: $next_time${NC}"
        log "INFO" "${BLUE}💤 Sleeping for $INTERVAL_MINUTES minutes...${NC}"
        echo ""

        # Sleep for the specified interval
        sleep $((INTERVAL_MINUTES * 60))
    done
}

# Show usage if --help is passed
if [[ "${1:-}" == "--help" ]]; then
    cat << EOF
Ultra-Simple OIF Demo Cron Job Script

Usage: $0 [interval_minutes]

Arguments:
  interval_minutes    Minutes between executions (default: $DEFAULT_INTERVAL)

Examples:
  $0        # Run every 5 minutes
  $0 10     # Run every 10 minutes
  $0 30     # Run every 30 minutes

Commands executed sequentially (each waits for previous to complete):
  1. cargo run --bin solver-demo -- intent build --from-chain 31337 --to-chain 31338 --from-token TOKA --to-token TOKB --amount 0.9 --settlement escrow --auth permit2
  2. cargo run --bin solver-demo -- quote get .oif-demo/requests/get_quote.req.json
  3. cargo run --bin solver-demo -- quote sign .oif-demo/requests/get_quote.res.json
  4. cargo run --bin solver-demo -- intent submit .oif-demo/requests/post_order.req.json

To stop: Press Ctrl+C
EOF
    exit 0
fi

# Execute main function
main
