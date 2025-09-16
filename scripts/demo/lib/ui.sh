#!/usr/bin/env bash
#
# ==============================================================================
# UI Module - User Interface and Output Formatting
# ==============================================================================
#
# This module provides all user interface elements including colored output,
# formatted tables, progress indicators, and interactive prompts.
#
# Key Features:
# - Color-coded output with status indicators
# - Formatted table display for balances and data
# - Progress bars and spinners for long operations
# - Interactive confirmation prompts
# - Debug and verbose output control
# - Banner and header formatting
#
# Output Types:
# - Success (✓): Green checkmark for successful operations
# - Error (✗): Red X for failures
# - Warning (⚠): Yellow warning for important notices
# - Info (ℹ): Blue info for general information
# - Debug: Gray output for debugging (when DEBUG=1)
#
# Formatting Features:
# - Balance tables with proper alignment
# - Token amount formatting with units
# - Address shortening for display
# - Section headers and dividers
#
# Dependencies:
# - Terminal with ANSI color support
# - tput: For terminal capability queries
#
# Usage:
#   print_success "Operation completed"
#   print_table_header "Title"
#   confirm_action "Continue?"
#
# ==============================================================================

# -----------------------------------------------------------------------------
# Color Definitions
# -----------------------------------------------------------------------------
# Color definitions
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r CYAN='\033[0;36m'
declare -r MAGENTA='\033[0;35m'
declare -r GRAY='\033[0;90m'
declare -r BOLD='\033[1m'
declare -r NC='\033[0m'  # No Color

# Status indicators
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_debug() {
    if [ "${DEBUG:-0}" = "1" ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1" >&2
    fi
}

# Banner
print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║          OIF Demo CLI - Open Intents Framework           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Progress indicators
show_spinner() {
    local pid=$1
    local message="${2:-Processing}"
    local delay=0.1
    local spinstr='|/-\'
    
    echo -n "$message "
    while is_process_running "$pid"; do
        local temp=${spinstr#?}
        printf "[%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
    echo ""
}

# Formatted tables
print_separator() {
    echo "────────────────────────────────────────────────────────────"
}

print_header() {
    local title="$1"
    echo ""
    echo -e "${BOLD}$title${NC}"
    print_separator
}

print_step() {
    local step="$1"
    echo ""
    echo -e "${BLUE}▶ $step${NC}"
    echo "────────────────────────────────────────────────────────────"
}

# Balance table formatting
print_balance_table() {
    local title="${1:-BALANCES}"
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    printf "║ %-76s ║\n" "$title"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
}

print_balance_row() {
    local label="$1"
    local value="$2"
    local unit="${3:-}"
    
    if [ -n "$unit" ]; then
        # With unit: label (40) + value (25) + unit (8) + spaces (3) = 76
        printf "║ %-40s %25s %-8s  ║\n" "$label:" "$value" "$unit"
    else
        # Without unit: label (40) + value (35) = 75, plus 1 space = 76
        printf "║ %-40s %35s ║\n" "$label:" "$value"
    fi
}

print_balance_section() {
    local section="$1"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    printf "║ %-76s ║\n" "$section"
    echo "╠──────────────────────────────────────────────────────────────────────────────╣"
}

print_balance_end() {
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
}

# Intent summary formatting
print_intent_summary() {
    local intent_json="$1"
    
    print_header "Intent Summary"
    
    # Extract key fields
    local origin_chain=$(echo "$intent_json" | jq -r '.originChainId // "N/A"')
    local dest_chain=$(echo "$intent_json" | jq -r '.destinationChainId // "N/A"')
    local user=$(echo "$intent_json" | jq -r '.user // "N/A"')
    local token_in=$(echo "$intent_json" | jq -r '.tokenIn // "N/A"')
    local token_out=$(echo "$intent_json" | jq -r '.tokenOut // "N/A"')
    local amount_in=$(echo "$intent_json" | jq -r '.amountIn // "N/A"')
    local amount_out=$(echo "$intent_json" | jq -r '.amountOut // "N/A"')
    
    echo "Origin Chain:      $origin_chain"
    echo "Destination Chain: $dest_chain"
    echo "User:              $user"
    echo "Token In:          $token_in"
    echo "Amount In:         $amount_in"
    echo "Token Out:         $token_out"
    echo "Amount Out:        $amount_out"
    
    print_separator
}

# Quote summary formatting
print_quote_summary() {
    local quote_json="$1"
    
    print_header "Quote Summary"
    
    # Extract key fields
    local quote_id=$(echo "$quote_json" | jq -r '.quoteId // "N/A"')
    local price=$(echo "$quote_json" | jq -r '.price // "N/A"')
    local fee=$(echo "$quote_json" | jq -r '.fee // "N/A"')
    local valid_until=$(echo "$quote_json" | jq -r '.validUntil // "N/A"')
    
    echo "Quote ID:     $quote_id"
    echo "Price:        $price"
    echo "Fee:          $fee"
    echo "Valid Until:  $valid_until"
    
    print_separator
}

# Transaction summary
print_transaction_summary() {
    local tx_hash="$1"
    local chain_id="$2"
    local status="${3:-pending}"
    
    print_header "Transaction"
    
    echo "Hash:     $tx_hash"
    echo "Chain:    $chain_id"
    echo "Status:   $status"
    
    print_separator
}

# Interactive prompts
confirm_action() {
    local message="$1"
    local default="${2:-n}"
    
    local prompt
    if [ "$default" = "y" ]; then
        prompt="[Y/n]"
    else
        prompt="[y/N]"
    fi
    
    read -p "$(echo -e "${YELLOW}?${NC} ${message} ${prompt}: ")" -n 1 -r reply
    echo ""
    
    if [ -z "$reply" ]; then
        reply="$default"
    fi
    
    [[ "$reply" =~ ^[Yy]$ ]]
}

prompt_input() {
    local message="$1"
    local default="${2:-}"
    local variable_name="${3:-REPLY}"
    
    local prompt="$message"
    if [ -n "$default" ]; then
        prompt="$prompt [$default]"
    fi
    
    read -p "$(echo -e "${CYAN}>${NC} ${prompt}: ")" value
    
    if [ -z "$value" ] && [ -n "$default" ]; then
        value="$default"
    fi
    
    eval "$variable_name='$value'"
}

prompt_secret() {
    local message="$1"
    local variable_name="${2:-REPLY}"
    
    read -s -p "$(echo -e "${CYAN}>${NC} ${message}: ")" value
    echo ""
    
    eval "$variable_name='$value'"
}

# Selection menu
show_menu() {
    local title="$1"
    shift
    local options=("$@")
    
    print_header "$title"
    
    local i=1
    for option in "${options[@]}"; do
        echo "  $i) $option"
        ((i++))
    done
    
    echo ""
    prompt_input "Select option" "" "selection"
    
    if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#options[@]}" ]; then
        return $((selection - 1))
    else
        print_error "Invalid selection"
        return 255
    fi
}

# Progress bar
show_progress() {
    local current="$1"
    local total="$2"
    local width="${3:-50}"
    
    local percent=$((current * 100 / total))
    local filled=$((width * current / total))
    
    printf "\r["
    printf "%${filled}s" | tr ' ' '='
    printf "%$((width - filled))s" | tr ' ' '-'
    printf "] %3d%%" "$percent"
    
    if [ "$current" -eq "$total" ]; then
        echo ""
    fi
}

# Status display
print_status() {
    local component="$1"
    local status="$2"
    
    case "$status" in
        running|active|up)
            echo -e "[$component] ${GREEN}● Running${NC}"
            ;;
        stopped|inactive|down)
            echo -e "[$component] ${RED}● Stopped${NC}"
            ;;
        error|failed)
            echo -e "[$component] ${RED}✗ Error${NC}"
            ;;
        pending|starting)
            echo -e "[$component] ${YELLOW}◌ Pending${NC}"
            ;;
        *)
            echo -e "[$component] ${CYAN}? Unknown${NC}"
            ;;
    esac
}

# File display
print_file_content() {
    local file="$1"
    local title="${2:-File Content}"
    
    if [ -f "$file" ]; then
        print_header "$title"
        cat "$file"
        print_separator
    else
        print_error "File not found: $file"
    fi
}

# JSON pretty printing
print_json() {
    local json="$1"
    local title="${2:-JSON Output}"
    
    print_header "$title"
    echo "$json" | jq '.' 2>/dev/null || echo "$json"
    print_separator
}

# Export color variables
export RED GREEN YELLOW BLUE CYAN MAGENTA GRAY BOLD NC

# Export functions
export -f print_success
export -f print_error
export -f print_warning
export -f print_info
export -f print_debug
export -f print_step
export -f confirm_action
export -f prompt_input
export -f show_spinner