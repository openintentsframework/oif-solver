#!/usr/bin/env bash
#
# ==============================================================================
# API Module - HTTP Client with Retry Logic
# ==============================================================================
#
# This module provides a robust HTTP client implementation for making API calls
# with automatic retry logic, error handling, and response parsing.
#
# Features:
# - HTTP GET/POST/PUT/DELETE support
# - Automatic retry with exponential backoff
# - Response caching and validation
# - JSON parsing and validation
# - Custom headers and authentication support
# - Comprehensive error handling
#
# Dependencies:
# - curl: For HTTP requests
# - jq: For JSON parsing
#
# Usage:
#   source api.sh
#   api_get "https://api.example.com/data"
#   api_post "https://api.example.com/submit" "$json_payload"
#   
# Global State:
#   API_RESPONSE[] - Associative array storing last response details
#
# ==============================================================================

# -----------------------------------------------------------------------------
# Configuration Section
# -----------------------------------------------------------------------------
# Default configuration
DEFAULT_TIMEOUT=30
DEFAULT_MAX_RETRIES=3
DEFAULT_RETRY_DELAY=2
DEFAULT_USER_AGENT="OIF-Demo-CLI/1.0"

# -----------------------------------------------------------------------------
# Global State Management
# -----------------------------------------------------------------------------
# API response structure - stores the last API call's response details
declare -gA API_RESPONSE
API_RESPONSE[status_code]=""
API_RESPONSE[body]=""
API_RESPONSE[headers]=""
API_RESPONSE[error]=""

# -----------------------------------------------------------------------------
# Dependency Checking Functions
# -----------------------------------------------------------------------------
# Check if curl is available
check_curl() {
    if ! command -v curl &> /dev/null; then
        print_error "curl is required but not installed"
        print_info "Install curl: brew install curl (macOS) or apt-get install curl (Linux)"
        return 1
    fi
    return 0
}

# Check if jq is available
check_jq() {
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed"
        print_info "Install jq: brew install jq (macOS) or apt-get install jq (Linux)"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Validation Functions
# -----------------------------------------------------------------------------
# Validate URL format - ensures URL starts with http:// or https://
validate_url() {
    local url="$1"
    
    if [[ ! "$url" =~ ^https?:// ]]; then
        print_error "Invalid URL format: $url"
        return 1
    fi
    
    return 0
}

# Validate JSON payload
validate_json() {
    local json="$1"
    
    if ! echo "$json" | jq empty 2>/dev/null; then
        print_error "Invalid JSON format"
        print_debug "JSON: $json"
        return 1
    fi
    
    return 0
}

# -----------------------------------------------------------------------------
# Response Management Functions
# -----------------------------------------------------------------------------
# Clear API response - resets all response fields
clear_api_response() {
    API_RESPONSE[status_code]=""
    API_RESPONSE[body]=""
    API_RESPONSE[headers]=""
    API_RESPONSE[error]=""
}

# Set API response
set_api_response() {
    local status_code="$1"
    local body="$2"
    local headers="$3"
    local error="$4"
    
    API_RESPONSE[status_code]="$status_code"
    API_RESPONSE[body]="$body"
    API_RESPONSE[headers]="$headers"
    API_RESPONSE[error]="$error"
}

# Get API response field
get_api_response() {
    local field="$1"
    echo "${API_RESPONSE[$field]}"
}

# -----------------------------------------------------------------------------
# Core HTTP Request Functions
# -----------------------------------------------------------------------------
# Basic HTTP request with error handling
# Parameters:
#   $1 - HTTP method (GET, POST, PUT, DELETE)
#   $2 - URL
#   $3 - Request body (optional)
#   $4 - Timeout in seconds (optional)
#   $5 - Additional headers (optional)
http_request() {
    local method="$1"
    local url="$2"
    local data="${3:-}"
    local timeout="${4:-$DEFAULT_TIMEOUT}"
    local headers="${5:-}"
    
    clear_api_response
    
    if ! validate_url "$url"; then
        set_api_response "0" "" "" "Invalid URL"
        return 1
    fi
    
    print_debug "HTTP $method request to: $url"
    print_debug "Timeout: ${timeout}s"
    
    # Build curl command
    local curl_args=()
    curl_args+=("-X" "$method")
    curl_args+=("-s")  # Silent
    curl_args+=("-w" "\n%{http_code}\n%{header_json}")  # Write status code and headers
    curl_args+=("--connect-timeout" "$timeout")
    curl_args+=("--max-time" "$((timeout * 2))")
    curl_args+=("-H" "User-Agent: $DEFAULT_USER_AGENT")
    curl_args+=("-H" "Accept: application/json")
    
    # Add JWT authentication if available
    if [ -z "$headers" ] || ! echo "$headers" | grep -q "Authorization:"; then
        # Only add JWT if no Authorization header is already present
        if command -v jwt_ensure_token >/dev/null 2>&1; then
            local jwt_token=$(jwt_ensure_token 2>/dev/null)
            if [ -n "$jwt_token" ]; then
                curl_args+=("-H" "Authorization: Bearer $jwt_token")
            fi
        fi
    fi
    
    # Add custom headers
    if [ -n "$headers" ]; then
        while IFS= read -r header; do
            if [ -n "$header" ]; then
                curl_args+=("-H" "$header")
            fi
        done <<< "$headers"
    fi
    
    # Add data for POST/PUT requests
    if [ -n "$data" ]; then
        curl_args+=("-H" "Content-Type: application/json")
        curl_args+=("-d" "$data")
        print_debug "Request body size: ${#data} bytes"
    fi
    
    curl_args+=("$url")
    
    # Execute request
    local response
    response=$(curl "${curl_args[@]}" 2>&1)
    local curl_exit_code=$?
    
    if [ $curl_exit_code -ne 0 ]; then
        local error_msg="curl failed with exit code $curl_exit_code"
        print_error "$error_msg"
        print_debug "curl response: $response"
        set_api_response "0" "" "" "$error_msg"
        return 1
    fi
    
    # Parse response - split by the markers we added
    # The response format is: body\n<status_code>\n<headers_json>
    # But headers_json can span multiple lines, so we need to find the status code first
    
    local body=""
    local status_code=""
    local headers_json=""
    
    # Find the status code (should be a 3-digit number on its own line after the body)
    local in_body=true
    local found_status=false
    local line_count=0
    
    while IFS= read -r line; do
        ((line_count++))
    done <<< "$response"
    
    # Read response into array
    local response_lines=()
    while IFS= read -r line; do
        response_lines+=("$line")
    done <<< "$response"
    
    # Find status code by looking for a line with just 3 digits
    local status_line_idx=-1
    for ((i=0; i<${#response_lines[@]}; i++)); do
        if [[ "${response_lines[i]}" =~ ^[0-9]{3}$ ]]; then
            status_line_idx=$i
            status_code="${response_lines[i]}"
            break
        fi
    done
    
    if [ $status_line_idx -ge 0 ]; then
        # Everything before status code is body
        for ((i=0; i<status_line_idx; i++)); do
            if [ $i -eq 0 ]; then
                body="${response_lines[i]}"
            else
                body="${body}
${response_lines[i]}"
            fi
        done
        
        # Everything after status code is headers
        for ((i=status_line_idx+1; i<${#response_lines[@]}; i++)); do
            if [ $((i - status_line_idx)) -eq 1 ]; then
                headers_json="${response_lines[i]}"
            else
                headers_json="${headers_json}
${response_lines[i]}"
            fi
        done
    else
        # Fallback for unexpected response format
        body="$response"
        status_code="0"
        headers_json="{}"
    fi
    
    print_debug "HTTP Status: $status_code"
    print_debug "Response size: ${#body} bytes"
    
    set_api_response "$status_code" "$body" "$headers_json" ""
    
    # Check if response is successful (2xx)
    if [[ "$status_code" =~ ^2[0-9][0-9]$ ]]; then
        print_debug "Request successful"
        return 0
    else
        print_warning "HTTP request returned status $status_code"
        return 1
    fi
}

# HTTP request with retry logic
http_request_with_retry() {
    local method="$1"
    local url="$2"
    local data="${3:-}"
    local max_retries="${4:-$DEFAULT_MAX_RETRIES}"
    local retry_delay="${5:-$DEFAULT_RETRY_DELAY}"
    local timeout="${6:-$DEFAULT_TIMEOUT}"
    local headers="${7:-}"
    
    local attempt=1
    
    while [ $attempt -le $max_retries ]; do
        print_debug "Attempt $attempt/$max_retries"
        
        if http_request "$method" "$url" "$data" "$timeout" "$headers"; then
            print_debug "Request succeeded on attempt $attempt"
            return 0
        fi
        
        local status_code=$(get_api_response "status_code")
        local error=$(get_api_response "error")
        
        # Don't retry client errors (4xx) except 429 (rate limit)
        if [[ "$status_code" =~ ^4[0-9][0-9]$ ]] && [ "$status_code" != "429" ]; then
            print_error "Client error $status_code, not retrying"
            return 1
        fi
        
        if [ $attempt -lt $max_retries ]; then
            print_warning "Request failed (status: $status_code), retrying in ${retry_delay}s..."
            sleep "$retry_delay"
            
            # Exponential backoff
            retry_delay=$((retry_delay * 2))
        fi
        
        attempt=$((attempt + 1))
    done
    
    print_error "Request failed after $max_retries attempts"
    return 1
}

# GET request
api_get() {
    local url="$1"
    local headers="${2:-}"
    local timeout="${3:-$DEFAULT_TIMEOUT}"
    
    http_request "GET" "$url" "" "$timeout" "$headers"
}

# GET request with retry
api_get_retry() {
    local url="$1"
    local headers="${2:-}"
    local max_retries="${3:-$DEFAULT_MAX_RETRIES}"
    local retry_delay="${4:-$DEFAULT_RETRY_DELAY}"
    local timeout="${5:-$DEFAULT_TIMEOUT}"
    
    http_request_with_retry "GET" "$url" "" "$max_retries" "$retry_delay" "$timeout" "$headers"
}

# POST request
api_post() {
    local url="$1"
    local data="$2"
    local headers="${3:-}"
    local timeout="${4:-$DEFAULT_TIMEOUT}"
    
    if [ -n "$data" ] && ! validate_json "$data"; then
        return 1
    fi
    
    http_request "POST" "$url" "$data" "$timeout" "$headers"
}

# POST request with retry
api_post_retry() {
    local url="$1"
    local data="$2"
    local headers="${3:-}"
    local max_retries="${4:-$DEFAULT_MAX_RETRIES}"
    local retry_delay="${5:-$DEFAULT_RETRY_DELAY}"
    local timeout="${6:-$DEFAULT_TIMEOUT}"
    
    if [ -n "$data" ] && ! validate_json "$data"; then
        return 1
    fi
    
    http_request_with_retry "POST" "$url" "$data" "$max_retries" "$retry_delay" "$timeout" "$headers"
}

# PUT request
api_put() {
    local url="$1"
    local data="$2"
    local headers="${3:-}"
    local timeout="${4:-$DEFAULT_TIMEOUT}"
    
    if [ -n "$data" ] && ! validate_json "$data"; then
        return 1
    fi
    
    http_request "PUT" "$url" "$data" "$timeout" "$headers"
}

# DELETE request
api_delete() {
    local url="$1"
    local headers="${2:-}"
    local timeout="${3:-$DEFAULT_TIMEOUT}"
    
    http_request "DELETE" "$url" "" "$timeout" "$headers"
}

# Check API endpoint availability
check_api_availability() {
    local base_url="$1"
    local timeout="${2:-10}"
    
    local health_endpoints=("/" "/health" "/status" "/ping")
    
    for endpoint in "${health_endpoints[@]}"; do
        local url="${base_url}${endpoint}"
        print_debug "Checking endpoint: $url"
        
        if api_get "$url" "" "$timeout"; then
            local status_code=$(get_api_response "status_code")
            if [[ "$status_code" =~ ^[23][0-9][0-9]$ ]]; then
                print_success "API available at $base_url"
                return 0
            fi
        fi
    done
    
    print_error "API not available at $base_url"
    return 1
}

# Wait for API to become available
wait_for_api() {
    local base_url="$1"
    local timeout="${2:-60}"
    local check_interval="${3:-5}"
    
    print_info "Waiting for API at $base_url..."
    
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if check_api_availability "$base_url" 5; then
            return 0
        fi
        
        print_debug "API not ready, waiting ${check_interval}s..."
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
    done
    
    print_error "API did not become available within ${timeout}s"
    return 1
}

# Parse JSON response
parse_json_response() {
    local json_path="$1"
    local default_value="${2:-null}"
    
    local body=$(get_api_response "body")
    
    if [ -z "$body" ]; then
        echo "$default_value"
        return 1
    fi
    
    local result
    result=$(echo "$body" | jq -r "$json_path" 2>/dev/null || echo "$default_value")
    
    if [ "$result" = "null" ] && [ "$default_value" != "null" ]; then
        echo "$default_value"
        return 1
    fi
    
    echo "$result"
}

# Check if response contains error
has_api_error() {
    local body=$(get_api_response "body")
    local status_code=$(get_api_response "status_code")
    
    # Check HTTP status code
    if [[ ! "$status_code" =~ ^[23][0-9][0-9]$ ]]; then
        return 0  # Has error
    fi
    
    # Check for common error fields in JSON
    if echo "$body" | jq -e '.error // .errors // .message' &>/dev/null; then
        return 0  # Has error
    fi
    
    return 1  # No error
}

# Extract error message from response
get_api_error_message() {
    local body=$(get_api_response "body")
    local status_code=$(get_api_response "status_code")
    
    # Try common error message fields
    local error_msg
    error_msg=$(echo "$body" | jq -r '.error.message // .error // .errors[0].message // .errors[0] // .message // empty' 2>/dev/null)
    
    if [ -n "$error_msg" ] && [ "$error_msg" != "null" ]; then
        echo "$error_msg"
    else
        echo "HTTP $status_code error"
    fi
}

# Pretty print API response
print_api_response() {
    local body=$(get_api_response "body")
    local status_code=$(get_api_response "status_code")
    local headers_json=$(get_api_response "headers")
    
    print_header "API Response"
    echo "HTTP Status: $status_code"
    
    # Try to extract message from JSON response
    if echo "$body" | jq empty 2>/dev/null; then
        local message=$(echo "$body" | jq -r '.message // empty')
        if [ -n "$message" ] && [ "$message" != "null" ]; then
            echo "Message: $message"
        fi
        echo ""
        echo "Response Body:"
        echo "$body" | jq '.'
    else
        echo "Body: $body"
    fi
    
    # Show headers if in debug mode
    if [ "${DEBUG:-0}" = "1" ] && [ -n "$headers_json" ] && [ "$headers_json" != "{}" ]; then
        echo ""
        echo "Response Headers:"
        echo "$headers_json" | jq '.' 2>/dev/null || echo "$headers_json"
    fi
    
    print_separator
}

# Build URL with query parameters
build_url() {
    local base_url="$1"
    shift
    local params=("$@")
    
    local url="$base_url"
    local separator="?"
    
    for param in "${params[@]}"; do
        if [[ "$param" =~ ^[^=]+= ]]; then
            url="${url}${separator}${param}"
            separator="&"
        fi
    done
    
    echo "$url"
}

# URL encode value
url_encode() {
    local string="$1"
    local encoded=""
    
    for ((i=0; i<${#string}; i++)); do
        local char="${string:i:1}"
        case "$char" in
            [a-zA-Z0-9.~_-])
                encoded="$encoded$char"
                ;;
            *)
                encoded="$encoded$(printf '%%%02X' "'$char")"
                ;;
        esac
    done
    
    echo "$encoded"
}

# Export functions
export -f check_curl
export -f check_jq
export -f validate_url
export -f validate_json
export -f clear_api_response
export -f get_api_response
export -f http_request
export -f http_request_with_retry
export -f api_get
export -f api_get_retry
export -f api_post
export -f api_post_retry
export -f api_put
export -f api_delete
export -f check_api_availability
export -f wait_for_api
export -f parse_json_response
export -f has_api_error
export -f get_api_error_message
export -f print_api_response
export -f build_url
export -f url_encode