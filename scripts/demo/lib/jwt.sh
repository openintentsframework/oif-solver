#!/usr/bin/env bash

# JWT Authentication Module for OIF Demo CLI
# Provides JWT token registration and validation for API authentication

# Register a new client via API endpoint
jwt_register() {
    local client="${1:-}"
    local scopes="${2:-}"
    local expiry="${3:-}"
    
    if [ -z "$client" ]; then
        print_error "Client identifier is required"
        echo ""
        echo "Usage: oif-demo jwt register <client> [scopes] [expiry_hours]"
        echo ""
        echo "Scopes (comma-separated):"
        echo "  read-orders    - Read order information"
        echo "  create-orders  - Create new orders"
        echo "  create-quotes  - Create quotes"
        echo "  read-quotes    - Read quotes"
        echo "  admin-all      - All permissions"
        echo ""
        echo "Examples:"
        echo "  oif-demo jwt register my-app"
        echo "  oif-demo jwt register my-app read-orders,create-orders"
        echo "  oif-demo jwt register admin-app admin-all 48"
        exit 1
    fi
    
    print_header "Client Registration"
    print_info "Registering client: $client"
    
    # Build request JSON
    local request_json="{\"client_id\": \"$client\""
    
    if [ -n "$scopes" ]; then
        # Convert comma-separated scopes to JSON array
        local scope_array=""
        IFS=',' read -ra SCOPE_PARTS <<< "$scopes"
        for scope in "${SCOPE_PARTS[@]}"; do
            scope=$(echo "$scope" | xargs) # trim whitespace
            if [ -n "$scope_array" ]; then
                scope_array="${scope_array},"
            fi
            scope_array="${scope_array}\"${scope}\""
        done
        request_json="${request_json}, \"scopes\": [$scope_array]"
        print_info "Requested scopes: $scopes"
    fi
    
    if [ -n "$expiry" ]; then
        request_json="${request_json}, \"expiry_hours\": $expiry"
        print_info "Custom expiry: $expiry hours"
    fi
    
    request_json="${request_json}}"
    
    # Call the register endpoint
    local api_url="${API_URL:-http://localhost:3000}"
    
    print_step "Calling registration endpoint..."
    local response=$(curl -s -X POST "${api_url}/api/auth/register" \
        -H "Content-Type: application/json" \
        -d "$request_json" 2>/dev/null || true)
    
    if [ -z "$response" ]; then
        print_error "Failed to connect to API server at $api_url"
        print_info "Make sure the solver service is running with authentication enabled"
        exit 1
    fi
    
    # Check if response contains an error
    local error=$(echo "$response" | jq -r '.error' 2>/dev/null)
    if [ -n "$error" ] && [ "$error" != "null" ]; then
        print_error "Registration failed: $error"
        exit 1
    fi
    
    # Extract token from response
    local token=$(echo "$response" | jq -r '.access_token' 2>/dev/null)
    if [ -z "$token" ] || [ "$token" = "null" ]; then
        print_error "No token in response"
        echo "$response" | jq . 2>/dev/null || echo "$response"
        exit 1
    fi
    
    # Display registration details
    print_success "Client registered successfully!"
    echo ""
    echo "Registration Details:"
    echo "$response" | jq . 2>/dev/null || echo "$response"
    echo ""
    
    print_info "Use this token in API requests:"
    echo "curl -H \"Authorization: Bearer $token\" ${api_url}/api/orders/123"
}

# Validate JWT token (basic validation)
jwt_validate() {
    local token="${1:-}"
    local secret=""
    
    # Check for --secret flag
    if [ "$1" = "--secret" ]; then
        secret="${2:-}"
        token="${3:-}"
        
        if [ -z "$secret" ] || [ -z "$token" ]; then
            print_error "Both secret and token are required when using --secret"
            echo ""
            echo "Usage: oif-demo jwt validate [--secret <secret>] <token>"
            echo ""
            echo "Examples:"
            echo "  oif-demo jwt validate eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            echo "  oif-demo jwt validate --secret 'my-secret-key' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            exit 1
        fi
    fi
    
    if [ -z "$token" ]; then
        print_error "Token is required"
        echo ""
        echo "Usage: oif-demo jwt validate [--secret <secret>] <token>"
        echo ""
        echo "Examples:"
        echo "  oif-demo jwt validate eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        echo "  oif-demo jwt validate --secret 'my-secret-key' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        exit 1
    fi
    
    print_header "JWT Token Validation"
    
    # Split the JWT into parts
    IFS='.' read -ra PARTS <<< "$token"
    
    if [ ${#PARTS[@]} -ne 3 ]; then
        print_error "Invalid JWT format (expected 3 parts separated by dots)"
        exit 1
    fi
    
    # Decode header (handle URL-safe base64 and add padding if needed)
    local header_b64=$(echo "${PARTS[0]}" | tr '_' '/' | tr '-' '+')
    # Add padding if needed
    local pad=$((4 - ${#header_b64} % 4))
    if [ $pad -ne 4 ]; then
        header_b64="${header_b64}$(printf '%.0s=' $(seq 1 $pad))"
    fi
    local header_json=$(echo "$header_b64" | base64 -d 2>/dev/null)
    if [ $? -ne 0 ]; then
        print_error "Failed to decode JWT header"
        exit 1
    fi
    
    # Decode payload (handle URL-safe base64 and add padding if needed)
    local payload_b64=$(echo "${PARTS[1]}" | tr '_' '/' | tr '-' '+')
    # Add padding if needed
    local pad=$((4 - ${#payload_b64} % 4))
    if [ $pad -ne 4 ]; then
        payload_b64="${payload_b64}$(printf '%.0s=' $(seq 1 $pad))"
    fi
    local payload_json=$(echo "$payload_b64" | base64 -d 2>/dev/null)
    if [ $? -ne 0 ]; then
        print_error "Failed to decode JWT payload"
        exit 1
    fi
    
    print_success "Token structure is valid"
    echo ""
    
    # Parse and display header
    print_info "Header:"
    echo "$header_json" | jq . 2>/dev/null || echo "$header_json"
    echo ""
    
    # Parse and display payload
    print_info "Payload:"
    echo "$payload_json" | jq . 2>/dev/null || echo "$payload_json"
    echo ""
    
    # Check expiration
    local exp=$(echo "$payload_json" | jq -r '.exp' 2>/dev/null)
    if [ -n "$exp" ] && [ "$exp" != "null" ]; then
        local now=$(date +%s)
        if [ "$exp" -lt "$now" ]; then
            print_error "Token has expired"
            local exp_date=$(date -r "$exp" 2>/dev/null || date -d "@$exp" 2>/dev/null || echo "Unknown")
            print_info "Expired at: $exp_date"
        else
            print_success "Token is not expired"
            local exp_date=$(date -r "$exp" 2>/dev/null || date -d "@$exp" 2>/dev/null || echo "Unknown")
            print_info "Expires at: $exp_date"
            
            local time_left=$((exp - now))
            local hours_left=$((time_left / 3600))
            local minutes_left=$(((time_left % 3600) / 60))
            print_info "Time remaining: ${hours_left}h ${minutes_left}m"
        fi
    fi
    
    # If secret was provided, verify the signature
    if [ -n "$secret" ]; then
        echo ""
        print_info "Verifying signature with provided secret..."
        
        # Get the signature part and convert from base64url to base64
        local provided_signature="${PARTS[2]}"
        
        # Convert base64url signature to standard base64 for comparison
        local sig_b64=$(echo -n "$provided_signature" | tr '_-' '/+')
        # Add padding if needed
        case $(( ${#sig_b64} % 4 )) in
            2) sig_b64="${sig_b64}==" ;;
            3) sig_b64="${sig_b64}=" ;;
        esac
        
        # Create the signing input (header.payload)
        local signing_input="${PARTS[0]}.${PARTS[1]}"
        
        # Calculate HMAC-SHA256 signature and encode to base64
        local calculated_sig_b64=$(echo -n "$signing_input" | \
            openssl dgst -sha256 -hmac "$secret" -binary | \
            base64)
        
        # Convert calculated signature to base64url for display
        local calculated_signature=$(echo -n "$calculated_sig_b64" | tr '/+' '_-' | sed 's/=*$//')
        
        if [ "$sig_b64" = "$calculated_sig_b64" ]; then
            print_success "Signature verification PASSED! Token is valid and authentic."
        else
            print_error "Signature verification FAILED! Token may be forged or the secret is incorrect."
            print_info "Provided signature:   $provided_signature"
            print_info "Calculated signature: $calculated_signature"
        fi
    else
        print_warning "Note: Signature not verified (use --secret to verify)"
        print_info "Example: oif-demo jwt validate --secret 'your-secret' $token"
    fi
}

# Test JWT authentication flow
jwt_test() {
    local test_type="${1:-basic}"
    
    print_header "JWT Authentication Test"
    
    # Load config if not already loaded
    if ! config_is_loaded; then
        if [ -f "${CONFIG_DIR}/demo.toml" ]; then
            config_load "${CONFIG_DIR}/demo.toml"
        else
            print_error "No configuration found"
            print_info "Run 'oif-demo env up' to set up environment"
            exit 1
        fi
    fi
    
    case "$test_type" in
        basic)
            print_step "1. Registering test client with read-orders scope"
            local client="test-client-$$"
            # Register client via API
            local api_url="${API_URL:-http://localhost:3000}"
            local response=$(curl -s -X POST "${api_url}/api/auth/register" \
                -H "Content-Type: application/json" \
                -d "{\"client_id\": \"$client\", \"scopes\": [\"read-orders\"]}" 2>/dev/null || true)
            
            if [ -z "$response" ]; then
                print_error "Failed to connect to API server"
                exit 1
            fi
            
            local token=$(echo "$response" | jq -r '.access_token' 2>/dev/null)
            if [ -z "$token" ] || [ "$token" = "null" ]; then
                print_error "Failed to register client"
                echo "$response" | jq . 2>/dev/null || echo "$response"
                exit 1
            fi
            
            print_success "Client registered successfully"
            
            print_step "2. Validating generated token"
            jwt_validate "$token" > /dev/null 2>&1 && \
                print_success "Token validation passed" || \
                print_error "Token validation failed"
            
            print_step "3. Testing authenticated API call"
            
            # Try to get an order (this will fail if no orders exist, but will test auth)
            local response=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $token" \
                "${api_url}/api/orders/test-order-123" 2>/dev/null || true)
            
            local http_code=$(echo "$response" | tail -1)
            local body=$(echo "$response" | sed '$d')
            
            if [ "$http_code" = "401" ]; then
                print_error "Authentication failed - token was rejected"
                exit 1
            elif [ "$http_code" = "403" ]; then
                print_error "Authorization failed - insufficient permissions"
                exit 1
            elif [ "$http_code" = "404" ]; then
                print_success "Authentication successful (order not found - expected)"
            elif [ "$http_code" = "400" ]; then
                # 400 can occur for invalid order ID format, but auth still worked
                print_success "Authentication successful (bad request - likely invalid order ID format)"
            elif [ "$http_code" = "200" ]; then
                print_success "Authentication successful - order retrieved"
            elif [ "$http_code" = "000" ]; then
                print_warning "Could not connect to API server at $api_url"
                print_info "Make sure the solver service is running"
            else
                print_warning "Unexpected response code: $http_code"
                [ -n "$body" ] && echo "$body"
            fi
            
            print_success "JWT authentication test completed"
            ;;
            
        full)
            print_step "Testing all authentication scopes"
            
            local scopes=("read-orders" "create-orders" "create-quotes" "read-quotes" "admin-all")
            local api_url="${API_URL:-http://localhost:3000}"
            
            for scope in "${scopes[@]}"; do
                print_info "Testing scope: $scope"
                
                local client="test-${scope}-$$"
                
                # Register client
                local response=$(curl -s -X POST "${api_url}/api/auth/register" \
                    -H "Content-Type: application/json" \
                    -d "{\"client_id\": \"$client\", \"scopes\": [\"$scope\"]}" 2>/dev/null || true)
                
                if [ -n "$response" ]; then
                    local token=$(echo "$response" | jq -r '.access_token' 2>/dev/null)
                    
                    if [ -n "$token" ] && [ "$token" != "null" ]; then
                        # Validate token
                        jwt_validate "$token" > /dev/null 2>&1 && \
                            print_success "  ✓ $scope token valid" || \
                            print_error "  ✗ $scope token invalid"
                    else
                        print_error "  ✗ Failed to register $scope client"
                    fi
                else
                    print_error "  ✗ Could not connect to API"
                fi
            done
            ;;
            
        *)
            print_error "Unknown test type: $test_type"
            print_info "Usage: oif-demo jwt test [basic|full]"
            exit 1
            ;;
    esac
}

# Token management functions
# Store JWT token for future use
jwt_store_token() {
    local token="${1:-}"
    local client_id="${2:-default}"
    
    if [ -z "$token" ]; then
        print_error "Token is required"
        return 1
    fi
    
    local token_dir="${OUTPUT_DIR:-./demo-output}/.tokens"
    mkdir -p "$token_dir"
    
    local token_file="$token_dir/${client_id}.jwt"
    echo "$token" > "$token_file"
    chmod 600 "$token_file"
    
    return 0
}

# Retrieve stored JWT token
jwt_get_token() {
    local client_id="${1:-default}"
    
    local token_dir="${OUTPUT_DIR:-./demo-output}/.tokens"
    local token_file="$token_dir/${client_id}.jwt"
    
    if [ -f "$token_file" ]; then
        cat "$token_file"
        return 0
    else
        return 1
    fi
}

# Get or create JWT token for API calls
jwt_ensure_token() {
    local client_id="${1:-oif-demo-client}"
    local scopes="${2:-read-orders,create-orders,create-quotes,read-quotes}"
    
    # Check if auth is enabled
    local auth_enabled=$(config_get "api.auth" "enabled" 2>/dev/null)
    if [ "$auth_enabled" != "true" ]; then
        return 0
    fi
    
    # Try to get stored token
    local token=$(jwt_get_token "$client_id")
    
    if [ -n "$token" ]; then
        # Validate token is not expired
        local payload_b64=$(echo "$token" | cut -d'.' -f2)
        # Add padding if needed
        local pad=$((4 - ${#payload_b64} % 4))
        if [ $pad -ne 4 ]; then
            payload_b64="${payload_b64}$(printf '%.0s=' $(seq 1 $pad))"
        fi
        local payload_json=$(echo "$payload_b64" | tr '_-' '/+' | base64 -d 2>/dev/null)
        local exp=$(echo "$payload_json" | jq -r '.exp' 2>/dev/null)
        local now=$(date +%s)
        
        if [ -n "$exp" ] && [ "$exp" != "null" ] && [ "$exp" -gt "$now" ]; then
            echo "$token"
            return 0
        fi
    fi
    
    # Generate new token (with one retry)
    local api_url="${API_URL:-http://localhost:3000}"
    local attempts=0
    local max_attempts=2
    
    while [ $attempts -lt $max_attempts ]; do
        # Build scopes array properly
        local scopes_json="[]"
        if [ -n "$scopes" ]; then
            scopes_json="[\"$(echo "$scopes" | sed 's/,/","/g')\"]"
        fi
        
        local response=$(curl -s -X POST "${api_url}/api/auth/register" \
            -H "Content-Type: application/json" \
            -d "{\"client_id\": \"$client_id\", \"scopes\": $scopes_json}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token=$(echo "$response" | jq -r '.access_token' 2>/dev/null)
            if [ -n "$token" ] && [ "$token" != "null" ]; then
                # Success! Store the token and return it
                jwt_store_token "$token" "$client_id"
                echo "$token"
                return 0
            fi
        fi
        
        attempts=$((attempts + 1))
        if [ $attempts -lt $max_attempts ]; then
            sleep 0.5  # Brief pause before retry
        fi
    done
    
    # All attempts failed
    return 1
}

# Export functions for use in main script
export -f jwt_register
export -f jwt_validate
export -f jwt_test
export -f jwt_store_token
export -f jwt_get_token
export -f jwt_ensure_token