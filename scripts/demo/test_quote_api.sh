#!/bin/bash

# Test script for the OIF Solver Quote API
# This script demonstrates how to call the POST /quote endpoint

set -e

API_URL="http://127.0.0.1:3000"
QUOTE_ENDPOINT="$API_URL/api/quote"

echo "Testing OIF Solver Quote API at $QUOTE_ENDPOINT"
echo "================================================="

# Test 1: Basic quote request
echo "Test 1: Basic quote request (ETH -> USDC)"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "availableInputs": [
      {
        "input": {
          "asset": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
          "amount": "1000000000000000000"
        },
        "priority": 80
      }
    ],
    "requestedMinOutputs": [
      {
        "asset": "0xA0b86a33E6441986C3F2EB618C2a25C3dB00B7c4",
        "amount": "1500000000"
      }
    ],
    "preference": "price"
  }' | jq '.'

echo -e "\n\n"

# Test 2: Speed-optimized quote
echo "Test 2: Speed-optimized quote request"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "availableInputs": [
      {
        "input": {
          "asset": "0xA0b86a33E6441986C3F2EB618C2a25C3dB00B7c4",
          "amount": "2000000000"
        }
      }
    ],
    "requestedMinOutputs": [
      {
        "asset": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "amount": "500000000000000000"
      }
    ],
    "preference": "speed",
    "minValidUntil": 600
  }' | jq '.'

echo -e "\n\n"

# Test 3: Multiple inputs and outputs
echo "Test 3: Multiple inputs and outputs"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "availableInputs": [
      {
        "input": {
          "asset": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
          "amount": "1000000000000000000"
        },
        "priority": 90
      },
      {
        "input": {
          "asset": "0xA0b86a33E6441986C3F2EB618C2a25C3dB00B7c4",
          "amount": "3000000000"
        },
        "priority": 70
      }
    ],
    "requestedMinOutputs": [
      {
        "asset": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "amount": "2000000000000000000000"
      }
    ],
    "preference": "input-priority"
  }' | jq '.'

echo -e "\n\n"

# Test 4: Invalid request (should return error)
echo "Test 4: Invalid request (empty inputs - should return 400)"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "availableInputs": [],
    "requestedMinOutputs": [
      {
        "asset": "0xA0b86a33E6441986C3F2EB618C2a25C3dB00B7c4",
        "amount": "1000000000"
      }
    ]
  }' | jq '.'

echo -e "\n\nQuote API testing complete!"
echo "Note: Make sure the solver service is running with API enabled before running this script."
echo "Start the solver with: cargo run --bin solver -- --config config/demo.toml" 