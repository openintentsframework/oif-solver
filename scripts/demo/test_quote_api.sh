#!/bin/bash

# Test script for the OIF Solver Quote API
# This script demonstrates how to call the POST /quote endpoint
# 
# Note: All addresses use ERC-7930 Interoperable Address format:
# - 0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234 = User address on Ethereum mainnet (chain ID 1)
# - 0x010000011401c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 = WETH on Ethereum mainnet
# - 0x010000011401a0b86a33e6441986c3f2eb618c2a25c3db00b7c4 = USDC on Ethereum mainnet  
# - 0x0100000114016b175474e89094c44da98b954eedeac495271d0f = DAI on Ethereum mainnet

set -e

API_URL="http://127.0.0.1:3000"
QUOTE_ENDPOINT="$API_URL/api/quote"

echo "Testing OIF Solver Quote API at $QUOTE_ENDPOINT"
echo "================================================="

# Test 1: Basic quote request (UII compliant with ERC-7930 addresses)
echo "Test 1: Basic quote request (ETH -> USDC)"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
    "availableInputs": [
      {
        "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "amount": "1000000000000000000"
      }
    ],
    "requestedOutputs": [
      {
        "receiver": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401a0b86a33e6441986c3f2eb618c2a25c3db00b7c4",
        "amount": "1500000000"
      }
    ],
    "preference": "price"
  }' | jq '.'

echo -e "\n\n"

# Test 2: Speed-optimized quote (UII compliant with ERC-7930 addresses)
echo "Test 2: Speed-optimized quote request"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
    "availableInputs": [
      {
        "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401a0b86a33e6441986c3f2eb618c2a25c3db00b7c4",
        "amount": "2000000000"
      }
    ],
    "requestedOutputs": [
      {
        "receiver": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "amount": "500000000000000000"
      }
    ],
    "preference": "speed",
    "minValidUntil": 600
  }' | jq '.'

echo -e "\n\n"

# Test 3: Multiple inputs and outputs with lock (UII compliant with ERC-7930 addresses)
echo "Test 3: Multiple inputs and outputs with lock"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
    "availableInputs": [
      {
        "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "amount": "1000000000000000000"
      },
      {
        "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401a0b86a33e6441986c3f2eb618c2a25c3db00b7c4",
        "amount": "3000000000",
        "lock": {
          "kind": "the-compact",
          "params": { "lockTag": "0x1234" }
        }
      }
    ],
    "requestedOutputs": [
      {
        "receiver": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x0100000114016b175474e89094c44da98b954eedeac495271d0f",
        "amount": "2000000000000000000000",
        "calldata": "0x"
      }
    ],
    "preference": "input-priority"
  }' | jq '.'

echo -e "\n\n"

# Test 4: Trust-minimization preference (UII compliant with ERC-7930 addresses)
echo "Test 4: Trust-minimization preference"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
    "availableInputs": [
      {
        "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "amount": "500000000000000000"
      }
    ],
    "requestedOutputs": [
      {
        "receiver": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401a0b86a33e6441986c3f2eb618c2a25c3db00b7c4",
        "amount": "750000000"
      }
    ],
    "preference": "trust-minimization"
  }' | jq '.'

echo -e "\n\n"

# Test 5: Invalid request (should return error)
echo "Test 5: Invalid request (empty inputs - should return 400)"
curl -X POST "$QUOTE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
    "availableInputs": [],
    "requestedOutputs": [
      {
        "receiver": "0x010000011401742d35cc6634c0532925a3b8d4ad62d93b3d1234",
        "asset": "0x010000011401a0b86a33e6441986c3f2eb618c2a25c3db00b7c4",
        "amount": "1000000000"
      }
    ]
  }' | jq '.'

echo -e "\n\nQuote API testing complete!"
echo "Note: Make sure the solver service is running with API enabled before running this script."
echo "Start the solver with: cargo run --bin solver -- --config config/demo.toml" 