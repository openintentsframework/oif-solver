#!/bin/bash
# Script de test pour le mini-solver Uniswap
# Teste la génération de quotes via l'API

set -e

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

API_URL="${1:-http://localhost:3000}"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Test Mini-Solver Uniswap - Génération Quote        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Test 1: Health check
echo -e "${YELLOW}📊 Test 1: Health Check${NC}"
echo -e "   GET ${API_URL}/health"
echo ""

HEALTH_RESPONSE=$(curl -s "${API_URL}/health" || echo "ERROR")

if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    echo -e "${GREEN}✅ Service actif${NC}"
    echo "   Réponse: $HEALTH_RESPONSE"
else
    echo -e "${RED}❌ Service non disponible${NC}"
    echo "   Assurez-vous que le solver est démarré avec:"
    echo "   ./start-uniswap-solver.sh"
    exit 1
fi
echo ""

# Test 2: Quote simple (USDC -> USDT sur Ethereum)
echo -e "${YELLOW}📊 Test 2: Quote Simple (USDC → USDT sur Ethereum Mainnet)${NC}"
echo -e "   POST ${API_URL}/quote"
echo ""

QUOTE_REQUEST='{
  "inputs": [{
    "asset": {
      "type": "evm",
      "chainId": 1,
      "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    },
    "amount": "1000000000",
    "sender": {
      "type": "evm",
      "chainId": 1,
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
    }
  }],
  "outputs": [{
    "asset": {
      "type": "evm",
      "chainId": 1,
      "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    },
    "receiver": {
      "type": "evm",
      "chainId": 1,
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
    }
  }]
}'

echo "   Input: 1000 USDC (0xA0b8...eB48)"
echo "   Output: USDT (0xdAC1...1ec7)"
echo ""

QUOTE_RESPONSE=$(curl -s -X POST "${API_URL}/quote" \
  -H "Content-Type: application/json" \
  -d "$QUOTE_REQUEST" || echo "ERROR")

if echo "$QUOTE_RESPONSE" | grep -q "orderId"; then
    echo -e "${GREEN}✅ Quote générée avec succès${NC}"
    echo ""
    echo "   Détails de la quote:"
    
    # Extraire les informations clés (si jq est disponible)
    if command -v jq &> /dev/null; then
        ORDER_ID=$(echo "$QUOTE_RESPONSE" | jq -r '.quote.orderId // empty')
        OUTPUT_AMOUNT=$(echo "$QUOTE_RESPONSE" | jq -r '.quote.outputs[0].amount // empty')
        HAS_CALLDATA=$(echo "$QUOTE_RESPONSE" | jq -r '.quote.outputs[0].call // empty' | grep -q "0x" && echo "Oui" || echo "Non")
        
        echo "   - Order ID: ${ORDER_ID:0:20}..."
        echo "   - Montant de sortie: $OUTPUT_AMOUNT"
        echo "   - Calldata Uniswap: $HAS_CALLDATA"
    else
        echo "$QUOTE_RESPONSE" | head -c 500
        echo "..."
    fi
else
    echo -e "${RED}❌ Échec de génération de quote${NC}"
    echo "   Réponse: $QUOTE_RESPONSE"
fi
echo ""

# Test 3: Quote avec montant différent
echo -e "${YELLOW}📊 Test 3: Quote avec Montant Plus Élevé (10000 USDC)${NC}"
echo -e "   POST ${API_URL}/quote"
echo ""

QUOTE_REQUEST_2='{
  "inputs": [{
    "asset": {
      "type": "evm",
      "chainId": 1,
      "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    },
    "amount": "10000000000",
    "sender": {
      "type": "evm",
      "chainId": 1,
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
    }
  }],
  "outputs": [{
    "asset": {
      "type": "evm",
      "chainId": 1,
      "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    },
    "receiver": {
      "type": "evm",
      "chainId": 1,
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
    }
  }]
}'

QUOTE_RESPONSE_2=$(curl -s -X POST "${API_URL}/quote" \
  -H "Content-Type: application/json" \
  -d "$QUOTE_REQUEST_2" || echo "ERROR")

if echo "$QUOTE_RESPONSE_2" | grep -q "orderId"; then
    echo -e "${GREEN}✅ Quote générée avec succès${NC}"
    
    if command -v jq &> /dev/null; then
        OUTPUT_AMOUNT_2=$(echo "$QUOTE_RESPONSE_2" | jq -r '.quote.outputs[0].amount // empty')
        echo "   - Montant de sortie: $OUTPUT_AMOUNT_2"
    fi
else
    echo -e "${RED}❌ Échec de génération de quote${NC}"
fi
echo ""

# Résumé
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Tests terminés${NC}"
echo ""
echo -e "${YELLOW}💡 Prochaines étapes :${NC}"
echo "   1. Vérifier les logs du solver pour voir les appels Uniswap"
echo "   2. Tester avec d'autres paires de tokens"
echo "   3. Intégrer avec l'agrégateur OIF"
echo ""
echo -e "${YELLOW}📚 Documentation :${NC}"
echo "   - Guide complet : ./QUICKSTART_UNISWAP.md"
echo "   - Architecture : ./UNISWAP_ROUTING.md"
echo ""

