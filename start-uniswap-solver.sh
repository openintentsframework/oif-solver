#!/bin/bash
# Script de démarrage du mini-solver Uniswap
# Mode "quote only" - génère des quotes sans exécuter les transactions

set -e

# Couleurs pour les messages
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Mini-Solver Uniswap - Mode Quote Only              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Vérifier si le binaire existe
if [ ! -f "target/release/solver" ]; then
    echo -e "${YELLOW}⚠️  Binaire non trouvé. Compilation en cours...${NC}"
    cargo build --release -p solver-service
    echo -e "${GREEN}✅ Compilation terminée${NC}"
    echo ""
fi

# Configuration
CONFIG_FILE="${1:-config/uniswap-demo.toml}"
LOG_LEVEL="${2:-info}"

echo -e "${GREEN}📋 Configuration :${NC}"
echo -e "   Fichier : ${CONFIG_FILE}"
echo -e "   Log level : ${LOG_LEVEL}"
echo -e "   Port : 3000"
echo ""

# Vérifier si le fichier de config existe
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}⚠️  Fichier de configuration non trouvé : ${CONFIG_FILE}${NC}"
    echo -e "${YELLOW}   Utilisation de la configuration par défaut...${NC}"
    CONFIG_FILE="config/demo.toml"
fi

# Afficher les variables d'environnement optionnelles
if [ ! -z "$UNISWAP_API_KEY" ]; then
    echo -e "${GREEN}🔑 Clé API Uniswap détectée${NC}"
else
    echo -e "${YELLOW}ℹ️  Pas de clé API Uniswap (limites de taux par défaut)${NC}"
    echo -e "${YELLOW}   Pour ajouter une clé : export UNISWAP_API_KEY='votre-cle'${NC}"
fi
echo ""

echo -e "${BLUE}🚀 Démarrage du solver...${NC}"
echo ""

# Démarrer le solver
exec ./target/release/solver \
    --config "$CONFIG_FILE" \
    --log-level "$LOG_LEVEL"

