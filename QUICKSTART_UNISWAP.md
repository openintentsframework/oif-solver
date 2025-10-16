# 🚀 Guide de Démarrage Rapide - Mini-Solver Uniswap

Ce guide explique comment démarrer le mini-solver Uniswap pour générer des quotes via l'API Routing de Uniswap.

## 📋 Prérequis

- Rust installé (voir `rust-toolchain.toml`)
- Configuration réseau (RPC endpoints) dans `config/demo/networks.toml`
- (Optionnel) Clé API Uniswap pour des limites de taux plus élevées

## ⚙️ Configuration

### Option 1 : Configuration Minimale (Mode Quote Uniquement)

Créez un fichier `config/uniswap-demo.toml` :

```toml
# Configuration minimale pour le mini-solver Uniswap
# Mode "quote only" - génère des quotes sans exécuter les transactions

include = [
    "demo/networks.toml",
    "demo/gas.toml",
]

[solver]
id = "uniswap-mini-solver"

# ============================================================================
# API SERVER - Endpoints HTTP pour les quotes
# ============================================================================
[api]
enabled = true
host = "127.0.0.1"
port = 3000
timeout_seconds = 30
max_request_size = 1048576  # 1MB

# Authentification JWT (optionnelle pour les tests)
[api.auth]
enabled = false  # Désactivé pour simplifier les tests

# Configuration des quotes
[api.quote]
validity_seconds = 60  # 1 minute de validité

# Configuration Uniswap
[api.quote.uniswap]
enabled = true
slippage_bps = 50  # 0.5% de slippage
# api_key = "YOUR_UNISWAP_API_KEY"  # Optionnel: ou définissez UNISWAP_API_KEY

# Adresses Universal Router par défaut (optionnel)
[api.quote.uniswap.router_addresses]
1 = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"      # Ethereum Mainnet
10 = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"     # Optimism
137 = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"    # Polygon
8453 = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"   # Base
42161 = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"  # Arbitrum One

# ============================================================================
# STORAGE - Requis pour le service
# ============================================================================
[storage]
primary = "memory"  # Stockage en mémoire pour les tests

[storage.implementations.memory]
# Pas de configuration nécessaire

# ============================================================================
# ACCOUNT - Requis mais non utilisé en mode quote-only
# ============================================================================
[account]
primary = "local"

[account.implementations.local]
# Clé privée de test (Anvil account #0)
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# ============================================================================
# PRICING - Pour calculer la profitabilité des quotes
# ============================================================================
[pricing]
primary = "mock"  # Utilise des prix mockés pour les tests

[pricing.implementations.mock]
# Prix par défaut ETH/USD = 4615.16
```

### Option 2 : Ajouter Uniswap à la Configuration Existante

Ajoutez simplement ces lignes à votre `config/demo/api.toml` :

```toml
# À la fin du fichier api.toml
[api.quote.uniswap]
enabled = true
slippage_bps = 50
# api_key = "YOUR_UNISWAP_API_KEY"  # Optionnel
```

## 🚀 Démarrage

### 1. Compiler le Solver

```bash
cd /home/warden/Documents/oif-solver
cargo build --release -p solver-service
```

### 2. Démarrer le Service (Mode Quote Uniquement)

**Option A : Avec configuration minimale**
```bash
cargo run --release -p solver-service -- \
  --config config/uniswap-demo.toml \
  --log-level info
```

**Option B : Avec configuration demo existante**
```bash
# D'abord, ajoutez la config Uniswap à demo/api.toml
cargo run --release -p solver-service -- \
  --config config/demo.toml \
  --log-level info
```

**Option C : Avec clé API Uniswap**
```bash
export UNISWAP_API_KEY="votre-cle-api"
cargo run --release -p solver-service -- \
  --config config/uniswap-demo.toml \
  --log-level info
```

### 3. Vérifier que le Service est Actif

```bash
curl http://localhost:3000/health
```

Vous devriez voir :
```json
{"status":"healthy"}
```

## 🧪 Tester les Quotes Uniswap

### Exemple 1 : Quote Simple (USDC → USDT sur Ethereum)

```bash
curl -X POST http://localhost:3000/quote \
  -H "Content-Type: application/json" \
  -d '{
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
```

### Exemple 2 : Quote Cross-Chain (ETH sur Optimism → USDC sur Base)

```bash
curl -X POST http://localhost:3000/quote \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": [{
      "asset": {
        "type": "evm",
        "chainId": 10,
        "address": "0x4200000000000000000000000000000000000006"
      },
      "amount": "1000000000000000000",
      "sender": {
        "type": "evm",
        "chainId": 10,
        "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
      }
    }],
    "outputs": [{
      "asset": {
        "type": "evm",
        "chainId": 8453,
        "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
      },
      "receiver": {
        "type": "evm",
        "chainId": 8453,
        "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
      }
    }]
  }'
```

## 📊 Comprendre la Réponse

La réponse contiendra :

```json
{
  "quote": {
    "orderId": "...",
    "outputs": [{
      "asset": { ... },
      "amount": "999500000",  // Montant après swap Uniswap
      "receiver": { ... },
      "call": "0x3593564c..."  // Calldata Uniswap Universal Router
    }],
    "signature": "...",
    "validity": 60
  }
}
```

**Points clés :**
- `amount` : Montant de sortie calculé par Uniswap (après slippage)
- `call` : Calldata pour exécuter le swap via Universal Router
- `receiver` : Peut être le Universal Router (qui transfère ensuite au destinataire final)

## 🔧 Mode Développement

Pour voir les logs détaillés de l'intégration Uniswap :

```bash
RUST_LOG=solver_service=debug,solver_service::apis::quote=trace \
cargo run -p solver-service -- \
  --config config/uniswap-demo.toml \
  --log-level debug
```

## 📝 Notes Importantes

### Mode "Quote Only" (Sans Exécution)

Le mini-solver en mode actuel :
- ✅ **Génère des quotes** avec calldata Uniswap
- ✅ **Répond aux endpoints HTTP** (`/quote`, `/intents`, `/orders`)
- ❌ **N'exécute PAS les transactions** on-chain automatiquement

Pour exécuter les transactions, il faudrait :
1. Configurer les modules `delivery`, `discovery`, `order`, `settlement`
2. Démarrer le solver engine complet (pas seulement le serveur HTTP)

### Chaînes Supportées par Uniswap

Le Routing API Uniswap supporte :
- Ethereum Mainnet (1)
- Optimism (10)
- Polygon (137)
- Arbitrum One (42161)
- Base (8453)
- BNB Chain (56)
- Avalanche (43114)
- Celo (42220)

### Limites de Taux

- **Sans clé API** : ~10 requêtes/seconde
- **Avec clé API** : Limites plus élevées (voir documentation Uniswap)

## 🐛 Dépannage

### Erreur "Uniswap routing failed"

- Vérifiez que les tokens sont supportés sur la chaîne
- Vérifiez qu'il existe de la liquidité pour la paire
- Augmentez le `slippage_bps` si nécessaire

### Erreur "Universal Router not configured"

- Vérifiez que la chaîne est dans `router_addresses`
- Utilisez les adresses par défaut (déjà configurées)

### Le service ne démarre pas

```bash
# Vérifier les erreurs de configuration
cargo run -p solver-service -- \
  --config config/uniswap-demo.toml \
  --log-level debug
```

## 📚 Ressources

- [Documentation Complète](./UNISWAP_ROUTING.md)
- [Plan d'Implémentation](./plan.md)
- [API Uniswap Routing](https://docs.uniswap.org/api/routing-api)
- [Universal Router](https://docs.uniswap.org/contracts/universal-router/overview)

## 🎯 Prochaines Étapes

1. **Tester avec l'agrégateur** : Intégrer avec `/home/warden/Documents/oif-aggregator`
2. **Ajouter l'exécution** : Configurer les modules pour exécuter les transactions
3. **Multi-routes** : Étendre pour supporter plusieurs DEXs (au-delà d'Uniswap)

