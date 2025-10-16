# Mini Solver Uniswap - Guide d'utilisation

Ce guide explique comment utiliser le mini-solver de test intégré avec l'API de routage Uniswap.

## Vue d'ensemble

Le mini-solver Uniswap enrichit automatiquement les quotes EIP-7683 avec des routes de swap Uniswap via le Universal Router. Il prend en charge:

- ✅ Routing automatique via l'API Uniswap Routing
- ✅ Universal Router sur plusieurs chaînes (Mainnet, Optimism, Polygon, Base, Arbitrum)
- ✅ Slippage configurable
- ✅ Génération de calldata pour exécution on-chain
- ✅ Intégration transparente avec le solver-service existant

## Limitations

- ❌ Un seul chemin Uniswap (pas de multi-routes)
- ❌ Pas d'agrégation multi-DEX
- ❌ ERC20 uniquement (pas d'ETH natif)

## Configuration

### 1. Activer Uniswap dans la configuration API

Ajoutez la configuration Uniswap dans votre fichier `config/demo/api.toml` ou créez un fichier séparé:

```toml
[api.quote.uniswap]
enabled = true
slippage_bps = 50  # 0.5% de slippage

# Optionnel: Clé API pour des limites de taux plus élevées
# api_key = "YOUR_UNISWAP_API_KEY"
```

### 2. Configuration modulaire (recommandée)

Incluez la configuration Uniswap dans votre fichier principal:

```toml
# config/demo.toml
include = [
    "demo/api.toml",
    "demo/cli.toml",
    "demo/gas.toml",
    "demo/networks.toml",
    "demo/uniswap.toml"  # ← Ajoutez cette ligne
]
```

### 3. Variables d'environnement

Définissez optionnellement une clé API Uniswap:

```bash
export UNISWAP_API_KEY="votre-cle-api"
```

## Utilisation

### Démarrer le solver

```bash
cargo run --bin solver-service -- --config config/demo.toml
```

### Requêter une quote avec routing Uniswap

Envoyez une requête `GET /quote` au solver-service:

```bash
curl -X POST http://localhost:3000/quote \
  -H "Content-Type: application/json" \
  -d '{
    "user": "0x01000001011234567890123456789012345678901234567890",
    "available_inputs": [{
      "user": "0x01000001011234567890123456789012345678901234567890",
      "asset": "0x010000010106B175474E89094C44Da98b954EedeAC495271d0F",
      "amount": "1000000000000000000"
    }],
    "requested_outputs": [{
      "receiver": "0x01000001371234567890123456789012345678901234567890",
      "asset": "0x010000013702791Bca1f2de4661ED88A30C99A7a9449Aa84174",
      "amount": "1000000"
    }]
  }'
```

### Comportement

Si Uniswap routing est activé:

1. **Génération de quote**: Le solver appelle l'API Uniswap Routing pour obtenir:
   - Le meilleur chemin de swap
   - Le calldata encodé pour le Universal Router
   - Le montant de sortie estimé après slippage

2. **Structure de la quote retournée**:
   ```json
   {
     "quotes": [{
       "orders": [{
         "message": {
           "outputs": [{
             "amount": "995000",  // ← Montant quoté par Uniswap
             "recipient": "0x...Router...",  // ← Universal Router
             "call": "0x3593564c..."  // ← Calldata Uniswap
           }]
         }
       }]
     }]
   }
   ```

3. **Exécution du fill**: Lorsque l'ordre est rempli, le settler:
   - Reçoit les tokens d'entrée de l'utilisateur
   - Appelle le Universal Router avec le calldata fourni
   - Le Universal Router exécute le swap et transfère les tokens au destinataire final

## Architecture

### Flux de données

```
┌─────────────┐      ┌──────────────┐      ┌─────────────────┐
│   Agrégateur│─────▶│ Solver       │─────▶│ Uniswap Routing │
│   (quote)   │      │ Service      │      │ API             │
└─────────────┘      └──────────────┘      └─────────────────┘
                            │                        │
                            │◀───────────────────────┘
                            │  (route + calldata)
                            ▼
                     ┌──────────────┐
                     │ Quote with   │
                     │ Uniswap call │
                     └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Order submit │
                     │ + Fill tx    │
                     └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ OutputSettler│───▶ Universal Router
                     │ (on-chain)   │     (execute swap)
                     └──────────────┘
```

### Points d'intégration

1. **Quote Generation** (`crates/solver-service/src/apis/quote/generation.rs`):
   - Méthode `enrich_output_with_uniswap()` appelle l'API Uniswap
   - Injecte le calldata dans `outputs[].call`
   - Override le recipient avec l'adresse du Universal Router

2. **Fill Transaction** (`crates/solver-order/src/implementations/standards/_7683.rs`):
   - Méthode `generate_fill_transaction()` propage `outputs[].call` et `outputs[].context`
   - Le settler exécute le calldata fourni

## Chaînes supportées

| Chain ID | Nom              | Universal Router Address                    |
|----------|------------------|---------------------------------------------|
| 1        | Ethereum Mainnet | `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` |
| 10       | Optimism         | `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` |
| 137      | Polygon          | `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` |
| 8453     | Base             | `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` |
| 42161    | Arbitrum One     | `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` |

## Dépannage

### Erreur "Uniswap routing failed"

- Vérifiez que la chaîne est supportée
- Vérifiez que les paires de tokens existent sur Uniswap
- Augmentez le slippage si la liquidité est faible
- Ajoutez une clé API si vous atteignez les limites de taux

### Erreur "Universal Router not configured"

- Vérifiez que l'adresse du Universal Router est correcte pour la chaîne cible
- Utilisez les adresses par défaut en omettant `router_addresses` dans la config

### Calldata non propagé dans le fill

- Vérifiez que `output.call` n'est pas vide dans la quote
- Vérifiez les logs du solver pour les erreurs d'appel API Uniswap

## Tests

### Tests unitaires

```bash
# Test du client Uniswap
cargo test -p solver-service --test uniswap -- --nocapture

# Test de la génération de quote
cargo test -p solver-service quote_generation -- --nocapture
```

### Test d'intégration

```bash
# Démarrer le solver avec config démo
cargo run --bin solver-service -- --config config/demo.toml

# Envoyer une requête de quote
curl -X POST http://localhost:3000/quote -H "Content-Type: application/json" -d @test_quote_request.json
```

## Ressources

- [Uniswap Routing API Docs](https://docs.uniswap.org/api/routing/overview)
- [Universal Router Docs](https://docs.uniswap.org/contracts/universal-router/overview)
- [EIP-7683 Specification](https://eips.ethereum.org/EIPS/eip-7683)

