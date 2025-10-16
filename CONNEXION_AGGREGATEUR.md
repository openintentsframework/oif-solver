# 🔗 Connexion Mini-Solver Uniswap ↔ Agrégateur OIF

Ce guide explique comment connecter le mini-solver Uniswap avec l'agrégateur OIF.

## 📋 Architecture

```
┌─────────────────────┐         ┌──────────────────────┐         ┌─────────────────┐
│   Client/User       │         │  OIF Aggregator      │         │ Uniswap Mini    │
│                     │────────▶│  Port: 4100          │────────▶│ Solver          │
│  POST /quote        │         │                      │         │ Port: 3002      │
└─────────────────────┘         └──────────────────────┘         └─────────────────┘
                                         │                                │
                                         │                                │
                                         ▼                                ▼
                                  Agrège quotes                   Uniswap Routing
                                  de plusieurs                    API (calldata)
                                  solvers
```

## 🚀 Démarrage Rapide

### 1. Démarrer le Mini-Solver Uniswap

```bash
cd /home/warden/Documents/oif-solver
./start-uniswap-solver.sh
```

Le solver démarre sur **http://127.0.0.1:3002**

### 2. Configurer l'Agrégateur

Utilisez la configuration fournie :

```bash
cd /home/warden/Documents/oif-aggregator
cp config/config-with-uniswap-solver.json config/config.json
```

Ou modifiez manuellement `config/config.json` :

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 4100
  },
  "solvers": {
    "uniswap-mini-solver": {
      "solver_id": "uniswap-mini-solver",
      "adapter_id": "oif-v1",
      "endpoint": "http://127.0.0.1:3002/api",
      "timeout_ms": 3000,
      "enabled": true,
      "max_retries": 2,
      "name": "Uniswap Mini Solver",
      "description": "Mini-solver utilisant Uniswap Routing API",
      "adapter_metadata": {
        "auth": {
          "auth_enabled": false
        }
      }
    }
  }
}
```

### 3. Démarrer l'Agrégateur

```bash
cd /home/warden/Documents/oif-aggregator
cargo run --release
```

L'agrégateur démarre sur **http://0.0.0.0:4100**

## 🧪 Tester la Connexion

### Test 1 : Vérifier que le Solver est Accessible

```bash
# Depuis l'agrégateur, tester l'endpoint du solver
curl -s http://127.0.0.1:3002/api/tokens | jq .
```

### Test 2 : Demander une Quote via l'Agrégateur

```bash
curl -X POST http://localhost:4100/quote \
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
  }' | jq .
```

### Test 3 : Vérifier les Logs

**Logs du Solver :**
```bash
tail -f /tmp/solver-final.log
```

**Logs de l'Agrégateur :**
```bash
# Les logs s'affichent dans le terminal où vous avez lancé cargo run
```

## 📊 Endpoints

### Agrégateur (Port 4100)

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `GET /health` | GET | Health check de l'agrégateur |
| `POST /quote` | POST | Demander une quote agrégée |
| `GET /solvers` | GET | Lister les solvers configurés |
| `GET /solvers/{id}` | GET | Détails d'un solver |

### Mini-Solver (Port 3002)

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `GET /api/tokens` | GET | Lister tous les tokens supportés |
| `GET /api/tokens/{chain_id}` | GET | Tokens pour une chaîne |
| `POST /api/quotes` | POST | Générer une quote avec Uniswap |
| `POST /api/orders` | POST | Soumettre un ordre |
| `GET /api/orders/{id}` | GET | Récupérer un ordre |

## 🔧 Configuration Avancée

### Activer l'Authentification JWT

Si vous activez l'auth sur le solver, mettez à jour l'agrégateur :

```json
{
  "solvers": {
    "uniswap-mini-solver": {
      "adapter_metadata": {
        "auth": {
          "auth_enabled": true,
          "client_name": "OIF Aggregator",
          "scopes": ["read-orders", "create-orders", "create-quotes"],
          "expiry_hours": 24
        }
      }
    }
  }
}
```

### Ajuster les Timeouts

Pour des quotes Uniswap plus lentes :

```json
{
  "solvers": {
    "uniswap-mini-solver": {
      "timeout_ms": 5000,
      "max_retries": 3
    }
  },
  "aggregation": {
    "per_solver_timeout_ms": 5000
  }
}
```

### Ajouter des Headers Personnalisés

```json
{
  "solvers": {
    "uniswap-mini-solver": {
      "headers": {
        "X-Client-Version": "1.0.0",
        "X-Environment": "development"
      }
    }
  }
}
```

## 🐛 Dépannage

### Problème : L'agrégateur ne peut pas joindre le solver

**Solution :**
```bash
# Vérifier que le solver tourne
curl http://127.0.0.1:3002/api/tokens

# Vérifier les logs du solver
tail -f /tmp/solver-final.log

# Redémarrer le solver
pkill -f "solver.*uniswap-demo"
./start-uniswap-solver.sh
```

### Problème : Timeout sur les quotes Uniswap

**Solution :**
- Augmenter `timeout_ms` dans la config de l'agrégateur
- Vérifier que l'API Uniswap est accessible
- Considérer l'ajout d'une clé API Uniswap

### Problème : Quotes vides ou sans calldata

**Causes possibles :**
1. **Uniswap désactivé** : Vérifier `config/uniswap-demo.toml` → `[api.quote.uniswap] enabled = true`
2. **Rate limit Uniswap** : Ajouter une clé API ou attendre
3. **Tokens non supportés** : Vérifier que les tokens existent sur la chaîne
4. **Pas de liquidité** : Certaines paires n'ont pas de liquidité Uniswap

## 📈 Monitoring

### Vérifier l'État du Solver

```bash
# Via l'agrégateur
curl http://localhost:4100/solvers/uniswap-mini-solver | jq .

# Directement
curl http://localhost:3002/api/tokens | jq .
```

### Logs en Temps Réel

```bash
# Terminal 1 : Solver
tail -f /tmp/solver-final.log

# Terminal 2 : Agrégateur
cd /home/warden/Documents/oif-aggregator
RUST_LOG=info cargo run --release
```

## 🎯 Flux Complet

1. **Client** envoie une requête quote à l'agrégateur (port 4100)
2. **Agrégateur** interroge tous les solvers activés, dont le mini-solver Uniswap
3. **Mini-Solver** :
   - Reçoit la requête sur `/api/quotes`
   - Appelle l'API Routing Uniswap
   - Génère le calldata Universal Router
   - Retourne la quote avec calldata
4. **Agrégateur** :
   - Agrège les quotes de tous les solvers
   - Sélectionne la meilleure quote
   - Retourne au client

## 📚 Documentation Complémentaire

- **[Guide Démarrage Solver](./QUICKSTART_UNISWAP.md)** - Démarrage du mini-solver
- **[Architecture Uniswap](./UNISWAP_ROUTING.md)** - Détails techniques
- **[OIF Adapter Guide](../oif-aggregator/docs/oif-adapter.md)** - Configuration agrégateur
- **[API Aggregator](../oif-aggregator/docs/api/)** - Endpoints agrégateur

## ✅ Checklist de Démarrage

- [ ] Mini-solver démarré sur port 3002
- [ ] Agrégateur configuré avec le solver
- [ ] Agrégateur démarré sur port 4100
- [ ] Test de connectivité réussi
- [ ] Quote test via agrégateur réussie
- [ ] Logs visibles et sans erreur

---

**Prêt à tester !** 🚀

