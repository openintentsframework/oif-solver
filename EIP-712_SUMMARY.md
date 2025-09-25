# Resumen de Implementaciones EIP-712 en OIF Solver

Este documento presenta un análisis detallado de los tres tipos principales de EIP-712 utilizados en el proyecto OIF Solver:

1. **The Compact** - Para órdenes batch de intent cross-chain
2. **EIP-3009** - Para transferencias de tokens con autorización  
3. **Permit2** - Para aprobaciones de tokens con witness data

## 1. The Compact (BatchCompact)

### Domain Separator

**Estructura del Domain:**
```
EIP712Domain(string name,uint256 chainId,address verifyingContract)
```

**Implementación:**
```rust
// Se obtiene dinámicamente del contrato TheCompact
pub async fn get_domain_separator(
    delivery: &Arc<DeliveryService>,
    contract_address: &Address,
    chain_id: u64,
) -> Result<FixedBytes<32>, APIError>
```

**Domain Hash Computation:**
```rust
pub fn compute_domain_hash(name: &str, chain_id: u64, verifying_contract: &AlloyAddress) -> B256 {
    let domain_type_hash = keccak256(DOMAIN_TYPE.as_bytes());
    let name_hash = keccak256(name.as_bytes());
    let mut enc = Eip712AbiEncoder::new();
    enc.push_b256(&domain_type_hash);
    enc.push_b256(&name_hash);
    enc.push_u256(U256::from(chain_id));
    enc.push_address(verifying_contract);
    keccak256(enc.finish())
}
```

### HashStruct del Message

**Primary Type:**
```
BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)
```

**Tipos Dependientes:**
```
Lock(bytes12 lockTag,address token,uint256 amount)
Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)
MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)
```

**Type Hash Completo:**
```rust
let batch_compact_type_hash = keccak256(
    b"BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
);
```

**Estructura del Hash:**
```rust
pub fn compute_batch_compact_struct_hash(
    contract_address: AlloyAddress,     // arbiter
    sponsor: AlloyAddress,              // sponsor
    nonce: Uint<256, 4>,               // nonce
    expires: Uint<256, 4>,             // expires
    lock_hash: FixedBytes<32>,         // hash de los commitments
    witness: FixedBytes<32>,           // hash del mandate
) -> Result<FixedBytes<32>, APIError>
```

**Proceso de Firma:**
- El contrato devuelve el domain separator
- Se calcula el struct hash con todos los componentes
- Firma ABI-encoded: `abi.encode(sponsorSig, allocatorSig)`

---

## 2. EIP-3009 (ReceiveWithAuthorization)

### Domain Separator

**Estructura del Domain:**
```
EIP712Domain(string name,uint256 chainId,address verifyingContract)
```

**Obtención:**
```bash
# Se obtiene del token que implementa EIP-3009
local domain_separator=$(cast call $token_address "DOMAIN_SEPARATOR()" --rpc-url $rpc_url)
```

**Características:**
- Domain separator específico de cada token
- Cada token ERC-3009 tiene su propio domain
- Se obtiene dinámicamente mediante llamada al contrato

### HashStruct del Message

**Primary Type:**
```
ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)
```

**Type Hash:**
```bash
local eip3009_type_hash=$(cast keccak "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
```

**Estructura del Hash:**
```bash
# Encoding de la estructura
local struct_encoded=$(cast abi-encode "f(bytes32,address,address,uint256,uint256,uint256,bytes32)" \
    "$eip3009_type_hash" \
    "$from_address" \
    "$to_address" \
    "$value" \
    "$valid_after" \
    "$valid_before" \
    "$nonce_bytes32")
```

**Parámetros:**
- `from`: Dirección del usuario que autoriza
- `to`: Dirección del input settler (spender)
- `value`: Cantidad de tokens a transferir
- `validAfter`: 0 (válido inmediatamente)
- `validBefore`: Fill deadline del intent
- `nonce`: Order ID como nonce único

**Proceso de Firma:**
- Se obtiene domain separator del token
- Se construye el struct hash con los parámetros
- Se firma el digest final con `--no-hash` flag

---

## 3. Permit2 (PermitBatchWitnessTransferFrom)

### Domain Separator

**Estructura del Domain:**
```
EIP712Domain(string name,uint256 chainId,address verifyingContract)
```

**Constantes:**
```rust
pub const DOMAIN_TYPE: &str = "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
pub const NAME_PERMIT2: &str = "Permit2";
```

**Domain Hash Computation:**
```rust
// Domain separator hash
let mut enc = Eip712AbiEncoder::new();
enc.push_b256(&domain_type_hash);
enc.push_b256(&name_hash);                 // keccak256("Permit2")
enc.push_u256(U256::from(origin_chain_id));
enc.push_address(&permit2);                // Permit2 contract address
let domain_separator_hash = keccak256(enc.finish());
```

**Características:**
- Nombre fijo: "Permit2"
- Verifying contract: Dirección del contrato Permit2 en cada chain
- Chain ID específico de la chain origen

### HashStruct del Message

**Primary Type:**
```
PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)
```

**Tipos Dependientes:**
```rust
pub const TOKEN_PERMISSIONS_TYPE: &str = "TokenPermissions(address token,uint256 amount)";
pub const PERMIT2_WITNESS_TYPE: &str = "Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)";
pub const MANDATE_OUTPUT_TYPE: &str = "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)";
```

**Type Hash Completo:**
```rust
let permit_batch_witness_type_hash = keccak256(
    format!(
        "{}{}{}{}",
        PERMIT_BATCH_WITNESS_TYPE,
        MANDATE_OUTPUT_TYPE,
        TOKEN_PERMISSIONS_TYPE,
        PERMIT2_WITNESS_TYPE
    ).as_bytes(),
);
```

**Estructura del Hash:**

1. **TokenPermissions Hash:**
```rust
let mut enc = Eip712AbiEncoder::new();
enc.push_b256(&token_permissions_type_hash);
enc.push_address(&origin_token);
enc.push_u256(amount);
let token_perm_hash = keccak256(enc.finish());
```

2. **MandateOutput Hash:**
```rust
let mut enc = Eip712AbiEncoder::new();
enc.push_b256(&mandate_output_type_hash);
enc.push_b256(&B256::ZERO);              // oracle (empty)
enc.push_address(&output_settler);
enc.push_u256(U256::from(dest_chain_id));
enc.push_address(&dest_token);
enc.push_u256(amount);
enc.push_address(&recipient);
enc.push_b256(&empty_bytes_hash);        // call (empty)
enc.push_b256(&empty_bytes_hash);        // context (empty)
let mandate_output_hash = keccak256(enc.finish());
```

3. **Permit2Witness Hash:**
```rust
let mut enc = Eip712AbiEncoder::new();
enc.push_b256(&permit2_witness_type_hash);
enc.push_u32(expires_secs);
enc.push_address(&input_oracle);
enc.push_b256(&outputs_hash);
let witness_hash = keccak256(enc.finish());
```

4. **Main Struct Hash:**
```rust
let mut enc = Eip712AbiEncoder::new();
enc.push_b256(&permit_batch_witness_type_hash);
enc.push_b256(&permitted_array_hash);
enc.push_address(&spender);              // Input settler
enc.push_u256(nonce_ms);                 // Timestamp-based nonce
enc.push_u256(deadline_secs);            // Validity deadline
enc.push_b256(&witness_hash);
let main_struct_hash = keccak256(enc.finish());
```

**Parámetros Clave:**
- `permitted`: Array con token y amount
- `spender`: Input settler en origin chain
- `nonce`: Timestamp en milisegundos
- `deadline`: Tiempo de validez configurable
- `witness`: Cross-chain intent data con oracle y outputs

---

## 4. Digest Final Común

**Todos los tipos usan el mismo patrón EIP-712:**

```rust
pub fn compute_final_digest(domain_hash: &B256, struct_hash: &B256) -> B256 {
    let mut out = Vec::with_capacity(2 + 32 + 32);
    out.push(0x19);
    out.push(0x01);
    out.extend_from_slice(domain_hash.as_slice());
    out.extend_from_slice(struct_hash.as_slice());
    keccak256(out)
}
```

**Fórmula:**
```
digest = keccak256(0x1901 || domainHash || structHash)
```

---

## 5. Estructura de Quote Response

### Tipos de Quote Response

**Quote Structure (API Types):**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    pub orders: Vec<QuoteOrder>,
    pub details: QuoteDetails,
    pub valid_until: Option<u64>,
    pub eta: Option<u64>,
    pub quote_id: String,
    pub provider: String,
    pub cost: Option<CostEstimate>,
    pub lock_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteOrder {
    pub signature_type: SignatureType,  // Eip712 | Erc3009
    pub domain: InteropAddress,
    pub primary_type: String,
    pub message: serde_json::Value,
}
```

**Signature Types:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureType {
    Eip712,
    Erc3009,
}
```

### Flujo de Generación de Quotes

**Generación por Tipo:**

1. **Para Permit2:**
```rust
fn generate_permit2_order(
    request: &GetQuoteRequest,
    config: &Config,
    settlement: &dyn SettlementInterface,
    selected_oracle: solver_types::Address,
) -> Result<QuoteOrder, QuoteError> {
    let chain_id = request.available_inputs[0].asset.ethereum_chain_id()?;
    let domain_address = permit2_domain_address_from_config(config, chain_id)?;
    let (final_digest, message_obj) = 
        build_permit2_batch_witness_digest(request, config, settlement, selected_oracle)?;
    
    let message = json!({ 
        "digest": with_0x_prefix(&hex::encode(final_digest)), 
        "eip712": message_obj 
    });
    
    Ok(QuoteOrder {
        signature_type: SignatureType::Eip712,
        domain: domain_address,
        primary_type: "PermitBatchWitnessTransferFrom".to_string(),
        message,
    })
}
```

2. **Para The Compact:**
```rust
// La implementación genera un message complejo con:
let eip712_message = json!({
    "types": {
        "EIP712Domain": [...],
        "BatchCompact": [...],
        "Lock": [...],
        "Mandate": [...],
        "MandateOutput": [...]
    },
    "domain": {
        "name": "TheCompact",
        "version": "1",
        "chainId": input_chain_id.to_string(),
        "verifyingContract": "0x..."
    },
    "primaryType": "BatchCompact",
    "message": {
        "arbiter": "0x...",
        "sponsor": "0x...",
        "nonce": "...",
        "expires": "...",
        "commitments": [...],
        "mandate": {...}
    }
});

// Se intenta computar el digest en el server
let result_with_digest = match self.try_compute_server_digest(&eip712_message, ...) {
    Ok(digest) => json!({
        "digest": with_0x_prefix(&hex::encode(digest)),
        "eip712": eip712_message
    }),
    Err(_) => json!({
        "eip712": eip712_message  // Cliente debe computar digest
    }),
};
```

3. **Para EIP-3009:**
```rust
fn generate_erc3009_order(
    request: &GetQuoteRequest,
    config: &Config,
    settlement: &dyn SettlementInterface,
    selected_oracle: solver_types::Address,
) -> Result<QuoteOrder, QuoteError> {
    // Computa nonce y order_identifier usando StandardOrder
    let (nonce_u64, order_identifier) = self.compute_erc3009_order_identifier(request, config)?;
    
    let input_message = json!({
        "from": input.user.ethereum_address()?,
        "to": format!("0x{:040x}", input_settler_address),
        "value": input.amount.to_string(),
        "validAfter": 0,
        "validBefore": fill_deadline,
        "nonce": order_identifier,  // Order ID para firma
        "realNonce": format!("0x{:x}", nonce_u64),  // Nonce real para StandardOrder
        "inputOracle": format!("0x{:040x}", selected_oracle_address)
    });

    Ok(QuoteOrder {
        signature_type: SignatureType::Erc3009,
        domain: first_input.asset.clone(),  // Token address como domain
        primary_type: "ReceiveWithAuthorization".to_string(),
        message: input_message,
    })
}
```

### Detección del Tipo de Orden en Cliente

**En scripts/demo/lib/quotes.sh:**
```bash
# Detecta el tipo basado en signature_type
local signature_type=$(echo "$full_message" | jq -r '.signatureType // "eip712"')

if [ "$signature_type" = "erc3009" ]; then
    print_info "Detected ERC-3009 order, using ERC-3009 signing..."
    signature=$(create_prefixed_signature "$signature" "eip3009")

elif [ "$signature_type" = "eip712" ]; then
    # Para EIP-712, detecta el primaryType
    local eip712_primary_type=$(echo "$eip712_message" | jq -r '.primaryType // "PermitBatchWitnessTransferFrom"')
    
    if [ "$eip712_primary_type" = "BatchCompact" ]; then
        print_info "Detected BatchCompact order, using compact signing..."
        signature=$(sign_compact_digest_from_quote "$user_key" "$full_message")
        
        # ABI-encode para compact/resource lock
        local allocator_data="0x"
        signature=$(cast abi-encode "f(bytes,bytes)" "$signature" "$allocator_data")
        
    else
        print_info "Detected Permit2 order, using standard signing..."
        # Procesa Permit2
    fi
fi
```

### Campos del Message por Tipo

**Permit2 Message:**
```json
{
  "digest": "0x...",  // Pre-computed digest
  "eip712": {
    "signing": {
      "scheme": "eip-712",
      "noPrefix": true,
      "domain": {
        "name": "Permit2",
        "chainId": 1,
        "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
      },
      "primaryType": "PermitBatchWitnessTransferFrom"
    },
    "permitted": [{
      "token": "0x...",
      "amount": "1000000000"
    }],
    "spender": "0x...",
    "nonce": "1703847123456",  // Timestamp-based
    "deadline": "1703847423",  // Current + validity
    "witness": {
      "expires": 1703847423,
      "inputOracle": "0x...",
      "outputs": [{
        "oracle": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "settler": "0x000000000000000000000000...",  // Padded to 32 bytes
        "chainId": 137,
        "token": "0x000000000000000000000000...",    // Padded to 32 bytes
        "amount": "995000000",
        "recipient": "0x000000000000000000000000...", // Padded to 32 bytes
        "call": "0x",
        "context": "0x"
      }]
    }
  }
}
```

**The Compact Message:**
```json
{
  "digest": "0x...",  // Optional pre-computed
  "eip712": {
    "types": {
      // Complete type definitions
    },
    "domain": {
      "name": "TheCompact",
      "version": "1",
      "chainId": "1",
      "verifyingContract": "0x..."
    },
    "primaryType": "BatchCompact",
    "message": {
      "arbiter": "0x...",    // Contract address
      "sponsor": "0x...",    // User address  
      "nonce": "123456789",
      "expires": "1703847423",
      "commitments": [{
        "lockTag": "0x000000000000000000000000",
        "token": "0x...",
        "amount": "1000000000"
      }],
      "mandate": {
        "fillDeadline": "1703847423",
        "inputOracle": "0x...",
        "outputs": [{
          "oracle": "0x000000000000000000000000...",
          "settler": "0x000000000000000000000000...",
          "chainId": "137",
          "token": "0x000000000000000000000000...",
          "amount": "995000000",
          "recipient": "0x000000000000000000000000...",
          "call": "0x",
          "context": "0x"
        }]
      }
    }
  },
  // Backward compatibility fields
  "user": "0x...",
  "inputs": [["123456789", "1000000000"]],
  "outputs": [...],
  "nonce": "123456789",
  "deadline": "1703847423"
}
```

**EIP-3009 Message:**
```json
{
  "from": "0x...",           // User address
  "to": "0x...",             // Input settler  
  "value": "1000000000",     // Amount
  "validAfter": 0,           // Valid immediately
  "validBefore": "1703847423", // Fill deadline
  "nonce": "0x...",          // Order identifier (32 bytes)
  "realNonce": "0x7b",       // Real nonce for StandardOrder
  "inputOracle": "0x..."     // Oracle address
}
```

---

## 6. Validación de Firmas

### Proceso Genérico

```rust
pub fn validate_eip712_signature(
    domain_separator: FixedBytes<32>,
    struct_hash: FixedBytes<32>,
    signature: &Bytes,
    expected_signer: AlloyAddress,
) -> Result<bool, APIError> {
    // Compute EIP-712 message hash
    let message_hash = keccak256([
        &[0x19, 0x01][..],
        domain_separator.as_slice(),
        struct_hash.as_slice(),
    ].concat());

    // Recover signer from signature
    let recovered_signer = recover_signer(message_hash, signature)?;
    
    Ok(recovered_signer == expected_signer)
}
```

### Casos Especiales

**The Compact:**
- Signatures ABI-encoded con allocator data
- Extracción de sponsor signature del encoding

**EIP-3009:**
- Domain separator específico del token
- Nonce management mediante order ID

**Permit2:**
- Timestamp-based nonces para unicidad
- Witness data para cross-chain validation

---

## 7. Constantes y Configuración

### Type Strings Reutilizables

```rust
pub const DOMAIN_TYPE: &str = "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
pub const NAME_PERMIT2: &str = "Permit2";
pub const MANDATE_OUTPUT_TYPE: &str = "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)";
pub const PERMIT2_WITNESS_TYPE: &str = "Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)";
pub const TOKEN_PERMISSIONS_TYPE: &str = "TokenPermissions(address token,uint256 amount)";
pub const PERMIT_BATCH_WITNESS_TYPE: &str = "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)";
```

### Registry de Protocolos

```rust
// Protocol registry para obtener direcciones de contratos
let permit2 = PROTOCOL_REGISTRY
    .get_permit2_address(origin_chain_id)
    .ok_or_else(|| QuoteError::InvalidRequest(format!("Permit2 not deployed on chain {}", origin_chain_id)))?;
```

---

## 6. Conversión de Quote a IntentRequest

### Proceso de Conversión

**TryFrom Implementation:**
```rust
impl TryFrom<&Quote> for interfaces::StandardOrder {
    fn try_from(quote: &Quote) -> Result<Self, Self::Error> {
        let quote_order = quote.orders.first().ok_or("Quote must contain at least one order")?;

        match quote_order.signature_type {
            SignatureType::Erc3009 => {
                Self::handle_erc3009_quote_conversion(quote)
            },
            SignatureType::Eip712 => {
                let (eip712_data, primary_type) = Self::extract_eip712_data_from_quote(quote)?;
                
                if primary_type == "BatchCompact" {
                    Self::handle_batch_compact_quote_conversion(quote, eip712_data)
                } else {
                    Self::handle_permit2_quote_conversion(quote, eip712_data)
                }
            },
        }
    }
}
```

**IntentRequest Structure:**
```rust
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IntentRequest {
    pub order: Bytes,        // ABI-encoded StandardOrder
    pub sponsor: Address,    // User address
    pub signature: Bytes,    // User signature
    pub lock_type: LockType, // TheCompact | Permit2 | Eip3009
}
```

---

## 7. Flujo Completo de Firma

### 1. Quote Generation
```
Cliente solicita quote → Solver genera QuoteOrder → Incluye todos los datos necesarios para firma
```

### 2. Client-Side Signing
```
Cliente recibe quote → Detecta tipo de orden → Usa datos apropiados → Genera firma
```

### 3. Order Submission
```
Cliente envía firma → Solver convierte a IntentRequest → Valida firma → Procesa orden
```

### Ejemplo de Flujo Permit2:

1. **Quote Generation:**
   - Solver calcula digest usando `build_permit2_batch_witness_digest()`
   - Incluye estructura EIP-712 completa en response

2. **Client Signing:**
   - Cliente extrae `eip712` object del message
   - Firma usando estructura proporcionada
   - Genera signature bytes

3. **Order Processing:**
   - Solver recibe signature
   - Convierte quote a `StandardOrder`
   - Valida firma contra expected signer
   - Procesa intent

---

## 8. Recomendaciones de Mejora

### 1. Centralización de Domain Separators
- Crear un registry centralizado para todos los domain separators
- Cachear domain separators para evitar múltiples llamadas

### 2. Validación Unificada
- Implementar trait común para todos los tipos de EIP-712
- Centralizar la lógica de recuperación de signer

### 3. Testing
- Tests unitarios para cada tipo de EIP-712
- Tests de interoperabilidad entre tipos

### 4. Documentación
- Ejemplos de uso para cada tipo
- Diagramas de flujo para el proceso de firma

Este documento proporciona la base completa para entender y mejorar el proceso de manejo de EIP-712 en el proyecto.
