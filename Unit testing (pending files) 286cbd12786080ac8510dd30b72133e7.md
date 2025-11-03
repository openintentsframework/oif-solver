# Unit testing (pending files)

I think right now, the most critical module without proper test coverage is `solver-service` and focus on the signatures process

Files NEEDING Unit Tests 

**High Priority (Core Business Logic)**

1. `src/server.rs`

- HTTP server setup and routing
- Request handling pipeline
- Order validation and forwarding
- Quote acceptance processing
- Signature validation integration

2. `src/signature_validator.rs` 

- EIP-712 signature validation
- Order signature verification
- Multi-standard signature support

3. `src/factory_registry.rs`

- Dynamic factory registration (?)
- Configuration-based solver building
- Implementation discovery

4. `src/eip712/mod.rs`

- EIP-712 message hashing
- Domain separator handling
- Signature recovery

**Medium Priority (API Endpoints)**

5. `src/apis/tokens.rs`

- Token information endpoints
- Network token listing
- Chain-specific token queries

6. `src/apis/quote/mod.rs`

- Quote processing pipeline orchestration
- Quote storage and retrieval
- Cost context integration

7. `src/apis/quote/custody.rs`- Token custody decisions
- Balance verification logic

8. `src/eip712/compact/mod.rs`

- TheCompact protocol integration
- Compact-specific EIP-712 handling

- Token custody decisions
- Balance verification logic

8. `src/eip712/compact/mod.rs`

- TheCompact protocol integration
- Compact-specific EIP-712 handling