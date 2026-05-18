# Off-chain Discovery API Exposure

The off-chain EIP-7683 discovery API is an internal ingestion endpoint. It exposes `POST /intent` so the solver's public API can forward validated off-chain orders into the discovery pipeline.

Operators should expose the main solver-service API to clients and keep the discovery API private:

- Public clients submit orders to `/api/v1/orders`.
- Solver-service performs ResourceLock signature validation before forwarding.
- Solver-service forwards validated requests to the configured discovery URL at `/intent`.
- The discovery API should be bound to localhost or private networking, or protected by internal authentication such as mTLS.

Do not publish the discovery port to untrusted networks. If it is exposed, untrusted clients can bypass validation performed by the public `/api/v1/orders` path and submit directly to `/intent`.

Defense in depth recommendation: even when the endpoint is private, keep `/intent` protected by network policy and consider validating ResourceLock signatures in the discovery handler as well, so a future deployment misconfiguration does not become an external bypass.
