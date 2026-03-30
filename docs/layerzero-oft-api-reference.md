# LayerZero V2 OFT API Reference

Reference documentation for the LayerZero V2 OFT (Omnichain Fungible Token) integration used for cross-chain rebalancing.

## Official Documentation Links

### Core OFT Documentation
- **OFT Quickstart**: https://docs.layerzero.network/v2/developers/evm/oft/quickstart
- **OFT Technical Reference**: https://docs.layerzero.network/v2/concepts/technical-reference/oft-reference
- **OApp Reference (base contract)**: https://docs.layerzero.network/v2/concepts/technical-reference/oapp-reference

### Protocol & Messaging
- **LayerZero Endpoint**: https://docs.layerzero.network/v2/concepts/protocol/layerzero-endpoint
- **Message Properties**: https://docs.layerzero.network/v2/concepts/protocol/message-properties
- **Message Security**: https://docs.layerzero.network/v2/concepts/protocol/message-security
- **Message Send Library**: https://docs.layerzero.network/v2/concepts/protocol/message-send-library
- **Message Receive Library**: https://docs.layerzero.network/v2/concepts/protocol/message-receive-library
- **Transaction Pricing**: https://docs.layerzero.network/v2/concepts/protocol/transaction-pricing
- **Packet Lifecycle**: https://docs.layerzero.network/v2/concepts/protocol/packet

### Configuration & Options
- **Message Execution Options**: https://docs.layerzero.network/v2/concepts/message-options
- **Debugging Messages**: https://docs.layerzero.network/v2/concepts/troubleshooting/debugging-messages

### Deployments & Contracts
- **Deployed Contracts (all chains)**: https://docs.layerzero.network/v2/deployments/deployed-contracts
- **DVN Addresses**: https://docs.layerzero.network/v2/deployments/dvn-addresses
- **Deployments Metadata API**: https://metadata.layerzero-api.com/v1/metadata/deployments

### OFT API (tracking transfers)
- **List OFTs**: https://docs.layerzero.network/api-reference/ofts/get-list
- **Get Transfer**: https://docs.layerzero.network/api-reference/ofts/get-transfer
- **OpenAPI Spec**: https://docs.layerzero.network/api-reference/openapi/get-openapi

### LayerZero Scan (message tracking)
- **Explorer**: https://layerzeroscan.com
- **Message Lookup by GUID**: https://layerzeroscan.com/tx/{guid}

### GitHub Sources (contract ABIs)
- **IOFT.sol**: https://github.com/LayerZero-Labs/LayerZero-v2/blob/main/packages/layerzero-v2/evm/oapp/contracts/oft/interfaces/IOFT.sol
- **OFT.sol**: https://github.com/LayerZero-Labs/LayerZero-v2/blob/main/packages/layerzero-v2/evm/oapp/contracts/oft/OFT.sol
- **OFTAdapter.sol**: https://github.com/LayerZero-Labs/LayerZero-v2/blob/main/packages/layerzero-v2/evm/oapp/contracts/oft/OFTAdapter.sol
- **OFTCore.sol**: https://github.com/LayerZero-Labs/LayerZero-v2/blob/main/packages/layerzero-v2/evm/oapp/contracts/oft/OFTCore.sol
- **OptionsBuilder.sol**: https://github.com/LayerZero-Labs/LayerZero-v2/blob/main/packages/layerzero-v2/evm/oapp/contracts/oapp/libs/OptionsBuilder.sol
- **ExecutorOptions.sol**: https://github.com/LayerZero-Labs/LayerZero-v2/blob/main/packages/layerzero-v2/evm/protocol/contracts/messagelib/libs/ExecutorOptions.sol
- **ILayerZeroEndpointV2.sol**: https://github.com/LayerZero-Labs/LayerZero-v2/blob/main/packages/layerzero-v2/evm/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol

### Katana-Specific
- **Bridge to Katana with LayerZero**: https://docs.katana.network/katana/how-to/bridge-to-katana-with-layerzero/
- **Katana App (bridge UI)**: https://app.katana.network/
- **L2Beat Interop (Katana ↔ Ethereum)**: https://l2beat.com/interop/summary?selectedChains=katana%2Cethereum

---

## Endpoint IDs (EIDs)

LayerZero uses its own endpoint IDs, **not** EVM chain IDs.

| Chain | EID | Chain ID |
|---|---|---|
| Ethereum | `30101` | 1 |
| Katana | `30375` | 747474 |
| Arbitrum | `30110` | 42161 |
| Optimism | `30111` | 10 |
| Base | `30184` | 8453 |
| Polygon | `30109` | 137 |

Mainnets use the `30xxx` range. Testnets use `40xxx`.

---

## Deployed Contracts

### LayerZero Protocol (Ethereum)

| Contract | Address |
|---|---|
| EndpointV2 | `0x1a44076050125825900e736c501f859c50fE728c` |
| SendUln302 | `0x6c26c61a97006888ea9E4FA36584c7df57Cd9dA3` |
| ReceiveUln302 | `0x1322871e4ab09Bc7f5717189434f97bBD9546e95` |
| Executor | `0xCd3F213AD101472e1713C72B1697E727C803885b` |

### Vaultbridge (USDC — Katana ↔ Ethereum)

| Contract | Chain | Address |
|---|---|---|
| USDC | Ethereum | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` |
| USDC Vault Bridge | Ethereum | `0x53E82ABbb12638F09d9e624578ccB666217a765e` |
| Share OFT Adapter | Ethereum | `0xb5bADA33542a05395d504a25885e02503A957Bb3` |
| OVault Composer | Ethereum | `0x8A35897fda9E024d2aC20a937193e099679eC477` |
| Share OFT (vbUSDC) | Katana | `0x807275727Dd3E640c5F2b5DE7d1eC72B4Dd293C0` |

---

## Solidity Interfaces

### IOFT — Core Token Interface

Both `OFT` (native) and `OFTAdapter` (wrapper) implement this interface.

```solidity
interface IOFT {
    // Quote the messaging fee for a cross-chain send
    function quoteSend(
        SendParam calldata _sendParam,
        bool _payInLzToken
    ) external view returns (MessagingFee memory);

    // Execute a cross-chain token transfer
    function send(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    ) external payable returns (MessagingReceipt memory, OFTReceipt memory);

    // Get limits and fee details for a send
    function quoteOFT(
        SendParam calldata _sendParam
    ) external view returns (OFTLimit memory, OFTFeeDetail[] memory, OFTReceipt memory);

    // Returns the address of the underlying token
    function token() external view returns (address);

    // Whether the caller needs to approve the OFT before sending
    function approvalRequired() external view returns (bool);
}
```

### Structs

```solidity
struct SendParam {
    uint32 dstEid;           // Destination LayerZero endpoint ID
    bytes32 to;              // Recipient address (left-padded to 32 bytes)
    uint256 amountLD;        // Amount in local decimals
    uint256 minAmountLD;     // Minimum amount (slippage protection)
    bytes extraOptions;      // Encoded executor options (TYPE_3)
    bytes composeMsg;        // Composed message (empty for simple transfers)
    bytes oftCmd;            // OFT command (empty for standard sends)
}

struct MessagingFee {
    uint256 nativeFee;       // Fee in native gas token (e.g. ETH)
    uint256 lzTokenFee;      // Fee in LZ token (usually 0)
}

struct MessagingReceipt {
    bytes32 guid;            // Globally unique message ID (for tracking)
    uint64 nonce;            // Message nonce
    MessagingFee fee;        // Actual fee charged
}

struct OFTReceipt {
    uint256 amountSentLD;    // Amount debited from sender
    uint256 amountReceivedLD;// Amount recipient will receive
}

struct OFTLimit {
    uint256 minAmountLD;     // Minimum sendable amount
    uint256 maxAmountLD;     // Maximum sendable amount
}

struct OFTFeeDetail {
    int256 feeAmountLD;      // Fee amount
    string description;      // Fee description
}
```

---

## extraOptions Encoding (TYPE_3)

Used in `SendParam.extraOptions` to specify gas for `lzReceive` on the destination chain.

### Basic lzReceive option (most common)

```
Bytes layout:
  0x0003              // uint16 — TYPE_3 prefix
  0x01                // uint8  — WORKER_ID (1 = executor)
  0x0011              // uint16 — option_size (17 = 1 type + 16 gas)
  0x01                // uint8  — OPTION_TYPE_LZRECEIVE
  <uint128 gas>       // 16 bytes big-endian gas limit (e.g. 200_000)
```

### lzReceive with msg.value

```
Bytes layout:
  0x0003              // TYPE_3 prefix
  0x01                // WORKER_ID
  0x0021              // option_size (33 = 1 type + 16 gas + 16 value)
  0x01                // OPTION_TYPE_LZRECEIVE
  <uint128 gas>       // gas limit
  <uint128 value>     // native value to forward
```

### Rust Example

```rust
fn build_lz_receive_option(gas: u128) -> Vec<u8> {
    let mut opts = Vec::with_capacity(22);
    opts.extend_from_slice(&3u16.to_be_bytes());     // TYPE_3
    opts.push(1u8);                                   // WORKER_ID
    opts.extend_from_slice(&17u16.to_be_bytes());     // size
    opts.push(1u8);                                   // OPTION_TYPE_LZRECEIVE
    opts.extend_from_slice(&gas.to_be_bytes());       // gas limit
    opts
}
```

---

## OFT vs OFT Adapter Behavior

|  | OFT (Katana — vbUSDC) | OFT Adapter (Ethereum) |
|---|---|---|
| `token()` | `address(this)` | underlying ERC-20 address |
| `approvalRequired()` | `false` | `true` |
| On send | **Burns** tokens | **Locks** tokens into adapter |
| On receive | **Mints** tokens | **Unlocks** tokens to recipient |

---

## Rebalancing Call Flows

### Katana → Ethereum (send vbUSDC back)

```
1. quoteSend(sendParam, false)  on Share OFT (Katana)    → MessagingFee
2. send(sendParam, fee, solver) on Share OFT (Katana)    → burns vbUSDC
   ↳ msg.value = fee.nativeFee
3. Track via MessagingReceipt.guid on LayerZero Scan
4. ~4-5 min: shares arrive at OFT Adapter on Ethereum (auto-unlock)
5. (Optional) Redeem shares from ERC-4626 vault → USDC
```

### Ethereum → Katana (deposit USDC, bridge as vbUSDC)

```
1. approve(Composer, amount)     on USDC (Ethereum)
2. OVault Composer deposits USDC into vault → receives shares
3. Composer bridges shares via OFT Adapter → sends LZ message
   ↳ msg.value = fee.nativeFee
4. Track via MessagingReceipt.guid on LayerZero Scan
5. ~4-5 min: vbUSDC minted on Katana to solver address
```

### Address Encoding for `SendParam.to`

Recipient address must be left-padded to 32 bytes:

```rust
fn address_to_bytes32(addr: Address) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[12..].copy_from_slice(addr.as_slice());
    b
}
```
