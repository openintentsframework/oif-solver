//! Live integration test against the destination chain's RPC.
//!
//! Skipped unless `OIF_LIVE_RPC=1`. The test verifies two things against
//! a real RPC node:
//!   1. Without the `stateOverride`, `eth_estimateGas` for the synthetic
//!      Hyperlane post-fill `submit(...)` call reverts (the contract
//!      requires a recorded fill — typically `0x0ef392ae` =
//!      `FillNotRecorded`).
//!   2. With the `stateOverride` produced by
//!      `post_fill_overrides::build_post_fill_state_override`, the same
//!      `eth_estimateGas` returns a realistic units value.
//!
//! Required env vars:
//!   - `OIF_LIVE_RPC=1`
//!   - `OIF_TEST_DEST_RPC_URL` — RPC for the destination chain
//!     (where eth_estimateGas runs). MUST honor `stateOverride`.
//!   - `OIF_TEST_DEST_CHAIN_ID`    — destination chain id (e.g. 1, 747474).
//!   - `OIF_TEST_ORIGIN_CHAIN_ID` — origin chain id, used as
//!     `destinationDomain` in the synthetic Hyperlane `submit(...)` call.
//!   - `OIF_TEST_OUTPUT_SETTLER`   — OutputSettler address on dest chain.
//!   - `OIF_TEST_OUTPUT_ORACLE` — Hyperlane output oracle address on
//!     dest chain (= `to` of the submit tx).
//!   - `OIF_TEST_RECIPIENT_ORACLE` — Hyperlane input oracle address on
//!     origin chain. Just an address arg in the synthetic submit() call;
//!     no RPC connection to origin.
//!
//! Run for Katana → Ethereum (post-fill on Ethereum):
//!   OIF_LIVE_RPC=1 \
//!   OIF_TEST_DEST_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/<key> \
//!   OIF_TEST_DEST_CHAIN_ID=1 \
//!   OIF_TEST_ORIGIN_CHAIN_ID=747474 \
//!   OIF_TEST_OUTPUT_SETTLER=0x... \
//!   OIF_TEST_OUTPUT_ORACLE=0x... \
//!   OIF_TEST_RECIPIENT_ORACLE=0x... \
//!   cargo test -p solver-core --features test-helpers \
//!       --test post_fill_override_integration -- --nocapture
//!
//! Run for Ethereum → Katana (post-fill on Katana):
//!   OIF_LIVE_RPC=1 \
//!   OIF_TEST_DEST_RPC_URL=<katana_rpc_url> \
//!   OIF_TEST_DEST_CHAIN_ID=747474 \
//!   OIF_TEST_ORIGIN_CHAIN_ID=1 \
//!   OIF_TEST_OUTPUT_SETTLER=0x... \
//!   OIF_TEST_OUTPUT_ORACLE=0x... \
//!   OIF_TEST_RECIPIENT_ORACLE=0x... \
//!   cargo test -p solver-core --features test-helpers \
//!       --test post_fill_override_integration -- --nocapture
//!
//! NOTE: this test exercises ONLY public seams of `solver-core`. It does
//! not depend on `cost_profit.rs` private helpers. The Hyperlane oracle
//! ABI (`submit`/`quoteGasPayment`) and the FillDescription encoding are
//! re-declared inline. **Duplication risk:** if either of these shapes
//! change in `crates/solver-core/src/engine/cost_profit.rs`, this file
//! must be updated to match. The unit/property tests in
//! `post_fill_overrides.rs` cover the storage-layout side; the encoding
//! side is verified live by this test.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_sol_types::{sol, SolCall};
use async_trait::async_trait;
use solver_core::engine::post_fill_overrides::{
	build_post_fill_state_override, estimate_post_fill_with_overrides_for_test,
};
use solver_delivery::{DeliveryError, DeliveryInterface, FeeParams};
use solver_types::{
	Address as SolverAddress, ConfigSchema, Schema, Transaction as SolverTransaction,
};

fn skip_unless_live() -> bool {
	if std::env::var("OIF_LIVE_RPC").ok().as_deref() != Some("1") {
		eprintln!(
			"Skipping post_fill_override_integration: set OIF_LIVE_RPC=1 \
			(plus OIF_TEST_DEST_RPC_URL / OIF_TEST_DEST_CHAIN_ID / \
			OIF_TEST_ORIGIN_CHAIN_ID / OIF_TEST_OUTPUT_SETTLER / \
			OIF_TEST_OUTPUT_ORACLE / OIF_TEST_RECIPIENT_ORACLE) to run"
		);
		return true;
	}
	false
}

fn require_env(name: &str) -> String {
	std::env::var(name).unwrap_or_else(|_| panic!("missing required env var: {name}"))
}

// -------------------------------------------------------------------------
// Hyperlane oracle ABI — duplicated from cost_profit.rs intentionally so
// the integration test depends only on public seams. See top-of-file note.
// -------------------------------------------------------------------------
sol! {
	interface IHyperlaneOracleForQuote {
		function submit(
			uint32 destinationDomain,
			address recipientOracle,
			uint256 gasLimit,
			bytes calldata customMetadata,
			address source,
			bytes[] calldata payloads
		) external payable;

		function quoteGasPayment(
			uint32 destinationDomain,
			address recipientOracle,
			uint256 gasLimit,
			bytes calldata customMetadata,
			address source,
			bytes[] calldata payloads
		) external view returns (uint256);
	}
}

/// Mirror of `cost_profit::quote_hyperlane_message_gas_limit`. Duplicated
/// for test isolation — see top-of-file note.
fn quote_hyperlane_message_gas_limit(payload_size: usize) -> U256 {
	let base_gas: usize = 200_000;
	let gas_per_byte: usize = 16;
	let buffer: usize = 100_000;
	U256::from(base_gas + (payload_size * gas_per_byte) + buffer)
}

/// Mirror of `cost_profit::address20_to_bytes32`.
fn address20_to_bytes32(addr20: &[u8]) -> [u8; 32] {
	let mut buf = [0u8; 32];
	let len = addr20.len().min(20);
	buf[32 - len..].copy_from_slice(&addr20[..len]);
	buf
}

/// Mirror of `cost_profit::encode_quote_hyperlane_fill_description`.
/// Duplicated for test isolation — see top-of-file note.
#[allow(clippy::too_many_arguments)]
fn encode_quote_hyperlane_fill_description(
	solver_identifier: [u8; 32],
	order_id: [u8; 32],
	timestamp: u32,
	token: [u8; 32],
	amount: U256,
	recipient: [u8; 32],
	call_data: Vec<u8>,
	context: Vec<u8>,
) -> Vec<u8> {
	assert!(
		call_data.len() <= u16::MAX as usize,
		"test call_data too large"
	);
	assert!(context.len() <= u16::MAX as usize, "test context too large");
	let mut payload =
		Vec::with_capacity(32 + 32 + 4 + 32 + 32 + 32 + 2 + call_data.len() + 2 + context.len());
	payload.extend_from_slice(&solver_identifier);
	payload.extend_from_slice(&order_id);
	payload.extend_from_slice(&timestamp.to_be_bytes());
	payload.extend_from_slice(&token);
	payload.extend_from_slice(&amount.to_be_bytes::<32>());
	payload.extend_from_slice(&recipient);
	payload.extend_from_slice(&(call_data.len() as u16).to_be_bytes());
	payload.extend_from_slice(&call_data);
	payload.extend_from_slice(&(context.len() as u16).to_be_bytes());
	payload.extend_from_slice(&context);
	payload
}

// -------------------------------------------------------------------------
// Minimal `DeliveryInterface` impl backed by a single alloy provider. Only
// `estimate_gas` and `estimate_gas_with_overrides` are exercised; every
// other method is `unimplemented!()` because the test does not call them.
// -------------------------------------------------------------------------
struct LiveRpcDelivery {
	provider: alloy_provider::DynProvider,
	chain_id: u64,
}

impl LiveRpcDelivery {
	fn new(rpc_url: &str, chain_id: u64) -> Self {
		let url = rpc_url.parse().expect("valid RPC URL");
		let provider = ProviderBuilder::new().connect_http(url).erased();
		Self { provider, chain_id }
	}
}

struct EmptyConfigSchema;
impl ConfigSchema for EmptyConfigSchema {
	fn validate(&self, _config: &serde_json::Value) -> Result<(), solver_types::ValidationError> {
		Ok(())
	}
}

fn solver_to_alloy_request(tx: SolverTransaction) -> alloy_rpc_types::TransactionRequest {
	let to = tx.to.as_ref().map(|a| {
		let mut buf = [0u8; 20];
		let len = a.0.len().min(20);
		buf[..len].copy_from_slice(&a.0[..len]);
		Address::from(buf)
	});
	let mut req = alloy_rpc_types::TransactionRequest::default()
		.value(tx.value)
		.input(Bytes::from(tx.data).into());
	if let Some(addr) = to {
		req = req.to(addr);
	}
	req
}

#[async_trait]
impl DeliveryInterface for LiveRpcDelivery {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(EmptyConfigSchema)
	}

	async fn submit(
		&self,
		_tx: SolverTransaction,
		_tracking: Option<solver_delivery::TransactionTrackingWithConfig>,
	) -> Result<solver_types::TransactionHash, DeliveryError> {
		unimplemented!("LiveRpcDelivery is read-only — submit() is never called by this test")
	}

	async fn get_receipt(
		&self,
		_hash: &solver_types::TransactionHash,
		_chain_id: u64,
	) -> Result<solver_types::TransactionReceipt, DeliveryError> {
		unimplemented!()
	}

	async fn get_fee_params(&self, _chain_id: u64) -> Result<FeeParams, DeliveryError> {
		unimplemented!()
	}

	async fn get_balance(
		&self,
		_address: &str,
		_token: Option<&str>,
		_chain_id: u64,
	) -> Result<String, DeliveryError> {
		unimplemented!()
	}

	async fn get_allowance(
		&self,
		_owner: &str,
		_spender: &str,
		_token_address: &str,
		_chain_id: u64,
	) -> Result<String, DeliveryError> {
		unimplemented!()
	}

	async fn get_nonce(&self, _address: &str, _chain_id: u64) -> Result<u64, DeliveryError> {
		unimplemented!()
	}

	async fn get_block_number(&self, _chain_id: u64) -> Result<u64, DeliveryError> {
		unimplemented!()
	}

	async fn estimate_gas(&self, tx: SolverTransaction) -> Result<u64, DeliveryError> {
		assert_eq!(
			tx.chain_id, self.chain_id,
			"tx chain_id != provider chain_id"
		);
		let request = solver_to_alloy_request(tx);
		self.provider
			.estimate_gas(request)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to estimate gas: {e}")))
	}

	async fn estimate_gas_with_overrides(
		&self,
		tx: SolverTransaction,
		state_override: alloy_rpc_types::state::StateOverride,
	) -> Result<u64, DeliveryError> {
		assert_eq!(
			tx.chain_id, self.chain_id,
			"tx chain_id != provider chain_id"
		);
		let request = solver_to_alloy_request(tx);
		self.provider
			.estimate_gas(request)
			.overrides(state_override)
			.await
			.map_err(|e| {
				DeliveryError::Network(format!("Failed to estimate gas with overrides: {e}"))
			})
	}

	async fn eth_call(&self, _tx: SolverTransaction) -> Result<Bytes, DeliveryError> {
		unimplemented!()
	}

	async fn tx_exists(
		&self,
		_hash: &solver_types::TransactionHash,
		_chain_id: u64,
	) -> Result<bool, DeliveryError> {
		unimplemented!()
	}

	async fn get_logs(
		&self,
		_chain_id: u64,
		_filter: solver_types::LogFilter,
	) -> Result<Vec<solver_types::Log>, DeliveryError> {
		unimplemented!()
	}
}

// `Schema` is referenced via `ConfigSchema`; suppress unused-import lint
// in case the prelude path changes — keeps the import for clarity.
#[allow(dead_code)]
fn _force_schema_use(_s: Schema) {}

#[tokio::test]
async fn post_fill_estimate_with_overrides_returns_realistic_units() {
	if skip_unless_live() {
		return;
	}

	let dest_rpc_url = require_env("OIF_TEST_DEST_RPC_URL");
	let dest_chain_id: u64 = require_env("OIF_TEST_DEST_CHAIN_ID")
		.parse()
		.expect("OIF_TEST_DEST_CHAIN_ID must be u64");
	let origin_chain_id: u64 = require_env("OIF_TEST_ORIGIN_CHAIN_ID")
		.parse()
		.expect("OIF_TEST_ORIGIN_CHAIN_ID must be u64");
	let origin_domain: u32 = std::env::var("OIF_TEST_ORIGIN_DOMAIN")
		.ok()
		.map(|value| value.parse().expect("OIF_TEST_ORIGIN_DOMAIN must be u32"))
		.unwrap_or_else(|| {
			u32::try_from(origin_chain_id).expect(
				"OIF_TEST_ORIGIN_CHAIN_ID must fit u32 when OIF_TEST_ORIGIN_DOMAIN is unset",
			)
		});
	let output_settler: Address = require_env("OIF_TEST_OUTPUT_SETTLER")
		.parse()
		.expect("OIF_TEST_OUTPUT_SETTLER must be a 0x... address");
	let output_oracle: Address = require_env("OIF_TEST_OUTPUT_ORACLE")
		.parse()
		.expect("OIF_TEST_OUTPUT_ORACLE must be a 0x... address");
	let recipient_oracle: Address = require_env("OIF_TEST_RECIPIENT_ORACLE")
		.parse()
		.expect("OIF_TEST_RECIPIENT_ORACLE must be a 0x... address");

	// --- Build the synthetic FillDescription payload ---------------------
	//
	// Mirrors `cost_profit::build_post_fill_tx_for_quote` for the parts
	// that determine gas units. The token/amount/recipient values are
	// arbitrary but consistent: any valid 32-byte values work for
	// estimation, since the override pre-populates the fill record keyed
	// only by (orderId, outputHash).
	let solver_identifier_addr = Address::repeat_byte(0xAA);
	let solver_identifier = address20_to_bytes32(solver_identifier_addr.as_slice());
	let synthetic_order_id_bytes = [0u8; 32];
	// Use a concrete past-but-recent timestamp so the override's stored
	// `keccak256(solver || timestamp)` matches what the contract
	// reconstructs from the payload's timestamp field.
	let fill_timestamp: u32 = 1_700_000_000;
	let token_addr = Address::repeat_byte(0xBB);
	let token_bytes32 = address20_to_bytes32(token_addr.as_slice());
	let recipient_addr = Address::repeat_byte(0xCC);
	let recipient_bytes32 = address20_to_bytes32(recipient_addr.as_slice());
	let amount = U256::from(1_000_000u64);

	let fill_description = encode_quote_hyperlane_fill_description(
		solver_identifier,
		synthetic_order_id_bytes,
		fill_timestamp,
		token_bytes32,
		amount,
		recipient_bytes32,
		Vec::new(),
		Vec::new(),
	);

	// --- Recompute outputHash ------------------------------------------
	//
	// `_isPayloadValid` on the OutputSettler computes:
	//   keccak256(abi.encodePacked(
	//       msg.sender (= output oracle, padded to bytes32),
	//       address(this) (= output settler, padded to bytes32),
	//       block.chainid (= dest_chain_id, as uint256),
	//       payload[68:]  (= the FillDescription's common payload)
	//   ))
	let oracle_padded = address20_to_bytes32(output_oracle.as_slice());
	let settler_padded = address20_to_bytes32(output_settler.as_slice());
	let common_payload = &fill_description[68..];
	let mut hash_buf = Vec::with_capacity(32 + 32 + 32 + common_payload.len());
	hash_buf.extend_from_slice(&oracle_padded);
	hash_buf.extend_from_slice(&settler_padded);
	hash_buf.extend_from_slice(&U256::from(dest_chain_id).to_be_bytes::<32>());
	hash_buf.extend_from_slice(common_payload);
	let output_hash: B256 = keccak256(&hash_buf);

	// --- Build the synthetic submit() tx --------------------------------
	let payloads = vec![fill_description];
	let total_payload_size: usize = payloads.iter().map(|p| p.len()).sum();
	let message_gas_limit = quote_hyperlane_message_gas_limit(total_payload_size);

	// Quote the gas payment; some oracle deployments require msg.value
	// even during eth_estimateGas. We attach whatever quoteGasPayment
	// returns. If the call itself reverts, the test fails fast — which
	// IS informative: it says the destination oracle's deployment is
	// not the expected shape for this test.
	let provider_for_quote = ProviderBuilder::new()
		.connect_http(dest_rpc_url.parse().expect("valid RPC URL"))
		.erased();

	let quote_call_data = IHyperlaneOracleForQuote::quoteGasPaymentCall {
		destinationDomain: origin_domain,
		recipientOracle: recipient_oracle,
		gasLimit: message_gas_limit,
		customMetadata: Bytes::new(),
		source: output_settler,
		payloads: payloads.clone().into_iter().map(Into::into).collect(),
	};
	let quote_request = alloy_rpc_types::TransactionRequest::default()
		.to(output_oracle)
		.input(Bytes::from(quote_call_data.abi_encode()).into());
	let quote_result = provider_for_quote
		.call(quote_request)
		.await
		.expect("quoteGasPayment call should succeed against the oracle on the destination chain");
	let gas_payment = U256::from_be_slice(quote_result.as_ref());

	// --- Build the override-enabled DeliveryInterface ------------------
	let delivery = LiveRpcDelivery::new(&dest_rpc_url, dest_chain_id);

	let submit_call_data = IHyperlaneOracleForQuote::submitCall {
		destinationDomain: origin_domain,
		recipientOracle: recipient_oracle,
		gasLimit: message_gas_limit,
		customMetadata: Bytes::new(),
		source: output_settler,
		payloads: payloads.into_iter().map(Into::into).collect(),
	};
	let synthetic_tx = SolverTransaction {
		to: Some(SolverAddress(output_oracle.as_slice().to_vec())),
		data: submit_call_data.abi_encode(),
		value: gas_payment,
		chain_id: dest_chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	};

	let solver_b256 = B256::from(solver_identifier);
	let order_id_b256 = B256::from(synthetic_order_id_bytes);
	let state_override = build_post_fill_state_override(
		output_settler,
		order_id_b256,
		output_hash,
		solver_b256,
		fill_timestamp,
	);

	// --- Assertion 1: WITHOUT overrides, estimate must revert -----------
	//
	// Proves the override is actually doing the work — without a recorded
	// fill, the contract must reject the submit call (typically with the
	// `0x0ef392ae` FillNotRecorded selector). We accept any error here:
	// asserting on the exact selector is fragile across oracle versions,
	// and the contract may also revert for other reasons (e.g. ISM
	// validation). What matters is that the call DOES revert without
	// the override.
	let no_override_result = delivery.estimate_gas(synthetic_tx.clone()).await;
	assert!(
		no_override_result.is_err(),
		"estimate_gas without override should revert (typically 0x0ef392ae \
		FillNotRecorded). Got Ok({no_override_result:?}) — the override is \
		not actually exercising a no-fill code path, or the oracle deployment \
		does not match the expected shape."
	);
	let err_msg = format!("{}", no_override_result.unwrap_err());
	eprintln!("[expected] estimate_gas without override errored as: {err_msg}");
	// Loose check: alloy maps `eth_estimateGas` reverts to messages that
	// contain "execution reverted" or the JSON-RPC error code path. Either
	// signal is sufficient evidence; we just want to confirm it's a revert
	// vs. a timeout / network failure.
	assert!(
		err_msg.to_lowercase().contains("revert")
			|| err_msg.contains("0x0ef392ae")
			|| err_msg.contains("FillNotRecorded"),
		"expected a revert error from estimate_gas without override; got: {err_msg}"
	);

	// --- Assertion 2: WITH override, estimate must succeed -------------
	let units = estimate_post_fill_with_overrides_for_test(&delivery, synthetic_tx, state_override)
		.await
		.expect("estimate_gas WITH override should succeed");

	eprintln!("[ok] estimate_gas with override returned {units} units");
	// Initial sanity range — tighten after the first real run by capturing
	// the actual value here. Hyperlane post-fill submit on mainnet is
	// typically in the 100k–500k range; bound generously.
	assert!(
		(50_000..1_000_000).contains(&units),
		"override-enabled gas estimate {units} is outside the sanity range \
		[50_000, 1_000_000); update the bounds (and capture the realistic \
		range per direction) once the live run reveals the real value"
	);
}
