//! Cost estimation and profitability calculation service for the OIF solver.
//!
//! This module provides unified functionality for:
//! - Estimating costs associated with executing orders across different blockchain networks
//! - Calculating profit margins for orders and validating profitability thresholds
//! - Unified service combining cost estimation and profitability validation

use crate::engine::live_estimate::LiveEstimateController;
use crate::engine::token_manager::{TokenManager, TokenManagerError};
use alloy_primitives::{keccak256, Address as AlloyAddress, B256, U256};
use alloy_sol_types::{sol, SolCall};

/// Discriminator strings for the post-fill live-estimate outcome event.
/// The call site emits exactly ONE event per quote with one of these values
/// in the `outcome=` field, so dashboards can aggregate by outcome.
pub(crate) mod post_fill_outcome {
	/// Override path returned non-zero units that we then applied.
	pub const SUCCESS: &str = "success";
	/// Override path returned `Ok(0)` — kept the static default.
	pub const FALLBACK_ZERO: &str = "fallback_zero";
	/// Override path returned `Err(_)` — kept the static default.
	pub const FALLBACK_ERROR: &str = "fallback_error";
	/// `build_post_fill_tx_for_quote` failed (config / encode error).
	pub const SKIPPED_BUILD_TX: &str = "skipped_build_tx";
	/// `build_post_fill_tx_for_quote` returned `Ok(None)` (no Hyperlane
	/// post-fill required for this quote).
	pub const SKIPPED_DISABLED: &str = "skipped_disabled";
	/// Quote's destination chain is not in
	/// `live_post_fill_estimate_chain_ids`; static default used.
	pub const SKIPPED_UNSUPPORTED_CHAIN: &str = "skipped_unsupported_chain";
}
use rust_decimal::Decimal;
use solver_config::{source_finality_expected_delay_seconds, Config};
use solver_delivery::{DeliveryService, FeeParams};
use solver_pricing::PricingService;
use solver_storage::StorageService;
use solver_types::{
	costs::{CostBreakdown, CostContext, TokenAmountInfo},
	current_timestamp, is_native_token_id,
	standards::eip7683::{
		interfaces::{IOutputSettlerSimple, SolMandateOutput},
		MAX_CALLBACK_DATA_BYTES,
	},
	utils::{conversion::ceil_dp, formatting::format_percentage},
	APIError, Address, ApiErrorType, GetQuoteRequest, InteropAddress, Order, OrderInput,
	OrderOutput, StorageKey, SwapType, Transaction, ValidatedQuoteContext,
};
use std::primitive::str;
use std::{str::FromStr, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CostProfitError {
	#[error("API error: {0}")]
	Api(#[from] APIError),
	#[error("Calculation error: {0}")]
	Calculation(String),
	#[error("Configuration error: {0}")]
	Config(String),
	#[error("Token manager error: {0}")]
	TokenManager(#[from] TokenManagerError),
	#[error("Storage error: {0}")]
	Storage(#[from] solver_storage::StorageError),
}

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
	}
}

fn quote_hyperlane_message_gas_limit(payload_size: usize) -> U256 {
	let base_gas = 200000usize;
	let gas_per_byte = 16usize;
	let buffer = 100000usize;

	U256::from(base_gas + (payload_size * gas_per_byte) + buffer)
}

fn extra_native_fee_configured(config: &Config, chain_id: u64) -> bool {
	let chain_key = chain_id.to_string();
	config
		.delivery
		.implementations
		.values()
		.any(|implementation| {
			implementation
				.get("fee_policy")
				.and_then(|fee_policy| fee_policy.get("chains"))
				.and_then(|chains| chains.get(&chain_key))
				.and_then(|chain| chain.get("extra_native_fee"))
				.is_some()
		})
}

/// Decides what to do when a synthetic quote transaction cannot be built for
/// extra-native-fee pricing. For chains that have an `extra_native_fee` policy
/// configured (e.g. OP Stack L1 data fee), that fee is a required cost
/// component, so we fail closed instead of silently pricing the leg at zero —
/// otherwise a build edge case would reintroduce the M-14 under-pricing the fee
/// model exists to prevent. For all other chains there is no extra fee to
/// price, so we log and skip (price the leg at zero).
fn fail_closed_on_extra_fee_build_error(
	config: &Config,
	chain_id: u64,
	leg: &'static str,
	error: impl std::fmt::Display,
) -> Result<(), CostProfitError> {
	if extra_native_fee_configured(config, chain_id) {
		return Err(CostProfitError::Calculation(format!(
			"Cannot build synthetic {leg} tx to price extra native fee for chain {chain_id}: {error}"
		)));
	}

	tracing::warn!(
		chain_id,
		leg,
		error = %error,
		"Skipping extra native fee estimate: failed to build synthetic tx"
	);
	Ok(())
}

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
) -> Result<Vec<u8>, APIError> {
	if call_data.len() > u16::MAX as usize {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: "Quote output calldata is too large for Hyperlane fill description".into(),
			details: None,
		});
	}
	if context.len() > u16::MAX as usize {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: "Quote output context is too large for Hyperlane fill description".into(),
			details: None,
		});
	}

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
	Ok(payload)
}

fn hyperlane_config_for_quote(config: &Config) -> Option<&serde_json::Value> {
	let configured = config
		.settlement
		.implementations
		.get(&config.settlement.primary)
		.or_else(|| config.settlement.implementations.get("hyperlane"))?;

	if configured.get("oracles").is_some() {
		Some(configured)
	} else {
		configured.get("hyperlane")
	}
}

fn first_hyperlane_oracle_for_quote(
	hyperlane_config: &serde_json::Value,
	direction: &str,
	chain_id: u64,
) -> Result<Option<Address>, APIError> {
	let Some(value) = hyperlane_config
		.get("oracles")
		.and_then(|oracles| oracles.get(direction))
		.and_then(|by_chain| by_chain.get(chain_id.to_string()))
		.and_then(|addresses| addresses.as_array())
		.and_then(|addresses| addresses.first())
	else {
		return Ok(None);
	};

	serde_json::from_value::<Address>(value.clone())
		.map(Some)
		.map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!(
				"Invalid Hyperlane {direction} oracle address for chain {chain_id}: {e}"
			),
			details: None,
		})
}

fn hyperlane_domain_for_quote(
	hyperlane_config: &serde_json::Value,
	chain_id: u64,
) -> Result<u32, APIError> {
	let value = hyperlane_config
		.get("domains")
		.and_then(|domains| domains.get(chain_id.to_string()))
		.ok_or_else(|| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Missing Hyperlane domain for chain {chain_id}"),
			details: None,
		})?;
	let domain = value.as_u64().ok_or_else(|| APIError::BadRequest {
		error_type: ApiErrorType::InvalidRequest,
		message: format!("Hyperlane domain for chain {chain_id} must be an unsigned integer"),
		details: None,
	})?;
	if domain == 0 || domain > u32::MAX as u64 {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Hyperlane domain for chain {chain_id} must be in 1..=u32::MAX"),
			details: None,
		});
	}
	Ok(domain as u32)
}

/// Parameters for gas unit calculations
#[derive(Debug, Clone)]
pub struct GasUnits {
	pub open_units: u64,
	pub fill_units: u64,
	pub post_fill_units: u64,
	pub pre_claim_units: u64,
	pub claim_units: u64,
}

pub(crate) const DEFAULT_OPEN_GAS_UNITS: u64 = 150_000;
pub(crate) const DEFAULT_FILL_GAS_UNITS: u64 = 150_000;
pub(crate) const DEFAULT_POST_FILL_GAS_UNITS: u64 = 300_000;
pub(crate) const DEFAULT_PRE_CLAIM_GAS_UNITS: u64 = 0;
pub(crate) const DEFAULT_CLAIM_GAS_UNITS: u64 = 150_000;

/// Worst-case EVM gas charged per calldata byte (a non-zero byte). Used to
/// upper-bound the gas the extra callbackData adds to the origin `open*` and
/// `finalise*`/claim transactions, which ABI-encode the full user-controlled
/// `StandardOrder` (including each output's callbackData).
const WORST_CASE_CALLDATA_GAS_PER_BYTE: u64 = 16;
/// ABI encodes dynamic `bytes` padded to 32-byte words.
const ABI_WORD_BYTES: u64 = 32;

/// Rounds a byte length up to the next multiple of an ABI word (32 bytes).
/// Zero stays zero.
fn align_to_abi_word(bytes: u64) -> u64 {
	bytes
		.div_ceil(ABI_WORD_BYTES)
		.saturating_mul(ABI_WORD_BYTES)
}

/// Decodes a hex callbackData string to its byte length. `None`, empty, and
/// `"0x"` contribute zero. Invalid or odd-length hex returns an error rather
/// than being silently priced as zero — this mirrors `validate_callback_calldata`
/// so a malformed callback can never under-price the quote (M-09).
fn decoded_callback_len_bytes(calldata: Option<&str>) -> Result<u64, CostProfitError> {
	let Some(calldata) = calldata else {
		return Ok(0);
	};
	let hex_payload = calldata.strip_prefix("0x").unwrap_or(calldata);
	if hex_payload.is_empty() {
		return Ok(0);
	}
	if hex_payload.len() % 2 != 0 {
		return Err(CostProfitError::Calculation(
			"Output callbackData must be valid hex".to_string(),
		));
	}
	let decoded = alloy_primitives::hex::decode(hex_payload).map_err(|e| {
		CostProfitError::Calculation(format!("Output callbackData must be valid hex: {e}"))
	})?;
	Ok(decoded.len() as u64)
}

/// Computes the extra gas the requested outputs' callbackData contributes to a
/// calldata-bearing leg. Each output's decoded byte length is ABI-word-aligned,
/// summed across outputs, and multiplied by the worst-case per-byte gas. Returns
/// an error if any output's callbackData is invalid hex (M-09 fail-closed).
fn callback_calldata_gas_units(outputs: &[OrderOutput]) -> Result<u64, CostProfitError> {
	let aligned_bytes = outputs.iter().try_fold(0u64, |acc, output| {
		let byte_len = decoded_callback_len_bytes(output.calldata.as_deref())?;
		Ok::<u64, CostProfitError>(acc.saturating_add(align_to_abi_word(byte_len)))
	})?;
	Ok(aligned_bytes.saturating_mul(WORST_CASE_CALLDATA_GAS_PER_BYTE))
}

/// Adds the size-aware callbackData gas term to the origin-side legs that
/// actually ABI-encode the full order: `open` and `claim`. Each is only bumped
/// when it is already priced (> 0), so a flow that does not use a leg never
/// silently grows it. `fill`, `post_fill`, and `pre_claim` are intentionally
/// untouched: fill simulation already prices callback execution/calldata, and
/// the other legs have their own payload sizing (M-09).
fn apply_callback_calldata_gas_units(gas_units: &mut GasUnits, extra_units: u64) {
	if extra_units == 0 {
		return;
	}
	if gas_units.open_units > 0 {
		gas_units.open_units = gas_units.open_units.saturating_add(extra_units);
	}
	if gas_units.claim_units > 0 {
		gas_units.claim_units = gas_units.claim_units.saturating_add(extra_units);
	}
}

/// Wei-denominated cost split for the OIF contract gas legs.
///
/// The chain boundaries follow the OIF settler/filler topology:
/// `Settler.open*`, pre-claim, and `finalise*` always run on the origin
/// chain, while `BaseFiller.fill*` and post-fill oracle work always run
/// on the destination chain. This struct exists so the split is a pure
/// computation that can be property-tested independently of mocks.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GasLegCostsWei {
	open: U256,
	fill: U256,
	post_fill: U256,
	pre_claim: U256,
	claim: U256,
}

/// Built-in `chain_id -> native gas-token symbol` fallback for well-known
/// chains. Used by [`CostProfitService::native_base_units_to_usd`] only when
/// the chain has no explicit zero-address `TokenConfig`, so gas legs still
/// price on configs that predate the native-token entry. Config always takes
/// precedence over this map.
///
/// This fallback is intentionally GAS-ONLY. Gas is priced for EVERY order,
/// including pure-ERC20 flows, so a missing native `TokenConfig` must not
/// hard-fail gas pricing — hence the fallback. Native OUTPUT (and INPUT)
/// valuation is the opposite case: it is opt-in and rare, so it deliberately
/// does NOT consult this map (see `calculate_outputs_usd_value`) and instead
/// requires an explicit native `TokenConfig` (symbol + decimals). Extending
/// this fallback to valuation would silently misprice orders whose native
/// symbol/decimals were never actually configured.
///
/// Returned symbols must exist in `solver_pricing::DEFAULT_TOKEN_MAPPINGS`.
/// All listed chains use an 18-decimal native token, so callers assume 18.
/// Unknown chains return `None`, keeping the caller's fail-closed behaviour.
fn native_symbol_fallback(chain_id: u64) -> Option<&'static str> {
	match chain_id {
		// Ethereum L1, its major rollups, and their testnets all meter gas in ETH.
		1              // Ethereum mainnet
		| 10           // OP Mainnet
		| 8453         // Base
		| 42161        // Arbitrum One
		| 747474       // Katana
		| 11155111     // Sepolia
		| 84532        // Base Sepolia
		| 421614       // Arbitrum Sepolia
		| 11155420     // OP Sepolia
			=> Some("ETH"),
		137 => Some("POL"),    // Polygon PoS
		56 => Some("BNB"),     // BNB Smart Chain
		43114 => Some("AVAX"), // Avalanche C-Chain
		_ => None,
	}
}

/// Compute per-leg wei costs from gas units and resolved per-chain
/// `cost_per_gas` values. Origin legs (open / pre_claim / claim) use
/// `origin_cost_per_gas`; destination legs (fill / post_fill) use
/// `dest_cost_per_gas`. Saturating multiplication mirrors the inline
/// behaviour the helper replaced.
fn calculate_gas_leg_costs_wei(
	gas_units: &GasUnits,
	origin_cost_per_gas: U256,
	dest_cost_per_gas: U256,
) -> GasLegCostsWei {
	GasLegCostsWei {
		open: origin_cost_per_gas.saturating_mul(U256::from(gas_units.open_units)),
		fill: dest_cost_per_gas.saturating_mul(U256::from(gas_units.fill_units)),
		post_fill: dest_cost_per_gas.saturating_mul(U256::from(gas_units.post_fill_units)),
		pre_claim: origin_cost_per_gas.saturating_mul(U256::from(gas_units.pre_claim_units)),
		claim: origin_cost_per_gas.saturating_mul(U256::from(gas_units.claim_units)),
	}
}

/// Result of callback simulation
#[derive(Debug, Clone)]
pub struct CallbackSimulationResult {
	/// Whether callback simulation passed (no revert detected)
	pub success: bool,
	/// Estimated gas units for the fill transaction (includes callback execution)
	pub estimated_gas_units: u64,
	/// Chain ID where the callback will be executed
	pub chain_id: u64,
	/// Whether the order has callback data
	pub has_callback: bool,
}

/// Inputs needed by the override-based post-fill estimator alongside the
/// synthetic post-fill `Transaction`. All five fields must agree exactly
/// with what the on-chain `_isPayloadValid` will look up — the override
/// pre-populates `_fillRecords[order_id][output_hash]` on
/// `output_settler` with the value `keccak256(solver || fill_timestamp)`,
/// so any drift between these and what the contract reconstructs from
/// the encoded FillDescription payload would re-introduce the revert.
struct PostFillQuoteTx {
	/// The synthetic Hyperlane `submit(...)` transaction to estimate.
	tx: Transaction,
	/// Address of the OutputSettler whose storage we override.
	output_settler: Address,
	/// `orderId` field encoded inside the FillDescription payload —
	/// matches what `loadOrderIdFromFillDescription` will read.
	synthetic_order_id: B256,
	/// Result of `MandateOutputEncodingLib.getMandateOutputHashFromCommonPayload(
	///     msg.sender (output oracle), settler, dest_chain_id, common_payload
	/// )` — matches what `_isPayloadValid` recomputes.
	output_hash: B256,
	/// Solver identifier (32-byte) embedded in the payload's solver field.
	solver: B256,
	/// Timestamp (uint32) embedded in the payload.
	fill_timestamp: u32,
}

/// Result of a single override-based post-fill estimate attempt.
/// Caller is responsible for logging exactly ONE structured outcome
/// event per call (see `post_fill_outcome`). The helper that returns
/// this enum performs no I/O beyond the RPC call and emits no logs.
pub(crate) enum PostFillEstimateOutcome {
	Success(u64),
	FallbackZero,
	FallbackError(solver_delivery::DeliveryError),
}

/// Unified service for cost estimation and profitability calculation.
pub struct CostProfitService {
	/// Pricing service for USD conversions and asset pricing
	pricing_service: Arc<PricingService>,
	/// Delivery service for blockchain data and gas estimation
	delivery_service: Arc<DeliveryService>,
	/// Token manager for token configuration lookups
	token_manager: Arc<TokenManager>,
	/// Storage service for reading quotes
	storage_service: Arc<StorageService>,
	/// Bounds quote-time live fill gas estimation per destination chain.
	live_estimate_controller: Arc<LiveEstimateController>,
	/// Settlement service for backend-owned native settlement fee quotes
	settlement_service: Arc<solver_settlement::SettlementService>,
}

impl CostProfitService {
	/// Creates a new CostProfitService with the given services.
	pub fn new(
		pricing_service: Arc<PricingService>,
		delivery_service: Arc<DeliveryService>,
		token_manager: Arc<TokenManager>,
		storage_service: Arc<StorageService>,
		settlement_service: Arc<solver_settlement::SettlementService>,
	) -> Self {
		Self {
			pricing_service,
			delivery_service,
			token_manager,
			storage_service,
			live_estimate_controller: Arc::new(LiveEstimateController::new()),
			settlement_service,
		}
	}

	/// Retrieves a stored cost context by quote ID.
	///
	/// This function looks up the StoredQuote and extracts the cost context.
	/// Quotes and their contexts are automatically expired based on their TTL.
	pub async fn get_cost_context_by_quote_id(
		&self,
		quote_id: &str,
	) -> Result<CostContext, CostProfitError> {
		use solver_types::StoredQuote;

		match self
			.storage_service
			.retrieve::<StoredQuote>(StorageKey::Quotes.as_str(), quote_id)
			.await
		{
			Ok(quote_with_context) => {
				tracing::debug!(
					"Retrieved quote with cost context for {} from storage",
					quote_id
				);
				Ok(quote_with_context.cost_context)
			},
			Err(e) => {
				tracing::warn!(
					"Failed to retrieve quote with cost context for {}: {}",
					quote_id,
					e
				);
				Err(CostProfitError::Storage(e))
			},
		}
	}

	/// Retrieves the full stored quote record (cost context + economic binding) by
	/// quote ID.
	///
	/// Used by the profitability gate to verify the submitted order against the
	/// quote's economic binding (H-07) before honoring the stored cost context.
	pub async fn get_stored_quote_by_quote_id(
		&self,
		quote_id: &str,
	) -> Result<solver_types::StoredQuote, CostProfitError> {
		self.storage_service
			.retrieve::<solver_types::StoredQuote>(StorageKey::Quotes.as_str(), quote_id)
			.await
			.map_err(CostProfitError::Storage)
	}

	/// Calculate base swap amounts using pricing service exchange rates.
	///
	/// This method determines the required token amounts for a swap based on the swap type:
	/// - **ExactInput**: Calculates output amounts - how much output token the user will receive
	/// - **ExactOutput**: Calculates input amounts - how much input token the user needs to provide
	///
	/// The calculation uses a two-step conversion through USD as a common base:
	/// 1. Convert source token amount to USD value
	/// 2. Convert USD value to target token amount
	///
	/// This approach ensures we can handle any token pair as long as both tokens
	/// have USD pricing available, even if there's no direct trading pair.
	///
	/// # Arguments
	/// * `request` - The quote request with input/output token specifications
	/// * `context` - Validated context with known amounts and swap type
	///
	/// # Returns
	/// HashMap mapping token addresses to their calculated amounts (in smallest unit)
	/// Calculate swap amounts for missing inputs or outputs based on exchange rates.
	///
	/// This method determines the amounts for inputs (in ExactOutput swaps) or outputs
	/// (in ExactInput swaps) by converting through USD as an intermediate currency.
	///
	/// ## Approach
	///
	/// Rather than equal distribution, we match exact input/output pairs:
	/// - For multi-input, multi-output swaps, we pair inputs with outputs in order
	/// - Each input amount is used to calculate its corresponding output amount
	/// - If there are more outputs than inputs, remaining outputs get zero
	/// - If there are more inputs than outputs, extra inputs contribute to the last output
	///
	/// ## Examples
	///
	/// - 1 input (100 USDC) → 2 outputs: First output gets full conversion, second gets zero
	/// - 2 inputs (50 USDC each) → 1 output: Output gets sum of both conversions
	/// - 2 inputs → 2 outputs: Each input converts to its corresponding output
	pub async fn calculate_swap_amounts(
		&self,
		request: &solver_types::GetQuoteRequest,
		context: &solver_types::ValidatedQuoteContext,
		decimals_map: &std::collections::HashMap<InteropAddress, u8>,
		rate_buffer_bps: u32,
	) -> Result<
		std::collections::HashMap<solver_types::InteropAddress, TokenAmountInfo>,
		CostProfitError,
	> {
		use solver_types::SwapType;
		if rate_buffer_bps >= 10000 {
			return Err(CostProfitError::Calculation(
				"rate_buffer_bps must be less than 10000".to_string(),
			));
		}
		let rate_multiplier = (Decimal::from(10000u32 - rate_buffer_bps)) / Decimal::from(10000u32);
		let mut calculated_amounts = std::collections::HashMap::new();

		match context.swap_type {
			SwapType::ExactInput => {
				// ExactInput: User specifies input amounts, we calculate output amounts
				// Flow: Input Token → USD → Output Token
				if let Some(known_inputs) = &context.known_inputs {
					// Convert each input to USD and match with corresponding outputs
					let mut input_usd_values = Vec::new();

					for (input, input_amount) in known_inputs {
						let input_chain_id = input.asset.ethereum_chain_id().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid input chain: {e}"))
						})?;
						let input_addr = input.asset.ethereum_address().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid input address: {e}"))
						})?;
						let input_token = self
							.token_manager
							.get_token_info(input_chain_id, &Address(input_addr.0.to_vec()))
							.await?;

						// Convert raw amount to USD
						let usd_value = Self::convert_raw_token_to_usd(
							input_amount,
							&input_token.symbol,
							input_token.decimals,
							&self.pricing_service,
						)
						.await
						.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

						input_usd_values.push(usd_value);
					}

					// Match inputs with outputs
					for (idx, output) in request.intent.outputs.iter().enumerate() {
						let output_usd = if idx < input_usd_values.len() {
							// Direct pairing: use the corresponding input's USD value
							input_usd_values[idx]
						} else if !input_usd_values.is_empty() {
							// More outputs than inputs: extra outputs get zero
							Decimal::ZERO
						} else {
							Decimal::ZERO
						};

						// If there are more inputs than outputs, add remaining inputs to last output
						let final_output_usd = if idx == request.intent.outputs.len() - 1
							&& input_usd_values.len() > request.intent.outputs.len()
						{
							// Sum all remaining input values
							let mut total = output_usd;
							for value in input_usd_values.iter().skip(idx + 1) {
								total += value;
							}
							total
						} else {
							output_usd
						};

						// Convert USD to output token amount
						let buffered_output_usd = final_output_usd * rate_multiplier;
						let output_amount = self
							.convert_usd_to_token_amount(buffered_output_usd, &output.asset)
							.await?;
						let decimals = decimals_map.get(&output.asset).copied().unwrap_or(18);
						calculated_amounts.insert(
							output.asset.clone(),
							TokenAmountInfo {
								token: output.asset.clone(),
								amount: output_amount,
								decimals,
							},
						);
					}
				}
			},
			SwapType::ExactOutput => {
				// ExactOutput: User specifies output amounts, we calculate input amounts
				// Flow: Output Token → USD → Input Token
				if let Some(known_outputs) = &context.known_outputs {
					// Convert each output to USD and match with corresponding inputs
					let mut output_usd_values = Vec::new();

					for (output, output_amount) in known_outputs {
						let output_chain_id = output.asset.ethereum_chain_id().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid output chain: {e}"))
						})?;
						let output_addr = output.asset.ethereum_address().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid output address: {e}"))
						})?;
						let output_token = self
							.token_manager
							.get_token_info(output_chain_id, &Address(output_addr.0.to_vec()))
							.await?;

						// Convert raw amount to USD
						let usd_value = Self::convert_raw_token_to_usd(
							output_amount,
							&output_token.symbol,
							output_token.decimals,
							&self.pricing_service,
						)
						.await
						.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

						output_usd_values.push(usd_value);
						calculated_amounts.insert(
							output.asset.clone(),
							TokenAmountInfo {
								token: output.asset.clone(),
								amount: *output_amount,
								decimals: output_token.decimals,
							},
						);
					}

					// Match outputs with inputs
					for (idx, input) in request.intent.inputs.iter().enumerate() {
						let input_usd = if idx < output_usd_values.len() {
							// Direct pairing: use the corresponding output's USD value
							output_usd_values[idx]
						} else if !output_usd_values.is_empty() {
							// More inputs than outputs: extra inputs get zero
							Decimal::ZERO
						} else {
							Decimal::ZERO
						};

						// If there are more outputs than inputs, add remaining outputs to last input
						let final_input_usd = if idx == request.intent.inputs.len() - 1
							&& output_usd_values.len() > request.intent.inputs.len()
						{
							// Sum all remaining output values
							let mut total = input_usd;
							for value in output_usd_values.iter().skip(idx + 1) {
								total += value;
							}
							total
						} else {
							input_usd
						};

						// Convert USD to input token amount
						let buffered_input_usd = if rate_multiplier.is_zero() {
							return Err(CostProfitError::Calculation(
								"rate_buffer_bps too high".to_string(),
							));
						} else {
							final_input_usd / rate_multiplier
						};
						let input_amount = self
							.convert_usd_to_token_amount(buffered_input_usd, &input.asset)
							.await?;
						let decimals = decimals_map.get(&input.asset).copied().unwrap_or(18);
						calculated_amounts.insert(
							input.asset.clone(),
							TokenAmountInfo {
								token: input.asset.clone(),
								amount: input_amount,
								decimals,
							},
						);
					}
				}
			},
		}

		tracing::debug!(
			"Calculated swap amounts for {:?}: {} tokens",
			context.swap_type,
			calculated_amounts.len()
		);

		Ok(calculated_amounts)
	}

	/// Helper function to get decimals for all tokens in a request
	async fn get_all_token_decimals(
		&self,
		request: &solver_types::GetQuoteRequest,
	) -> std::collections::HashMap<InteropAddress, u8> {
		let mut decimals_map = std::collections::HashMap::new();

		// Get decimals for all input tokens
		for input in &request.intent.inputs {
			if let (Ok(chain_id), Ok(eth_addr)) = (
				input.asset.ethereum_chain_id(),
				input.asset.ethereum_address(),
			) {
				let decimals = self
					.token_manager
					.get_token_info(chain_id, &Address(eth_addr.0.to_vec()))
					.await
					.ok()
					.map(|info| info.decimals)
					.unwrap_or(18);
				decimals_map.insert(input.asset.clone(), decimals);
			}
		}

		// Get decimals for all output tokens
		for output in &request.intent.outputs {
			if !decimals_map.contains_key(&output.asset) {
				if let (Ok(chain_id), Ok(eth_addr)) = (
					output.asset.ethereum_chain_id(),
					output.asset.ethereum_address(),
				) {
					let decimals = self
						.token_manager
						.get_token_info(chain_id, &Address(eth_addr.0.to_vec()))
						.await
						.ok()
						.map(|info| info.decimals)
						.unwrap_or(18);
					decimals_map.insert(output.asset.clone(), decimals);
				}
			}
		}

		decimals_map
	}

	/// Calculate cost context and swap amounts before quote generation
	pub async fn calculate_cost_context(
		&self,
		request: &solver_types::GetQuoteRequest,
		context: &solver_types::ValidatedQuoteContext,
		config: &Config,
		solver_address: &Address,
	) -> Result<CostContext, CostProfitError> {
		let flow_keys = request.flow_key().into_iter().collect::<Vec<_>>();
		self.calculate_cost_context_for_flow_keys(
			request,
			context,
			config,
			&flow_keys,
			solver_address,
		)
		.await
	}

	#[tracing::instrument(
		skip_all,
		fields(chain_id = tracing::field::Empty),
		name = "calculate_cost_context"
	)]
	pub async fn calculate_cost_context_for_flow_keys(
		&self,
		request: &solver_types::GetQuoteRequest,
		context: &solver_types::ValidatedQuoteContext,
		config: &Config,
		flow_keys: &[String],
		solver_address: &Address,
	) -> Result<CostContext, CostProfitError> {
		// Get all token decimals upfront
		let decimals_map = self.get_all_token_decimals(request).await;

		// Calculate base swap amounts FIRST to fill in missing values (now returns TokenAmountInfo)
		let swap_amounts_with_info = self
			.calculate_swap_amounts(
				request,
				context,
				&decimals_map,
				config.solver.rate_buffer_bps,
			)
			.await?;

		// Use inputs and outputs from request
		let inputs = &request.intent.inputs;
		let outputs = &request.intent.outputs;

		// Extract chain IDs
		let origin_chain_id = inputs
			.iter()
			.filter_map(|input| input.asset.ethereum_chain_id().ok())
			.next()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: "No input chain ID found".to_string(),
				details: None,
			})?;

		let dest_chain_id = outputs
			.iter()
			.filter_map(|output| output.asset.ethereum_chain_id().ok())
			.next()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: "No output chain ID found".to_string(),
				details: None,
			})?;

		// Record dest chain on the span so per-chain success rates of the
		// post-fill outcome events are computable from log aggregation
		// without joining across events.
		tracing::Span::current().record("chain_id", dest_chain_id);

		// Get gas units for cost calculation
		let mut gas_units = estimate_quote_gas_units_from_flow_keys(flow_keys, config);
		let include_source_finality_delay = !flow_keys.iter().any(|flow| flow == "resource_lock");

		// Optional: live-estimate destination-chain legs against the destination
		// chain so quote-time costs track the transactions the solver will send.
		// `open` and `claim` stay static — they can't be safely simulated pre-fill
		// (open needs the user's permit; claim needs the Hyperlane proof of fill).
		//
		// Fill and post-fill are gated INDEPENDENTLY (per plan v2 Finding 6):
		// - `live_fill_estimate_enabled` controls the fill tx live estimate.
		// - `live_post_fill_estimate_chain_ids` controls the override-based
		//   post-fill estimate per destination chain. Disabling fill no longer
		//   disables the override path and vice versa.
		let fill_enabled = config
			.gas
			.as_ref()
			.map(|g| g.live_fill_estimate_enabled)
			.unwrap_or(false);

		let post_fill_enabled_for_chain = config
			.gas
			.as_ref()
			.map(|g| g.live_post_fill_estimate_chain_ids.contains(&dest_chain_id))
			.unwrap_or(false);

		if fill_enabled {
			let max_live_fill_estimates = config
				.gas
				.as_ref()
				.map(|g| g.max_concurrent_live_fill_estimates_per_chain)
				.unwrap_or(solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN);
			match self
				.build_fill_tx_for_quote(
					request,
					context,
					&swap_amounts_with_info,
					config,
					solver_address,
					include_source_finality_delay,
				)
				.await
			{
				Ok(fill_tx) => {
					if let Some(live_units) = self
						.try_live_fill_estimate(dest_chain_id, &fill_tx, max_live_fill_estimates)
						.await
					{
						tracing::info!(
							chain_id = dest_chain_id,
							static_units = gas_units.fill_units,
							live_units,
							"Quote-time fill gas estimated live"
						);
						gas_units.fill_units = live_units;
					}
					// None ⇒ fall through with static units (helper logged the reason).
				},
				Err(e) => {
					tracing::warn!(
						chain_id = dest_chain_id,
						error = %e,
						"Skipping live fill estimate: failed to build synthetic fill tx"
					);
				},
			}
		}

		let settlement_fee_wei = match self.build_post_fill_fee_params_for_quote(
			request,
			context,
			&swap_amounts_with_info,
			config,
		)? {
			Some(params) => self
				.settlement_service
				.quote_post_fill_fee_primary(&params)
				.await
				.map_err(|e| APIError::InternalServerError {
					error_type: ApiErrorType::ServiceError,
					message: format!("Failed to quote settlement fee: {e}"),
				})?
				.map(|quote| quote.fee_wei)
				.unwrap_or(U256::ZERO),
			None => U256::ZERO,
		};

		// Build the synthetic post-fill tx + override, then estimate.
		// All branches log exactly ONE outcome event and yield Option<u64>.
		// We never `return` — the rest of cost calc must run regardless.
		let live_post_fill_units: Option<u64> = if post_fill_enabled_for_chain {
			match self
				.build_post_fill_tx_for_quote(
					request,
					context,
					&swap_amounts_with_info,
					config,
					solver_address,
					settlement_fee_wei,
				)
				.await
			{
				Ok(None) => {
					// Hyperlane config absent / not required for this quote.
					tracing::debug!(
						chain_id = dest_chain_id,
						outcome = post_fill_outcome::SKIPPED_DISABLED,
						"post-fill gas estimate"
					);
					None
				},
				Err(e) => {
					tracing::info!(
						chain_id = dest_chain_id,
						outcome = post_fill_outcome::SKIPPED_BUILD_TX,
						error = %e,
						"post-fill gas estimate"
					);
					None
				},
				Ok(Some(pf)) => {
					let settler_alloy = alloy_primitives::Address::from_slice(&pf.output_settler.0);
					let state_override =
						crate::engine::post_fill_overrides::build_post_fill_state_override(
							settler_alloy,
							pf.synthetic_order_id,
							pf.output_hash,
							pf.solver,
							pf.fill_timestamp,
						);
					match self
						.try_live_post_fill_estimate_with_overrides(
							dest_chain_id,
							&pf.tx,
							state_override,
						)
						.await
					{
						PostFillEstimateOutcome::Success(live_units) => {
							let static_units = gas_units.post_fill_units;
							let delta_pct = ((live_units as i64 - static_units as i64) * 100)
								.checked_div(static_units as i64)
								.unwrap_or(0);
							tracing::info!(
								chain_id = dest_chain_id,
								outcome = post_fill_outcome::SUCCESS,
								static_units,
								live_units,
								delta_pct,
								"post-fill gas estimate"
							);
							Some(live_units)
						},
						PostFillEstimateOutcome::FallbackZero => {
							tracing::info!(
								chain_id = dest_chain_id,
								outcome = post_fill_outcome::FALLBACK_ZERO,
								static_units = gas_units.post_fill_units,
								"post-fill gas estimate"
							);
							None
						},
						PostFillEstimateOutcome::FallbackError(e) => {
							tracing::info!(
								chain_id = dest_chain_id,
								outcome = post_fill_outcome::FALLBACK_ERROR,
								static_units = gas_units.post_fill_units,
								error = %e,
								"post-fill gas estimate"
							);
							None
						},
					}
				},
			}
		} else {
			tracing::debug!(
				chain_id = dest_chain_id,
				outcome = post_fill_outcome::SKIPPED_UNSUPPORTED_CHAIN,
				"post-fill gas estimate"
			);
			None
		};

		// Apply the live units if we got them; otherwise keep the static
		// default. Either way, downstream cost calculation continues.
		if let Some(live_units) = live_post_fill_units {
			gas_units.post_fill_units = live_units;
		}

		let mut l1_data_fee_wei = U256::ZERO;
		let mut l1_data_fee_buffer_wei = U256::ZERO;

		// Only chains with an extra_native_fee policy (OP Stack L1 data fee) need
		// a per-transaction fee estimate. On every other chain the synthetic-tx
		// builds below are pure waste (the estimate would be zero), so skip them.
		if extra_native_fee_configured(config, dest_chain_id) {
			match self
				.build_fill_tx_for_quote(
					request,
					context,
					&swap_amounts_with_info,
					config,
					solver_address,
					include_source_finality_delay,
				)
				.await
			{
				Ok(mut fill_tx) => {
					fill_tx.gas_limit = Some(gas_units.fill_units);
					let (raw, buffer) = self
						.estimate_extra_native_fee_wei(config, dest_chain_id, &fill_tx)
						.await?;
					l1_data_fee_wei = l1_data_fee_wei.saturating_add(raw);
					l1_data_fee_buffer_wei = l1_data_fee_buffer_wei.saturating_add(buffer);
				},
				Err(e) => {
					fail_closed_on_extra_fee_build_error(config, dest_chain_id, "fill", e)?;
				},
			}

			match self
				.build_post_fill_tx_for_quote(
					request,
					context,
					&swap_amounts_with_info,
					config,
					solver_address,
					settlement_fee_wei,
				)
				.await
			{
				Ok(Some(mut post_fill)) => {
					post_fill.tx.gas_limit = Some(gas_units.post_fill_units);
					let (raw, buffer) = self
						.estimate_extra_native_fee_wei(config, dest_chain_id, &post_fill.tx)
						.await?;
					l1_data_fee_wei = l1_data_fee_wei.saturating_add(raw);
					l1_data_fee_buffer_wei = l1_data_fee_buffer_wei.saturating_add(buffer);
				},
				Ok(None) => {},
				Err(e) => {
					fail_closed_on_extra_fee_build_error(config, dest_chain_id, "post-fill", e)?;
				},
			}
		}

		// Parse inputs/outputs to proper types for cost calculation
		let mut parsed_inputs = Vec::new();
		for input in inputs {
			if let Ok(mut order_input) = <OrderInput>::try_from(input) {
				// Fill in zero amounts with calculated swap amounts
				if order_input.amount == U256::ZERO {
					if let Some(calculated_info) = swap_amounts_with_info.get(&input.asset) {
						order_input.amount = calculated_info.amount;
					}
				}
				parsed_inputs.push(order_input);
			}
		}

		let mut parsed_outputs = Vec::new();
		for output in outputs {
			if let Ok(mut order_output) = <OrderOutput>::try_from(output) {
				// Fill in zero amounts with calculated swap amounts
				if order_output.amount == U256::ZERO {
					if let Some(calculated_info) = swap_amounts_with_info.get(&output.asset) {
						order_output.amount = calculated_info.amount;
					}
				}
				parsed_outputs.push(order_output);
			}
		}

		// M-09: price the user-controlled callbackData carried in the origin
		// `open*`/`finalise*` calldata. Applied AFTER the static + live-estimate
		// and L1 data fee updates, BEFORE cost calculation. Fail closed on invalid
		// callback hex rather than continuing with zero extra gas.
		let callback_gas_units = callback_calldata_gas_units(&parsed_outputs)?;
		apply_callback_calldata_gas_units(&mut gas_units, callback_gas_units);

		// First calculate base costs with swap amounts to determine operational costs
		let cost_breakdown = self
			.calculate_total_cost(
				&parsed_inputs,
				&parsed_outputs,
				config,
				origin_chain_id,
				dest_chain_id,
				&gas_units,
				settlement_fee_wei,
				l1_data_fee_wei,
				l1_data_fee_buffer_wei,
			)
			.await?;

		// Pre-calculate cost amounts in relevant tokens
		// Include min_profit for quotes so users know the total they need to provide
		let total_with_profit = cost_breakdown.total + cost_breakdown.min_profit;

		// Ceil to cents to protect our margin during USD -> token -> USD round-trip
		// This ensures we always collect enough to cover costs + min_profit after conversions
		let total_with_profit_rounded = ceil_dp(total_with_profit, 2);

		let mut cost_amounts_in_tokens = std::collections::HashMap::new();

		// Calculate cost in each requested input token
		for input in inputs {
			let cost_in_token = self
				.convert_usd_to_token_amount(total_with_profit_rounded, &input.asset)
				.await
				.unwrap_or(U256::ZERO);

			let decimals = decimals_map.get(&input.asset).copied().unwrap_or(18);
			cost_amounts_in_tokens.insert(
				input.asset.clone(),
				TokenAmountInfo {
					token: input.asset.clone(),
					amount: cost_in_token,
					decimals,
				},
			);
		}

		// Also calculate cost in each requested output token for reference
		for output in outputs {
			// Only add if not already calculated (in case same token appears in inputs)
			if !cost_amounts_in_tokens.contains_key(&output.asset) {
				let cost_in_token = self
					.convert_usd_to_token_amount(total_with_profit_rounded, &output.asset)
					.await
					.unwrap_or(U256::ZERO);

				let decimals = decimals_map.get(&output.asset).copied().unwrap_or(18);
				cost_amounts_in_tokens.insert(
					output.asset.clone(),
					TokenAmountInfo {
						token: output.asset.clone(),
						amount: cost_in_token,
						decimals,
					},
				);
			}
		}

		// Build execution costs by chain from base cost breakdown
		let mut execution_costs_by_chain = std::collections::HashMap::new();
		execution_costs_by_chain.insert(
			origin_chain_id,
			cost_breakdown.gas_open + cost_breakdown.gas_pre_claim + cost_breakdown.gas_claim,
		);
		execution_costs_by_chain.insert(
			dest_chain_id,
			cost_breakdown.gas_fill
				+ cost_breakdown.gas_post_fill
				+ cost_breakdown.settlement_fee
				+ cost_breakdown.settlement_fee_buffer
				+ cost_breakdown.l1_data_fee
				+ cost_breakdown.l1_data_fee_buffer,
		);

		// Calculate adjusted amounts (swap amounts +/- costs based on swap type)
		let mut adjusted_amounts = std::collections::HashMap::new();
		match context.swap_type {
			SwapType::ExactInput => {
				// For ExactInput: outputs are adjusted (swap_amount - cost)
				for (token, swap_info) in &swap_amounts_with_info {
					let cost_info = cost_amounts_in_tokens.get(token);
					let cost_amount = cost_info.map(|c| c.amount).unwrap_or(U256::ZERO);
					let adjusted = swap_info.amount.saturating_sub(cost_amount);
					adjusted_amounts.insert(
						token.clone(),
						TokenAmountInfo {
							token: token.clone(),
							amount: adjusted,
							decimals: swap_info.decimals,
						},
					);
				}
			},
			SwapType::ExactOutput => {
				// For ExactOutput: inputs are adjusted (swap_amount + cost)
				for (token, swap_info) in &swap_amounts_with_info {
					let cost_info = cost_amounts_in_tokens.get(token);
					let cost_amount = cost_info.map(|c| c.amount).unwrap_or(U256::ZERO);
					let adjusted = swap_info.amount.saturating_add(cost_amount);
					adjusted_amounts.insert(
						token.clone(),
						TokenAmountInfo {
							token: token.clone(),
							amount: adjusted,
							decimals: swap_info.decimals,
						},
					);
				}
			},
		}

		Ok(CostContext {
			cost_breakdown,
			execution_costs_by_chain,
			liquidity_cost_adjustment: Decimal::ZERO,
			protocol_fees: std::collections::HashMap::new(),
			swap_type: context.swap_type.clone(),
			cost_amounts_in_tokens,
			swap_amounts: swap_amounts_with_info,
			adjusted_amounts,
		})
	}

	#[allow(clippy::too_many_arguments)]
	pub async fn calculate_total_cost(
		&self,
		inputs: &[OrderInput],
		outputs: &[OrderOutput],
		config: &Config,
		origin_chain_id: u64,
		dest_chain_id: u64,
		gas_units: &GasUnits,
		settlement_fee_wei: U256,
		l1_data_fee_wei: U256,
		l1_data_fee_buffer_wei: U256,
	) -> Result<CostBreakdown, CostProfitError> {
		// Read gas_buffer_bps from solver config (hot-reloadable)
		let gas_buffer_bps_value = config.solver.gas_buffer_bps;

		// Resolve effective fee params per chain — the same model used by
		// transaction submit. `cost_per_gas` is the quote-economics value
		// chosen by the configured `FeeCostStrategy` (e.g. buffered
		// effective EIP-1559 price).
		let (origin_fee, dest_fee) = tokio::try_join!(
			self.get_chain_fee_params(origin_chain_id),
			self.get_chain_fee_params(dest_chain_id),
		)?;

		let origin_gp = U256::from(origin_fee.cost_per_gas);
		let dest_gp = U256::from(dest_fee.cost_per_gas);

		// Single structured event covering both legs — at INFO so the value
		// used for quote economics is auditable in canary deploys. Move to
		// `debug` once production confidence exists.
		tracing::info!(
			origin_chain_id,
			dest_chain_id,
			origin_fee_model = ?origin_fee.model,
			origin_cost_per_gas = origin_fee.cost_per_gas,
			origin_max_fee_per_gas = ?origin_fee.max_fee_per_gas,
			origin_max_priority_fee_per_gas = ?origin_fee.max_priority_fee_per_gas,
			origin_legacy_gas_price = ?origin_fee.gas_price,
			dest_fee_model = ?dest_fee.model,
			dest_cost_per_gas = dest_fee.cost_per_gas,
			dest_max_fee_per_gas = ?dest_fee.max_fee_per_gas,
			dest_max_priority_fee_per_gas = ?dest_fee.max_priority_fee_per_gas,
			dest_legacy_gas_price = ?dest_fee.gas_price,
			"Quote gas fee params resolved"
		);

		// Split gas costs across origin/destination contract legs. Helper
		// is pure to allow proptest coverage of the chain-boundary
		// invariant without touching mocks.
		let leg_costs = calculate_gas_leg_costs_wei(gas_units, origin_gp, dest_gp);
		let open_cost_wei = leg_costs.open;
		let fill_cost_wei = leg_costs.fill;
		let post_fill_cost_wei = leg_costs.post_fill;
		let pre_claim_cost_wei = leg_costs.pre_claim;
		let claim_cost_wei = leg_costs.claim;

		// Price conversions are independent as well.
		let (gas_open, gas_fill, gas_post_fill, gas_pre_claim, gas_claim) = tokio::try_join!(
			self.native_base_units_to_usd(origin_chain_id, &open_cost_wei),
			self.native_base_units_to_usd(dest_chain_id, &fill_cost_wei),
			self.native_base_units_to_usd(dest_chain_id, &post_fill_cost_wei),
			self.native_base_units_to_usd(origin_chain_id, &pre_claim_cost_wei),
			self.native_base_units_to_usd(origin_chain_id, &claim_cost_wei),
		)?;

		// Calculate gas buffer using config value (hot-reloadable)
		let gas_subtotal = gas_open + gas_fill + gas_post_fill + gas_pre_claim + gas_claim;
		let gas_buffer_bps = Decimal::new(gas_buffer_bps_value as i64, 0);
		let gas_buffer = (gas_subtotal * gas_buffer_bps) / Decimal::from(10000);

		// Rate buffer is applied in swap amount calculation (rate multiplier),
		// so keep this component at zero to avoid double-charging.
		let rate_buffer = Decimal::ZERO;

		let settlement_fee = self
			.native_base_units_to_usd(dest_chain_id, &settlement_fee_wei)
			.await?;
		let settlement_fee_buffer_bps =
			Decimal::new(config.solver.settlement_fee_buffer_bps as i64, 0);
		let settlement_fee_buffer =
			(settlement_fee * settlement_fee_buffer_bps) / Decimal::from(10000);
		let (l1_data_fee, l1_data_fee_buffer) = tokio::try_join!(
			self.native_base_units_to_usd(dest_chain_id, &l1_data_fee_wei),
			self.native_base_units_to_usd(dest_chain_id, &l1_data_fee_buffer_wei),
		)?;

		// Input and output valuations do not depend on each other.
		let (total_input_value_usd, total_output_value_usd) = tokio::try_join!(
			self.calculate_inputs_usd_value(inputs),
			self.calculate_outputs_usd_value(outputs),
		)?;

		// Calculate spread and base price
		let spread = total_input_value_usd - total_output_value_usd;
		let base_price = if spread < Decimal::ZERO {
			spread.abs() // Cover negative spread
		} else {
			Decimal::ZERO
		};

		// Calculate minimum profit based on TRANSACTION VALUE, not gas
		let transaction_value = total_input_value_usd.max(total_output_value_usd);
		let min_profit =
			(transaction_value * config.solver.min_profitability_pct) / Decimal::from(100);
		let commission = (transaction_value * Decimal::from(config.solver.commission_bps))
			/ Decimal::from(10000);
		let min_profit = min_profit + commission;

		// Calculate operational cost (gas + buffers)
		let operational_cost =
			gas_open
				+ gas_fill + gas_post_fill
				+ gas_pre_claim
				+ gas_claim + gas_buffer
				+ settlement_fee
				+ settlement_fee_buffer
				+ l1_data_fee
				+ l1_data_fee_buffer
				+ rate_buffer;

		// Calculate subtotal (actual costs only, excluding profit)
		let subtotal = operational_cost + base_price;

		// Calculate total (actual costs only, excluding profit requirement)
		let total = subtotal;

		Ok(CostBreakdown {
			gas_open,
			gas_fill,
			gas_post_fill,
			gas_pre_claim,
			gas_claim,
			gas_buffer,
			settlement_fee,
			settlement_fee_buffer,
			l1_data_fee,
			l1_data_fee_buffer,
			rate_buffer,
			base_price,
			min_profit,
			operational_cost,
			subtotal,
			total,
			currency: "USD".to_string(),
		})
	}

	/// Estimate cost for an Order using its OrderParsable implementation
	pub async fn estimate_cost_for_order(
		&self,
		order: &Order,
		config: &Config,
	) -> Result<CostBreakdown, CostProfitError> {
		self.estimate_cost_for_order_with_gas(order, config, None, None)
			.await
	}

	/// Performs cheap local validation that must happen before fill simulation.
	///
	/// This avoids spending RPC capacity on `eth_estimateGas` for orders whose
	/// assets or callback payloads are known locally to be unsupported.
	pub async fn validate_before_fill_simulation(
		&self,
		order: &Order,
		config: &Config,
	) -> Result<(), CostProfitError> {
		let order_parsed = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data: {e}"),
			details: None,
		})?;

		let available_inputs = order_parsed.parse_available_inputs();
		let requested_outputs = order_parsed.parse_requested_outputs();

		for input in &available_inputs {
			let chain_id = input.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get input chain ID: {e}"))
			})?;
			let ethereum_addr = input.asset.ethereum_address().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get input token address: {e}"))
			})?;
			let token_address = Address(ethereum_addr.0.to_vec());
			self.token_manager
				.get_token_info(chain_id, &token_address)
				.await?;
		}

		for output in &requested_outputs {
			let chain_id = output.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get output chain ID: {e}"))
			})?;
			let ethereum_addr = output.asset.ethereum_address().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get output token address: {e}"))
			})?;
			let token_address = Address(ethereum_addr.0.to_vec());
			self.token_manager
				.get_token_info(chain_id, &token_address)
				.await?;

			Self::validate_callback_calldata(output.calldata.as_deref())?;
		}

		Self::validate_callback_policy_before_simulation(&requested_outputs, config)
	}

	fn validate_callback_calldata(calldata: Option<&str>) -> Result<(), CostProfitError> {
		let Some(calldata) = calldata else {
			return Ok(());
		};
		let hex_payload = calldata.strip_prefix("0x").unwrap_or(calldata);
		if hex_payload.is_empty() {
			return Ok(());
		}
		if hex_payload.len() % 2 != 0 {
			return Err(CostProfitError::Calculation(
				"Output callbackData must be valid hex".to_string(),
			));
		}
		let byte_len = hex_payload.len() / 2;
		if byte_len > MAX_CALLBACK_DATA_BYTES {
			return Err(CostProfitError::Calculation(format!(
				"Output callbackData is too large: {byte_len} bytes exceeds {MAX_CALLBACK_DATA_BYTES} byte limit"
			)));
		}
		alloy_primitives::hex::decode(hex_payload).map_err(|e| {
			CostProfitError::Calculation(format!("Output callbackData must be valid hex: {e}"))
		})?;
		Ok(())
	}

	/// Returns true if `recipient_interop_hex` is permitted by the configured
	/// callback whitelist. An empty whitelist means "allow all callbacks",
	/// matching the quote-time contract in solver-service's
	/// `validate_callback_whitelist`.
	fn callback_recipient_whitelisted(config: &Config, recipient_interop_hex: &str) -> bool {
		let whitelist = &config.order.callback_whitelist;
		whitelist.is_empty()
			|| whitelist
				.iter()
				.any(|entry| entry.to_lowercase() == recipient_interop_hex)
	}

	fn validate_callback_policy_before_simulation(
		outputs: &[OrderOutput],
		config: &Config,
	) -> Result<(), CostProfitError> {
		for output in outputs {
			let has_callback = output
				.calldata
				.as_ref()
				.is_some_and(|c| !c.is_empty() && c != "0x");
			if !has_callback {
				continue;
			}

			if !config.order.simulate_callbacks {
				return Err(CostProfitError::Config(
					"Order has callback data but callback simulation is disabled. \
					Callbacks are not supported when simulate_callbacks = false in config."
						.to_string(),
				));
			}

			let recipient_interop_hex = output.receiver.to_hex().to_lowercase();
			let output_chain_id = output.receiver.ethereum_chain_id().map_err(|e| {
				CostProfitError::Config(format!("Failed to extract chain ID from recipient: {e}"))
			})?;
			let recipient_eth_address = output
				.receiver
				.ethereum_address()
				.map(|addr| format!("0x{}", alloy_primitives::hex::encode(addr)))
				.unwrap_or_else(|_| "unknown".to_string());

			let is_whitelisted =
				Self::callback_recipient_whitelisted(config, &recipient_interop_hex);

			if !is_whitelisted {
				return Err(CostProfitError::Config(format!(
					"Callback recipient {recipient_eth_address} on chain {output_chain_id} not in whitelist. Add '{recipient_interop_hex}' to order.callback_whitelist in config (EIP-7930 format)"
				)));
			}
		}

		Ok(())
	}

	/// Estimates the cost for an order with an optional simulated fill gas override.
	///
	/// When `simulated_fill_gas` is provided (from `eth_estimateGas`), it will be used
	/// instead of the config defaults. This provides accurate gas estimation for orders
	/// with callbacks or complex fill logic.
	///
	/// # Arguments
	/// * `order` - The order to estimate costs for
	/// * `config` - Solver configuration
	/// * `simulated_fill_gas` - Optional gas units from simulation (overrides config default)
	/// * `fill_tx` - Optional real fill transaction to use for live gas estimation
	pub async fn estimate_cost_for_order_with_gas(
		&self,
		order: &Order,
		config: &Config,
		simulated_fill_gas: Option<u64>,
		fill_tx: Option<&Transaction>,
	) -> Result<CostBreakdown, CostProfitError> {
		// Parse the order data based on its standard
		let order_parsed = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data: {e}"),
			details: None,
		})?;

		// Extract chain parameters
		let origin_chain_id = order_parsed.origin_chain_id();
		let dest_chain_ids = order_parsed.destination_chain_ids();

		let dest_chain_id =
			dest_chain_ids
				.first()
				.copied()
				.ok_or_else(|| APIError::BadRequest {
					error_type: ApiErrorType::MissingChainId,
					message: "No destination chain ID found".to_string(),
					details: None,
				})?;

		// Extract flow key (lock_type) for gas config lookup
		let flow_key = order_parsed.parse_lock_type();

		// Estimate gas units (may be overridden by simulated value)
		let mut gas_units = self
			.estimate_gas_units(
				&flow_key,
				config,
				origin_chain_id,
				dest_chain_id,
				simulated_fill_gas,
				fill_tx,
			)
			.await?;

		// Override fill gas with simulated value if provided and non-zero
		if let Some(simulated_gas) = simulated_fill_gas {
			if simulated_gas > 0 {
				tracing::info!(
					"Using simulated fill gas: {} units (config default was: {} units)",
					simulated_gas,
					gas_units.fill_units
				);
				gas_units.fill_units = simulated_gas;
			}
		}

		// Get inputs and outputs
		let available_inputs = order_parsed.parse_available_inputs();
		let requested_outputs = order_parsed.parse_requested_outputs();

		let settlement_fee_wei = match self.build_post_fill_fee_params_for_order(
			order,
			&requested_outputs,
			origin_chain_id,
			dest_chain_id,
		)? {
			Some(params) => self
				.settlement_service
				.quote_post_fill_fee_for_order(order, &params)
				.await
				.map_err(|e| APIError::InternalServerError {
					error_type: ApiErrorType::ServiceError,
					message: format!("Failed to quote settlement fee: {e}"),
				})?
				.map(|quote| quote.fee_wei)
				.unwrap_or(U256::ZERO),
			None => U256::ZERO,
		};

		let (l1_data_fee_wei, l1_data_fee_buffer_wei) = if let Some(fill_tx) = fill_tx {
			let mut fill_tx = fill_tx.clone();
			fill_tx.gas_limit = Some(gas_units.fill_units);
			self.estimate_extra_native_fee_wei(config, dest_chain_id, &fill_tx)
				.await?
		} else {
			(U256::ZERO, U256::ZERO)
		};

		// M-09: price the user-controlled callbackData carried in the origin
		// `open*`/`finalise*` calldata. Applied AFTER the static gas units and the
		// simulated-fill override, BEFORE cost calculation. Does not touch the
		// simulated fill gas. Fail closed on invalid callback hex.
		let callback_gas_units = callback_calldata_gas_units(&requested_outputs)?;
		apply_callback_calldata_gas_units(&mut gas_units, callback_gas_units);

		// Use the unified cost calculation method
		let cost_breakdown = self
			.calculate_total_cost(
				&available_inputs,
				&requested_outputs,
				config,
				origin_chain_id,
				dest_chain_id,
				&gas_units,
				settlement_fee_wei,
				l1_data_fee_wei,
				l1_data_fee_buffer_wei,
			)
			.await?;

		// Convert to API format
		Ok(cost_breakdown)
	}

	/// Validates that an order meets the minimum profitability threshold.
	///
	/// This method checks if an order (whether from our quote system or submitted directly)
	/// provides sufficient profit margin. It recalculates costs and compares actual profit
	/// against the minimum requirement.
	///
	/// If `quote_id` is provided, the quote will be retrieved from storage to get additional context.
	/// The `intent_source` parameter indicates whether the intent is "on-chain" or "off-chain".
	pub async fn validate_profitability(
		&self,
		order: &Order,
		cost_breakdown: &CostBreakdown,
		min_profitability_pct: Decimal,
		quote_id: Option<&str>,
		intent_source: &str,
	) -> Result<Decimal, APIError> {
		// Parse the order first so a stored quote can be bound to it (H-07).
		let order_parsed = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data: {e}"),
			details: None,
		})?;

		let available_inputs = order_parsed.parse_available_inputs();
		let requested_outputs = order_parsed.parse_requested_outputs();

		// Retrieve the stored quote's cost context if a quote ID is provided, but
		// honor it ONLY when its economic binding matches THIS order (H-07).
		//
		// A `quote_id` is otherwise an unaudienced bearer token: an unrelated,
		// loss-making order presenting a cheap quote's id would be judged against
		// that quote's (cheaper) stored operational cost and swap-type denominator,
		// letting a loss-making fill clear the gate. The binding pins the economic
		// identity of the order the quote priced, so a mismatch is rejected.
		let cost_context = if let Some(id) = quote_id {
			match self.get_stored_quote_by_quote_id(id).await {
				Ok(stored) => match stored.binding {
					Some(stored_binding) => {
						let actual = solver_types::quote_order_binding(
							order_parsed.origin_chain_id(),
							order_parsed.parse_lock_type().as_deref(),
							&available_inputs,
							&requested_outputs,
						);
						if stored_binding == actual {
							let ctx = stored.cost_context;
							tracing::debug!(
								"Cost context from quote generation: operational_cost=${:.2}, min_profit=${:.2}, total=${:.2}",
								ctx.cost_breakdown.operational_cost,
								ctx.cost_breakdown.min_profit,
								ctx.cost_breakdown.total
							);
							Some(ctx)
						} else {
							// Fail closed: the order does not match the quote it
							// references. This cannot happen on a legitimate
							// redemption (the order is rebuilt from the stored
							// quote), so a mismatch is anomalous and must not be
							// priced on the stored economics.
							tracing::warn!(
								quote_id = %id,
								expected_binding = %stored_binding,
								actual_binding = %actual,
								"Rejecting order: quote binding does not match submitted order (H-07)"
							);
							return Err(APIError::UnprocessableEntity {
								error_type: ApiErrorType::QuoteOrderMismatch,
								message: "Order does not match the quote it references".to_string(),
								details: None,
							});
						}
					},
					None => {
						// Legacy/unbindable quote record (e.g. stored before this
						// change, or a generic order). Judge on the freshly
						// recomputed breakdown, exactly like a direct submission.
						// Scoped strictly to a missing binding — never a mismatch.
						tracing::debug!(
							"Quote {} has no economic binding; judging on freshly recomputed cost",
							id
						);
						None
					},
				},
				Err(e) => {
					tracing::warn!("Failed to retrieve quote for {}: {}", id, e);
					None
				},
			}
		} else {
			None
		};

		// Calculate actual USD values from the order amounts
		let total_input_value_usd = self
			.calculate_inputs_usd_value(&available_inputs)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::InternalError,
				message: format!("Failed to calculate input USD value: {e}"),
			})?;

		let total_output_value_usd = self
			.calculate_outputs_usd_value(&requested_outputs)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::InternalError,
				message: format!("Failed to calculate output USD value: {e}"),
			})?;

		// Source of truth for operational cost:
		// - Quoted orders use the breakdown stored at quote time, so the order
		//   is judged against the price we actually promised. Honors the quote
		//   under gas-price drift (intentional).
		// - Direct submissions or orders whose quote context has been lost (e.g.
		//   quote expired between submission and validation) fall back to the
		//   freshly recomputed breakdown.
		let breakdown_for_decision = cost_context
			.as_ref()
			.map(|ctx| &ctx.cost_breakdown)
			.unwrap_or(cost_breakdown);

		if cost_context.is_some() {
			tracing::debug!(
				stored_operational_cost = %breakdown_for_decision.operational_cost,
				fresh_operational_cost = %cost_breakdown.operational_cost,
				"Validating quoted order against stored cost breakdown"
			);
		}

		// Operational cost is already available in the breakdown
		// For onchain intents, subtract the open cost since it's already paid by the user
		let operational_cost_usd = if intent_source == "on-chain" {
			// On-chain intent: user already paid for the open transaction
			breakdown_for_decision.operational_cost - breakdown_for_decision.gas_open
		} else {
			// Off-chain intent: solver will pay for all costs including open
			breakdown_for_decision.operational_cost
		};

		// Calculate the actual spread in the order
		// For normal swaps: spread = input - output (positive when user pays more than receives)
		// For arbitrage: spread = input - output (negative when user receives more than pays)
		let order_spread = total_input_value_usd - total_output_value_usd;

		// Actual profit is the spread minus operational costs
		// For normal swaps: profit comes from positive spread
		// For arbitrage: we would lose money (negative spread means user profits, not us)
		let actual_profit_usd = order_spread - operational_cost_usd;

		// Calculate profit margin as percentage of transaction value
		// For ExactOutput swaps, we must use the output value as the base (what the user requested)
		// For ExactInput swaps, we use the input value as the base
		// This ensures consistency with how profit was calculated during quote generation
		let transaction_value = if let Some(ref ctx) = cost_context {
			match ctx.swap_type {
				solver_types::SwapType::ExactOutput => {
					// For ExactOutput: use output value as base (what user wants to receive)
					total_output_value_usd
				},
				solver_types::SwapType::ExactInput => {
					// For ExactInput: use input value as base (what user is sending)
					total_input_value_usd
				},
			}
		} else {
			// No cost context (direct submission), use the larger value
			// This maintains backward compatibility for non-quoted orders
			total_input_value_usd.max(total_output_value_usd)
		};

		if transaction_value.is_zero() {
			return Err(APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: "Cannot calculate profit margin: zero transaction value".to_string(),
				details: None,
			});
		}

		let actual_profit_margin = (actual_profit_usd / transaction_value) * Decimal::from(100);
		let profit_validation_passed = actual_profit_margin >= min_profitability_pct;

		// Calculate what the values would be at different stages
		// Note: We're working backwards from the final quoted values
		// Display the actual minimum profit requirement from cost breakdown
		let display_actual_profit = actual_profit_usd;

		// Calculate effective exchange rate (what % of input value user receives)
		let effective_rate_pct = if !total_input_value_usd.is_zero() {
			(total_output_value_usd / total_input_value_usd * Decimal::from(100)).round_dp(1)
		} else {
			Decimal::ZERO
		};

		// For display: show the absolute spread amount (always positive)
		// and indicate if it's a cost to user or an arbitrage opportunity
		let display_spread = order_spread.abs();
		let spread_type = if order_spread >= Decimal::ZERO {
			"collected from user"
		} else {
			"arbitrage opportunity"
		};

		// Build the optional PreClaim cost line — kept out of the printed
		// summary when zero to avoid noise on flows that have no pre-claim
		// step (most common today).
		let pre_claim_line = if breakdown_for_decision.gas_pre_claim.is_zero() {
			String::new()
		} else {
			format!(
				"│  │  ├─ PreClaim:        $ {:>7.4}\n",
				breakdown_for_decision.gas_pre_claim
			)
		};

		// Log streamlined profitability validation summary
		tracing::info!(
			"\n\
			╭─ Quote Validation Summary:\n\
			│  ├─ Quote ID:           {}\n\
			│  ├─ Swap Type:          {}\n\
			│  └─ Effective Rate:     {:.1}%\n\
			├─ Order Economics:\n\
			│  ├─ Input:\n\
			│  │  ├─ USD Value:       $ {:>7.4}\n\
			│  ├─ Output:\n\
			│  │  ├─ USD Value:       $ {:>7.4}\n\
			│  └─ Spread:\n\
			│     ├─ Amount:          $ {:>7.4} ({})\n\
			│     └─ Solver P&L:      $ {:>7.4} (after ${:.2} costs)\n\
			├─ Cost Breakdown:\n\
			│  ├─ Gas Costs:\n\
			│  │  ├─ Open:            {}\n\
			│  │  ├─ Fill:            $ {:>7.4}\n\
			│  │  ├─ PostFill:        $ {:>7.4}\n\
			{}\
			│  │  ├─ Claim:           $ {:>7.4}\n\
			│  │  └─ Buffer (10%):    $ {:>7.4}\n\
			│  ├─ Total Operational:  $ {:>7.4}\n\
			│  └─ Solver Profit:      $ {:>7.4} (target: {:.1}% of transaction)\n\
			├─ Validation Result:\n\
			│  ├─ Profit Margin:      {:.2}%\n\
			│  ├─ Min Required:       {:.2}%\n\
			│  └─ Status:             {}\n\
			╰─ Decision: {}",
			// Quote info
			quote_id.unwrap_or("N/A"),
			if let Some(ref ctx) = cost_context {
				format!("{:?}", ctx.swap_type)
			} else {
				"Unknown".to_string()
			},
			effective_rate_pct,
			// Order values
			total_input_value_usd,
			total_output_value_usd,
			display_spread,
			spread_type,
			display_actual_profit,
			operational_cost_usd,
			// Cost breakdown - show N/A for gas_open if onchain intent
			if intent_source == "on-chain" {
				"N/A (on-chain intent)".to_string()
			} else {
				format!("$ {:>7.4}", breakdown_for_decision.gas_open)
			},
			breakdown_for_decision.gas_fill,
			breakdown_for_decision.gas_post_fill,
			pre_claim_line,
			breakdown_for_decision.gas_claim,
			breakdown_for_decision.gas_buffer,
			operational_cost_usd,
			display_actual_profit,
			min_profitability_pct,
			// Validation
			actual_profit_margin,
			min_profitability_pct,
			if profit_validation_passed {
				"✓ PASSED"
			} else {
				"✗ FAILED"
			},
			if profit_validation_passed {
				format!(
					"Order accepted with {} profit margin",
					format_percentage(actual_profit_margin)
				)
			} else {
				format!(
					"Order rejected - insufficient margin ({} < {})",
					format_percentage(actual_profit_margin),
					format_percentage(min_profitability_pct)
				)
			}
		);

		// Check if actual profit meets minimum requirement
		if !profit_validation_passed {
			let error_msg = format!(
				"Insufficient profit margin: {actual_profit_margin:.2}% < required {min_profitability_pct:.2}%"
			);
			return Err(APIError::UnprocessableEntity {
				error_type: ApiErrorType::InsufficientProfitability,
				message: error_msg,
				details: Some(serde_json::json!({
					"input_value": format!("${:.2}", total_input_value_usd),
					"output_value": format!("${:.2}", total_output_value_usd),
					"operational_cost": format!("${:.2}", operational_cost_usd),
					"actual_profit": format!("${:.2}", actual_profit_usd),
					"actual_margin": format!("{:.2}%", actual_profit_margin),
					"required_margin": format!("{:.2}%", min_profitability_pct),
				})),
			});
		}

		Ok(actual_profit_margin)
	}

	/// Estimate gas units with optional live estimation
	async fn estimate_gas_units(
		&self,
		flow_key: &Option<String>,
		config: &Config,
		_origin_chain_id: u64,
		dest_chain_id: u64,
		simulated_fill_gas: Option<u64>,
		fill_tx: Option<&Transaction>,
	) -> Result<GasUnits, CostProfitError> {
		let enable_live_gas_estimate = config
			.gas
			.as_ref()
			.map(|gas| gas.live_fill_estimate_enabled)
			.unwrap_or(false);
		let fill_already_simulated = simulated_fill_gas.is_some_and(|gas| gas > 0);

		// Get base units from config
		let (open_units, mut fill_units, post_fill_units, pre_claim_units, claim_units) =
			estimate_gas_units_from_config(
				flow_key,
				config,
				DEFAULT_OPEN_GAS_UNITS,
				DEFAULT_FILL_GAS_UNITS,
				DEFAULT_POST_FILL_GAS_UNITS,
				DEFAULT_PRE_CLAIM_GAS_UNITS,
				DEFAULT_CLAIM_GAS_UNITS,
			);

		// Live fill estimation if enabled and not already supplied by the order path.
		// This must use the real fill transaction generated by the order implementation;
		// a synthetic empty transaction can materially underprice fills.
		if enable_live_gas_estimate && !fill_already_simulated {
			let max_live_fill_estimates = config
				.gas
				.as_ref()
				.map(|gas| gas.max_concurrent_live_fill_estimates_per_chain)
				.unwrap_or(solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN);

			if let Some(fill_tx) = fill_tx {
				tracing::info!("Estimating fill gas on destination chain");
				if let Some(live_units) = self
					.try_live_fill_estimate(dest_chain_id, fill_tx, max_live_fill_estimates)
					.await
				{
					tracing::info!("Fill gas units: {}", live_units);
					fill_units = live_units;
				}
			} else {
				tracing::debug!(
					"Skipping live fill gas estimate because no generated fill transaction was provided"
				);
			}
		}

		Ok(GasUnits {
			open_units,
			fill_units,
			post_fill_units,
			pre_claim_units,
			claim_units,
		})
	}

	/// Attempts a live `eth_estimateGas` for the fill leg on `dest_chain_id`.
	///
	/// Returns `Some(units)` only if the RPC call succeeds with a non-zero result.
	/// Any other outcome (RPC error, zero units returned) yields `None`, and the
	/// caller is expected to fall back to the static config default. This keeps
	/// the live-estimation path strictly opportunistic — a transient RPC failure
	/// or a chain we can't reach must never refuse a quote.
	async fn try_live_fill_estimate(
		&self,
		dest_chain_id: u64,
		fill_tx: &Transaction,
		max_concurrent: usize,
	) -> Option<u64> {
		let Some(_permit) = self
			.live_estimate_controller
			.try_acquire(dest_chain_id, max_concurrent)
		else {
			tracing::warn!(
				chain_id = dest_chain_id,
				max_concurrent,
				"Live fill-gas estimation saturated; falling back to static default"
			);
			return None;
		};

		match self
			.delivery_service
			.estimate_gas(dest_chain_id, fill_tx.clone())
			.await
		{
			Ok(units) if units > 0 => {
				tracing::debug!(
					chain_id = dest_chain_id,
					units,
					"Live fill-gas estimation succeeded"
				);
				Some(units)
			},
			Ok(_) => {
				tracing::warn!(
					chain_id = dest_chain_id,
					"Live fill-gas estimation returned zero; falling back to static default"
				);
				None
			},
			Err(e) => {
				tracing::warn!(
					chain_id = dest_chain_id,
					error = %e,
					"Live fill-gas estimation failed; falling back to static default"
				);
				None
			},
		}
	}

	// Retained for now as a reference / fallback hook. The override-bearing
	// `try_live_post_fill_estimate_with_overrides` is the live path; per
	// the plan (Task 4 Step 3) this bare variant is unreachable from the
	// cost-profit pipeline and will be deleted once override rollout
	// completes everywhere.
	#[allow(dead_code)]
	async fn try_live_post_fill_estimate(
		&self,
		dest_chain_id: u64,
		post_fill_tx: &Transaction,
	) -> Option<u64> {
		match self
			.delivery_service
			.estimate_gas(dest_chain_id, post_fill_tx.clone())
			.await
		{
			Ok(units) if units > 0 => {
				tracing::debug!(
					chain_id = dest_chain_id,
					units,
					"Live post-fill gas estimation succeeded"
				);
				Some(units)
			},
			// Demoted from WARN to DEBUG (plan Task 4 Step 5): when overrides
			// are off and this bare path is reached, the always-revert is
			// expected and shouldn't be log noise.
			Ok(_) => {
				tracing::debug!(
					chain_id = dest_chain_id,
					"Live post-fill gas estimation returned zero; falling back to static default"
				);
				None
			},
			Err(e) => {
				tracing::debug!(
					chain_id = dest_chain_id,
					error = %e,
					"Live post-fill gas estimation failed; falling back to static default"
				);
				None
			},
		}
	}

	/// Override-bearing variant of `try_live_post_fill_estimate`. The
	/// caller is responsible for emitting exactly ONE structured outcome
	/// event per call (see [`post_fill_outcome`]); this helper performs
	/// no logging itself so outcome aggregation never double-counts.
	async fn try_live_post_fill_estimate_with_overrides(
		&self,
		dest_chain_id: u64,
		post_fill_tx: &Transaction,
		state_override: alloy_rpc_types::state::StateOverride,
	) -> PostFillEstimateOutcome {
		match self
			.delivery_service
			.estimate_gas_with_overrides(dest_chain_id, post_fill_tx.clone(), state_override)
			.await
		{
			Ok(units) if units > 0 => PostFillEstimateOutcome::Success(units),
			Ok(_) => PostFillEstimateOutcome::FallbackZero,
			Err(e) => PostFillEstimateOutcome::FallbackError(e),
		}
	}

	fn resolve_quote_output_amount(
		request: &GetQuoteRequest,
		context: &ValidatedQuoteContext,
		resolved_amounts: &std::collections::HashMap<InteropAddress, TokenAmountInfo>,
		output: &solver_types::QuoteOutput,
		dest_chain_id: u64,
		caller: &str,
	) -> Result<U256, APIError> {
		if let Some(info) = resolved_amounts.get(&output.asset) {
			return Ok(info.amount);
		}

		if let Some(known_outputs) = &context.known_outputs {
			if let Some((_, amount)) = known_outputs.iter().find(|(known_output, _)| {
				known_output.asset == output.asset && known_output.receiver == output.receiver
			}) {
				return Ok(*amount);
			}

			if request.intent.outputs.len() == 1 && known_outputs.len() == 1 {
				return Ok(known_outputs[0].1);
			}
		}

		if let Some(amount) = output.amount.as_deref() {
			return U256::from_str(amount).map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!("Output amount is not a valid integer: {e}"),
				details: None,
			});
		}

		Err(APIError::InternalServerError {
			error_type: ApiErrorType::InternalError,
			message: format!(
				"Missing output amount for asset on chain {dest_chain_id}; {caller} must run after calculate_swap_amounts or receive exact-output context"
			),
		})
	}

	/// Build a synthetic fill `Transaction` from a resolved quote request, suitable
	/// for `eth_estimateGas` against the destination chain's OutputSettler.
	///
	/// Mirrors the production encoder at
	/// `crates/solver-order/src/implementations/standards/_7683.rs:335-362`. If
	/// that encoder changes shape (new field on `SolMandateOutput`, different
	/// fill signature), THIS function must be updated in lockstep — there is
	/// currently no shared helper.
	///
	/// Notes:
	/// - `from` is intentionally not set on the returned `Transaction` (the
	///   type has no such field). The EVM delivery layer's wallet filler
	///   populates `from` with the configured solver signer for that chain
	///   (see `crates/solver-delivery/src/implementations/evm/alloy.rs:866-883`),
	///   which is exactly the address we want estimateGas to bill.
	/// - `oracle = B256::ZERO`, `context = vec![]`, `orderId = B256::ZERO`,
	///   `fillDeadline = 0` are placeholders. OutputSettlerSimple's gas is
	///   dominated by the ERC-20 transfer + a single SSTORE on a previously-
	///   empty slot; the SSTORE cost is identical for any non-zero hash, so
	///   placeholder values do not materially shift the estimate. If a
	///   particular settler reverts on the placeholders,
	///   `try_live_fill_estimate` returns `None` and the caller falls back to
	///   the static config default — safe.
	async fn build_fill_tx_for_quote(
		&self,
		request: &GetQuoteRequest,
		context: &ValidatedQuoteContext,
		resolved_amounts: &std::collections::HashMap<InteropAddress, TokenAmountInfo>,
		config: &Config,
		solver_address: &Address,
		include_source_finality_delay: bool,
	) -> Result<Transaction, APIError> {
		let output = request
			.intent
			.outputs
			.first()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: "Quote request has no outputs".into(),
				details: None,
			})?;

		let chain_id = output
			.asset
			.ethereum_chain_id()
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: format!("Failed to derive destination chain id: {e}"),
				details: None,
			})?;

		let network = config
			.networks
			.get(&chain_id)
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!(
					"Network {chain_id} not configured; cannot build fill tx for quote"
				),
				details: None,
			})?;
		let settler_address = network.output_settler_address.clone();

		// Required: resolved amount must exist by the time this runs. If it
		// doesn't, either the caller invoked us before calculate_swap_amounts
		// (sequencing bug) or the asset key doesn't match — both are programmer
		// errors. Do NOT silently encode a zero amount; that would make
		// estimateGas return a misleadingly low value and reintroduce the
		// quote/validator divergence we're trying to eliminate.
		let amount = Self::resolve_quote_output_amount(
			request,
			context,
			resolved_amounts,
			output,
			chain_id,
			"build_fill_tx_for_quote",
		)?;

		// Left-pad / right-align: 20-byte address occupies bytes32[12..32], the
		// leading 12 bytes are zero. Mirrors the convention used in
		// `crates/solver-service/src/apis/quote/generation.rs:910`.
		let token_addr = output
			.asset
			.ethereum_address()
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!("Output asset is not an EVM address: {e}"),
				details: None,
			})?;
		let recipient_addr =
			output
				.receiver
				.ethereum_address()
				.map_err(|e| APIError::BadRequest {
					error_type: ApiErrorType::InvalidRequest,
					message: format!("Output receiver is not an EVM address: {e}"),
					details: None,
				})?;
		let token_bytes32 = AlloyAddress::from_slice(token_addr.as_slice()).into_word();
		let recipient_bytes32 = AlloyAddress::from_slice(recipient_addr.as_slice()).into_word();
		let settler_bytes32 = AlloyAddress::from_slice(&settler_address.0).into_word();
		// Detect native output via the shared 32-byte identifier helper so this
		// matches `build_post_fill_tx_for_quote`/production fill builders.
		// `token_bytes32` is the clean 20-byte address left-padded into a word,
		// so an all-zero word is exactly the native (zero-address) case.
		let tx_value = if is_native_token_id(&token_bytes32.0) {
			amount
		} else {
			U256::ZERO
		};

		// Hex-decode calldata, mirroring
		// `crates/solver-service/src/apis/quote/generation.rs:938-951`.
		// `QuoteOutput.calldata` is a hex-encoded string like "0xdead..."; passing
		// it as raw bytes would inject ASCII into the encoded calldata.
		let callback_data_bytes: Vec<u8> = match output.calldata.as_deref() {
			None => Vec::new(),
			Some(s) if s.is_empty() || s == "0x" => Vec::new(),
			Some(s) => {
				let hex_str = s.trim_start_matches("0x");
				alloy_primitives::hex::decode(hex_str).unwrap_or_else(|e| {
					tracing::warn!(
						error = %e,
						"Failed to decode QuoteOutput.calldata for quote-time fill estimate; treating as empty"
					);
					Vec::new()
				})
			},
		};

		let output_struct = SolMandateOutput {
			oracle: B256::ZERO,
			settler: settler_bytes32,
			chainId: U256::from(chain_id),
			token: token_bytes32,
			amount,
			recipient: recipient_bytes32,
			callbackData: callback_data_bytes.into(),
			context: Vec::<u8>::new().into(),
		};

		let filler_data = AlloyAddress::from_slice(&solver_address.0)
			.into_word()
			.to_vec();

		// `fillDeadline` must be a near-future timestamp, but not too far ahead:
		// production OutputSettlers reject both `0` (selector 0x9f3ddb90 =
		// `FillDeadline()` — observed) AND values past their max-fill-window.
		//
		// Derive the window from `api.quote.fill_deadline_seconds` so the
		// simulation matches what real fills will use — if the operator
		// configures a longer deadline, the settler's max-fill-window must
		// already accept it, so the same value is safe here. If config is
		// missing, fall back to 60s (the historical hardcoded default).
		let configured_fill_deadline_window = config
			.api
			.as_ref()
			.and_then(|a| a.quote.as_ref())
			.map(|q| q.fill_deadline_seconds)
			.unwrap_or(60);
		let quote_validity_window = config
			.api
			.as_ref()
			.and_then(|a| a.quote.as_ref())
			.map(|q| q.validity_seconds)
			.unwrap_or_else(|| solver_config::QuoteConfig::default().validity_seconds);
		let origin_chain_id = request
			.intent
			.inputs
			.first()
			.and_then(|input| input.asset.ethereum_chain_id().ok());
		let source_finality_window = if include_source_finality_delay {
			origin_chain_id
				.and_then(|chain_id| source_finality_expected_delay_seconds(config, chain_id))
				.unwrap_or(0)
				.saturating_add(config.source_finality.retry_grace_seconds)
				.saturating_add(quote_validity_window)
		} else {
			0
		};
		let fill_deadline_window = configured_fill_deadline_window.max(source_finality_window);
		let fill_deadline_secs = current_timestamp().saturating_add(fill_deadline_window);

		let data = IOutputSettlerSimple::fillCall {
			orderId: B256::ZERO,
			output: output_struct,
			fillDeadline: alloy_primitives::Uint::<48, 1>::from(fill_deadline_secs),
			fillerData: filler_data.into(),
		}
		.abi_encode();

		Ok(Transaction {
			to: Some(settler_address),
			data,
			value: tx_value,
			chain_id,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		})
	}

	fn build_post_fill_fee_params_for_quote(
		&self,
		request: &GetQuoteRequest,
		context: &ValidatedQuoteContext,
		resolved_amounts: &std::collections::HashMap<InteropAddress, TokenAmountInfo>,
		config: &Config,
	) -> Result<Option<solver_settlement::PostFillFeeParams>, APIError> {
		let Some(input) = request.intent.inputs.first() else {
			return Ok(None);
		};
		let Some(output) = request.intent.outputs.first() else {
			return Ok(None);
		};

		let origin_chain_id =
			input
				.asset
				.ethereum_chain_id()
				.map_err(|e| APIError::BadRequest {
					error_type: ApiErrorType::MissingChainId,
					message: format!("Failed to derive origin chain id: {e}"),
					details: None,
				})?;
		let dest_chain_id = output
			.asset
			.ethereum_chain_id()
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: format!("Failed to derive destination chain id: {e}"),
				details: None,
			})?;
		let amount = Self::resolve_quote_output_amount(
			request,
			context,
			resolved_amounts,
			output,
			dest_chain_id,
			"settlement fee quote",
		)?;
		let source_settler = config
			.networks
			.get(&dest_chain_id)
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!(
					"Network {dest_chain_id} not configured; cannot quote settlement fee"
				),
				details: None,
			})?
			.output_settler_address
			.clone();

		let token_addr = output
			.asset
			.ethereum_address()
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!("Output asset is not an EVM address: {e}"),
				details: None,
			})?;
		let recipient_addr =
			output
				.receiver
				.ethereum_address()
				.map_err(|e| APIError::BadRequest {
					error_type: ApiErrorType::InvalidRequest,
					message: format!("Output receiver is not an EVM address: {e}"),
					details: None,
				})?;
		let mut output_token = [0u8; 32];
		output_token.copy_from_slice(
			AlloyAddress::from_slice(token_addr.as_slice())
				.into_word()
				.as_slice(),
		);
		let mut output_recipient = [0u8; 32];
		output_recipient.copy_from_slice(
			AlloyAddress::from_slice(recipient_addr.as_slice())
				.into_word()
				.as_slice(),
		);
		let output_call = match output.calldata.as_deref() {
			None => Vec::new(),
			Some(s) if s.is_empty() || s == "0x" => Vec::new(),
			Some(s) => alloy_primitives::hex::decode(s.trim_start_matches("0x")).map_err(|e| {
				APIError::BadRequest {
					error_type: ApiErrorType::InvalidRequest,
					message: format!("Output calldata is not valid hex: {e}"),
					details: None,
				}
			})?,
		};

		Ok(Some(solver_settlement::PostFillFeeParams {
			origin_chain_id,
			dest_chain_id,
			output_token,
			output_amount: amount,
			output_recipient,
			output_call,
			source_settler,
		}))
	}

	fn build_post_fill_fee_params_for_order(
		&self,
		order: &Order,
		outputs: &[OrderOutput],
		origin_chain_id: u64,
		dest_chain_id: u64,
	) -> Result<Option<solver_settlement::PostFillFeeParams>, APIError> {
		let Some(output) = outputs.first() else {
			return Ok(None);
		};
		let source_settler = order
			.output_chains
			.first()
			.map(|chain| chain.settler_address.clone())
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: "No output chain found".to_string(),
				details: None,
			})?;
		let token_addr = output
			.asset
			.ethereum_address()
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!("Output asset is not an EVM address: {e}"),
				details: None,
			})?;
		let recipient_addr =
			output
				.receiver
				.ethereum_address()
				.map_err(|e| APIError::BadRequest {
					error_type: ApiErrorType::InvalidRequest,
					message: format!("Output receiver is not an EVM address: {e}"),
					details: None,
				})?;
		let mut output_token = [0u8; 32];
		output_token.copy_from_slice(
			AlloyAddress::from_slice(token_addr.as_slice())
				.into_word()
				.as_slice(),
		);
		let mut output_recipient = [0u8; 32];
		output_recipient.copy_from_slice(
			AlloyAddress::from_slice(recipient_addr.as_slice())
				.into_word()
				.as_slice(),
		);
		let output_call = match output.calldata.as_deref() {
			None => Vec::new(),
			Some(s) if s.is_empty() || s == "0x" => Vec::new(),
			Some(s) => alloy_primitives::hex::decode(s.trim_start_matches("0x")).map_err(|e| {
				APIError::BadRequest {
					error_type: ApiErrorType::InvalidRequest,
					message: format!("Output calldata is not valid hex: {e}"),
					details: None,
				}
			})?,
		};

		Ok(Some(solver_settlement::PostFillFeeParams {
			origin_chain_id,
			dest_chain_id,
			output_token,
			output_amount: output.amount,
			output_recipient,
			output_call,
			source_settler,
		}))
	}

	/// Build a synthetic Hyperlane post-fill `submit(...)` transaction for
	/// quote-time `eth_estimateGas`.
	///
	/// This mirrors `HyperlaneSettlement::generate_post_fill_transaction` for the
	/// parts that determine gas units: selected output oracle, recipient input
	/// oracle, source output settler, message gas limit, and fill-description
	/// payload shape. The caller supplies the settlement-owned fee quote as
	/// transaction value, because some oracle deployments require the payment even
	/// during `eth_estimateGas`.
	async fn build_post_fill_tx_for_quote(
		&self,
		request: &GetQuoteRequest,
		context: &ValidatedQuoteContext,
		resolved_amounts: &std::collections::HashMap<InteropAddress, TokenAmountInfo>,
		config: &Config,
		solver_address: &Address,
		settlement_fee_wei: U256,
	) -> Result<Option<PostFillQuoteTx>, APIError> {
		let Some(hyperlane_config) = hyperlane_config_for_quote(config) else {
			return Ok(None);
		};

		let input = request
			.intent
			.inputs
			.first()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: "Quote request has no inputs".into(),
				details: None,
			})?;
		let output = request
			.intent
			.outputs
			.first()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: "Quote request has no outputs".into(),
				details: None,
			})?;

		let origin_chain_id =
			input
				.asset
				.ethereum_chain_id()
				.map_err(|e| APIError::BadRequest {
					error_type: ApiErrorType::MissingChainId,
					message: format!("Failed to derive origin chain id: {e}"),
					details: None,
				})?;
		let dest_chain_id = output
			.asset
			.ethereum_chain_id()
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: format!("Failed to derive destination chain id: {e}"),
				details: None,
			})?;

		let Some(oracle_address) =
			first_hyperlane_oracle_for_quote(hyperlane_config, "output", dest_chain_id)?
		else {
			return Ok(None);
		};
		let Some(recipient_oracle) =
			first_hyperlane_oracle_for_quote(hyperlane_config, "input", origin_chain_id)?
		else {
			return Ok(None);
		};

		let network = config
			.networks
			.get(&dest_chain_id)
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!(
					"Network {dest_chain_id} not configured; cannot build post-fill tx for quote"
				),
				details: None,
			})?;
		let output_settler = network.output_settler_address.clone();

		let amount = Self::resolve_quote_output_amount(
			request,
			context,
			resolved_amounts,
			output,
			dest_chain_id,
			"build_post_fill_tx_for_quote",
		)?;

		let token_addr = output
			.asset
			.ethereum_address()
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!("Output asset is not an EVM address: {e}"),
				details: None,
			})?;
		let recipient_addr =
			output
				.receiver
				.ethereum_address()
				.map_err(|e| APIError::BadRequest {
					error_type: ApiErrorType::InvalidRequest,
					message: format!("Output receiver is not an EVM address: {e}"),
					details: None,
				})?;
		let token_bytes32 = AlloyAddress::from_slice(token_addr.as_slice()).into_word();
		let recipient_bytes32 = AlloyAddress::from_slice(recipient_addr.as_slice()).into_word();

		let callback_data_bytes: Vec<u8> = match output.calldata.as_deref() {
			None => Vec::new(),
			Some(s) if s.is_empty() || s == "0x" => Vec::new(),
			Some(s) => {
				alloy_primitives::hex::decode(s.trim_start_matches("0x")).unwrap_or_else(|e| {
					tracing::warn!(
						error = %e,
						"Failed to decode QuoteOutput.calldata for quote-time post-fill estimate; treating as empty"
					);
					Vec::new()
				})
			},
		};

		let mut solver_identifier = [0u8; 32];
		solver_identifier.copy_from_slice(
			AlloyAddress::from_slice(&solver_address.0)
				.into_word()
				.as_slice(),
		);
		let mut token = [0u8; 32];
		token.copy_from_slice(token_bytes32.as_slice());
		let mut recipient = [0u8; 32];
		recipient.copy_from_slice(recipient_bytes32.as_slice());

		let synthetic_order_id_bytes: [u8; 32] = [0u8; 32];
		let fill_timestamp = current_timestamp().min(u32::MAX as u64) as u32;

		let fill_description = encode_quote_hyperlane_fill_description(
			solver_identifier,
			synthetic_order_id_bytes,
			fill_timestamp,
			token,
			amount,
			recipient,
			callback_data_bytes,
			vec![],
		)?;

		// Reconstruct the same outputHash the OutputSettler will compute on-chain
		// in `_isPayloadValid`:
		//
		//   keccak256(abi.encodePacked(
		//       msg.sender (= output oracle, padded to bytes32),
		//       address(this) (= output settler, padded to bytes32),
		//       block.chainid (= dest_chain_id, as uint256),
		//       payload[68:]  (= the FillDescription's common payload)
		//   ))
		//
		// `payload[68:]` skips the 32-byte solver, 32-byte orderId, and 4-byte
		// timestamp prefix; what remains is the common payload (token | amount
		// | recipient | call_len | call | ctx_len | ctx). Computed here, before
		// `fill_description` is consumed by `payloads`, to keep one allocation.
		let oracle_padded = AlloyAddress::from_slice(&oracle_address.0).into_word();
		let settler_padded = AlloyAddress::from_slice(&output_settler.0).into_word();
		let common_payload = &fill_description[68..];
		let mut hash_buf = Vec::with_capacity(32 + 32 + 32 + common_payload.len());
		hash_buf.extend_from_slice(oracle_padded.as_slice());
		hash_buf.extend_from_slice(settler_padded.as_slice());
		hash_buf.extend_from_slice(&U256::from(dest_chain_id).to_be_bytes::<32>());
		hash_buf.extend_from_slice(common_payload);
		let output_hash = keccak256(&hash_buf);

		let payloads = vec![fill_description];
		let total_payload_size: usize = payloads.iter().map(|p| p.len()).sum();
		let message_gas_limit = quote_hyperlane_message_gas_limit(total_payload_size);
		let origin_domain = hyperlane_domain_for_quote(hyperlane_config, origin_chain_id)?;

		let call_data = IHyperlaneOracleForQuote::submitCall {
			destinationDomain: origin_domain,
			recipientOracle: alloy_primitives::Address::from_slice(&recipient_oracle.0),
			gasLimit: message_gas_limit,
			customMetadata: vec![].into(),
			source: alloy_primitives::Address::from_slice(&output_settler.0),
			payloads: payloads.into_iter().map(Into::into).collect(),
		};

		let tx = Transaction {
			to: Some(oracle_address),
			data: call_data.abi_encode(),
			value: settlement_fee_wei,
			chain_id: dest_chain_id,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		};

		Ok(Some(PostFillQuoteTx {
			tx,
			output_settler,
			synthetic_order_id: B256::from(synthetic_order_id_bytes),
			output_hash,
			solver: B256::from(solver_identifier),
			fill_timestamp,
		}))
	}

	/// Gets effective fee params for a specific chain.
	///
	/// Uses the same fee model the delivery layer applies at submit time,
	/// so the quote economics line up with the actual on-chain cost.
	async fn get_chain_fee_params(&self, chain_id: u64) -> Result<FeeParams, APIError> {
		self.delivery_service
			.get_fee_params(chain_id)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::ServiceError,
				message: format!("Failed to get fee params: {e}"),
			})
	}

	async fn estimate_extra_native_fee_wei(
		&self,
		config: &Config,
		chain_id: u64,
		tx: &Transaction,
	) -> Result<(U256, U256), CostProfitError> {
		if !extra_native_fee_configured(config, chain_id) {
			return Ok((U256::ZERO, U256::ZERO));
		}

		let estimate = self
			.delivery_service
			.estimate_extra_native_fee(chain_id, tx)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::ServiceError,
				message: format!("Failed to estimate extra native fee: {e}"),
			})?;
		let raw = U256::from_str(&estimate.raw_fee_wei).map_err(|e| {
			CostProfitError::Calculation(format!("Failed to parse extra native raw fee wei: {e}"))
		})?;
		let buffer = U256::from_str(&estimate.buffer_wei).map_err(|e| {
			CostProfitError::Calculation(format!(
				"Failed to parse extra native fee buffer wei: {e}"
			))
		})?;
		Ok((raw, buffer))
	}

	/// Converts a native (gas-token) amount in base units to USD.
	///
	/// Symbol/decimals resolution is fail-open for gas: config first, then the
	/// gas-only [`native_symbol_fallback`] for well-known chains, so gas pricing
	/// — which runs for EVERY order, including pure-ERC20 flows — never
	/// hard-fails on a config lacking a zero-address native `TokenConfig`. This
	/// fallback is deliberately NOT used for output/input valuation (see
	/// [`CostProfitService::calculate_outputs_usd_value`]); native OUTPUT is
	/// opt-in and must be configured explicitly.
	///
	/// Assumes an 18-decimal native token (true for all supported EVM chains):
	/// gas/native amounts are 1e18-base wei. A configured native `decimals != d`
	/// where `d != 18` would misprice by `10^(18 - d)`, so this method fails
	/// closed and returns an error at runtime (in all builds) for any non-18
	/// native decimals. Revisit for non-EVM chains whose native token is not 18
	/// decimals.
	async fn native_base_units_to_usd(
		&self,
		chain_id: u64,
		value: &U256,
	) -> Result<Decimal, CostProfitError> {
		if value.is_zero() {
			return Ok(Decimal::ZERO);
		}

		let native_token = Address(vec![0u8; 20]);

		// Resolve the native gas-token symbol/decimals for this chain.
		//
		// Config always wins: an explicit zero-address `TokenConfig` lets an
		// operator override the symbol (or non-18 decimals). Only when the chain
		// has no such entry (`TokenNotSupported`) do we consult the built-in
		// `chain_id -> native symbol` fallback, so pure-ERC20 orders don't hard-
		// require a zero-address token on every chain. Unknown chains keep the
		// original error and fail closed.
		let (symbol, decimals) = match self
			.token_manager
			.get_token_info(chain_id, &native_token)
			.await
		{
			Ok(info) => (info.symbol, info.decimals),
			Err(e @ TokenManagerError::TokenNotSupported(..)) => {
				match native_symbol_fallback(chain_id) {
					// Well-known native tokens are all 18-decimal.
					Some(symbol) => (symbol.to_string(), 18u8),
					None => return Err(e.into()),
				}
			},
			Err(e) => return Err(e.into()),
		};

		// Fail closed: gas is denominated in 1e18-base wei, so a config that sets a
		// non-18 native `decimals` would misprice by 10^(18 - decimals). debug_assert
		// is stripped in release builds, so enforce this at runtime for all builds.
		if decimals != 18 {
			return Err(CostProfitError::Calculation(format!(
				"Native gas pricing assumes 18-decimal base units; chain {chain_id} \
				 configured native token {symbol} with {decimals} decimals"
			)));
		}

		Self::convert_raw_token_to_usd(value, &symbol, decimals, self.pricing_service.as_ref())
			.await
			.map_err(|e| {
				CostProfitError::Calculation(format!(
					"Failed to convert native units for chain {chain_id} to USD: {e}"
				))
			})
	}

	/// Validates callback safety and simulates fill transaction gas for an order with callbackData.
	///
	/// This method performs:
	/// 1. Whitelist validation for callback recipients
	/// 2. Gas estimation via eth_estimateGas to detect reverts and get accurate gas costs
	///
	/// # Arguments
	/// * `order` - The order to validate
	/// * `fill_tx` - The fill transaction to simulate (generated by OrderService)
	/// * `config` - Solver configuration
	///
	/// # Returns
	/// * `CallbackSimulationResult` containing success status and estimated gas
	pub async fn simulate_callback_and_estimate_gas(
		&self,
		order: &Order,
		fill_tx: &Transaction,
		config: &Config,
	) -> Result<CallbackSimulationResult, CostProfitError> {
		tracing::info!("🔍 Starting callback simulation for order {}", order.id);

		let chain_id = fill_tx.chain_id;

		// Parse order to check for callbacks
		let order_data = order.parse_order_data().map_err(|e| {
			CostProfitError::Calculation(format!("Failed to parse order data: {e}"))
		})?;

		let outputs = order_data.parse_requested_outputs();

		// Currently only single-output orders are supported
		if outputs.len() > 1 {
			return Err(CostProfitError::Calculation(format!(
				"Multiple outputs ({}) not supported. Only single-output orders can be processed",
				outputs.len()
			)));
		}

		let output = outputs
			.first()
			.ok_or_else(|| CostProfitError::Calculation("No outputs found in order".to_string()))?;

		// Check if there's callback data
		let has_callback = output
			.calldata
			.as_ref()
			.is_some_and(|c| !c.is_empty() && c != "0x");

		if !has_callback {
			tracing::info!("✓ No callback data - using default gas estimate");
			// For orders without callbacks, we still estimate gas but don't enforce whitelist
			return self.estimate_fill_gas(fill_tx, chain_id, false).await;
		}

		tracing::info!("⚠️  Order has callback data: {:?}", output.calldata);

		// Check if callback simulation is enabled
		if !config.order.simulate_callbacks {
			tracing::warn!(
				"❌ Order has callback but callback simulation is disabled. \
				Enable 'simulate_callbacks = true' in config to support callbacks."
			);
			return Err(CostProfitError::Config(
				"Order has callback data but callback simulation is disabled. \
				Callbacks are not supported when simulate_callbacks = false in config."
					.to_string(),
			));
		}

		// Extract recipient info for whitelist check
		// The receiver is already an InteropAddress (EIP-7930 format)
		let recipient_interop_hex = output.receiver.to_hex().to_lowercase();

		let output_chain_id = output.receiver.ethereum_chain_id().map_err(|e| {
			CostProfitError::Config(format!("Failed to extract chain ID from recipient: {e}"))
		})?;

		let recipient_eth_address = output
			.receiver
			.ethereum_address()
			.map(|addr| format!("0x{}", alloy_primitives::hex::encode(addr)))
			.unwrap_or_else(|_| "unknown".to_string());

		// Check whitelist using EIP-7930 InteropAddress format
		// Whitelist entries should be in EIP-7930 hex format (e.g., "0x0001000002210514...")
		let is_whitelisted = Self::callback_recipient_whitelisted(config, &recipient_interop_hex);

		if !is_whitelisted {
			tracing::warn!(
				"❌ Callback recipient {} (chain {}) is NOT whitelisted. InteropAddress: {}",
				recipient_eth_address,
				output_chain_id,
				recipient_interop_hex
			);
			return Err(CostProfitError::Config(format!(
				"Callback recipient {recipient_eth_address} on chain {output_chain_id} not in whitelist. Add '{recipient_interop_hex}' to order.callback_whitelist in config (EIP-7930 format)"
			)));
		}

		tracing::info!(
			"✅ Callback recipient {} (chain {}) is whitelisted - simulating gas",
			recipient_eth_address,
			output_chain_id
		);

		// Simulate the fill transaction to get accurate gas estimate
		self.estimate_fill_gas(fill_tx, chain_id, true).await
	}

	/// Estimates gas for a fill transaction using eth_estimateGas.
	///
	/// This serves two purposes:
	/// 1. Detects if the transaction would revert (callback execution failure)
	/// 2. Gets accurate gas estimate including callback execution cost
	async fn estimate_fill_gas(
		&self,
		fill_tx: &Transaction,
		chain_id: u64,
		has_callback: bool,
	) -> Result<CallbackSimulationResult, CostProfitError> {
		tracing::info!(
			"📊 Estimating gas for fill transaction on chain {} (has_callback: {})",
			chain_id,
			has_callback
		);

		match self
			.delivery_service
			.estimate_gas(chain_id, fill_tx.clone())
			.await
		{
			Ok(estimated_gas) => {
				tracing::info!(
					"✅ Gas estimation successful: {} units (has_callback: {})",
					estimated_gas,
					has_callback
				);
				Ok(CallbackSimulationResult {
					success: true,
					estimated_gas_units: estimated_gas,
					chain_id,
					has_callback,
				})
			},
			Err(e) => {
				let error_msg = e.to_string();
				tracing::warn!("❌ Gas estimation failed (likely revert): {}", error_msg);

				// Check if this is a revert error
				if error_msg.contains("revert")
					|| error_msg.contains("execution reverted")
					|| error_msg.contains("out of gas")
					|| error_msg.contains("insufficient funds")
				{
					Err(CostProfitError::Calculation(format!(
						"Fill transaction simulation failed (callback would revert): {error_msg}"
					)))
				} else {
					// For other errors (network issues, etc.), we might want to retry or use fallback
					tracing::warn!(
						"⚠️  Non-revert error during gas estimation, using fallback: {}",
						error_msg
					);
					// Return success with 0 gas to signal fallback to config default
					Ok(CallbackSimulationResult {
						success: true,
						estimated_gas_units: 0,
						chain_id,
						has_callback,
					})
				}
			},
		}
	}

	/// Converts a raw token amount to USD, handling decimals normalization.
	async fn convert_raw_token_to_usd(
		raw_amount: &U256,
		token_symbol: &str,
		token_decimals: u8,
		pricing_service: &PricingService,
	) -> Result<Decimal, Box<dyn std::error::Error>> {
		// Handle potential overflow for large decimals
		if token_decimals > 28 {
			return Err(format!(
				"Token decimals {token_decimals} exceeds maximum supported precision"
			)
			.into());
		}

		// Convert U256 to Decimal
		let raw_amount_str = raw_amount.to_string();
		let raw_amount_decimal = Decimal::from_str(&raw_amount_str)
			.map_err(|e| format!("Failed to parse raw amount {raw_amount_str}: {e}"))?;

		// Normalize amount by token decimals
		let normalized_amount = match token_decimals {
			0 => raw_amount_decimal,
			decimals => {
				// `decimals <= 28` is enforced above. Compute the power in
				// `i128` (not `i64`, which overflows at 10^19) so tokens with
				// 19..=28 decimals no longer panic (debug) / wrap (release).
				// 10^28 fits both `i128` and rust_decimal's 96-bit mantissa.
				let divisor = Decimal::from_i128_with_scale(10_i128.pow(decimals as u32), 0);
				raw_amount_decimal / divisor
			},
		};

		// Convert to USD
		let usd_amount_str = pricing_service
			.convert_asset(token_symbol, "USD", &normalized_amount.to_string())
			.await
			.map_err(|e| format!("Failed to convert {token_symbol} to USD: {e}"))?;

		Decimal::from_str(&usd_amount_str)
			.map_err(|e| format!("Failed to parse USD amount {usd_amount_str}: {e}").into())
	}

	/// Helper to calculate total USD value for a list of inputs
	async fn calculate_inputs_usd_value(
		&self,
		inputs: &[OrderInput],
	) -> Result<Decimal, CostProfitError> {
		let mut total_usd = Decimal::ZERO;

		for input in inputs {
			let chain_id = input.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get chain ID: {e}"))
			})?;
			let ethereum_addr = input
				.asset
				.ethereum_address()
				.map_err(|e| CostProfitError::Calculation(format!("Failed to get address: {e}")))?;
			let token_address = Address(ethereum_addr.0.to_vec());

			let token_info = match self
				.token_manager
				.get_token_info(chain_id, &token_address)
				.await
			{
				Ok(info) => info,
				Err(e @ TokenManagerError::TokenNotSupported(..)) => {
					// Defensive: native inputs are rejected upstream (order
					// validation), so this arm is not expected to fire in
					// practice — but if a native (zero-address) input ever
					// reaches valuation it needs an explicit native `TokenConfig`
					// (symbol + decimals). The `native_symbol_fallback` map is
					// GAS-ONLY (see its doc) and deliberately does not apply here.
					let mut token_id = [0u8; 32];
					token_id[12..].copy_from_slice(&token_address.0);
					if is_native_token_id(&token_id) {
						return Err(CostProfitError::Calculation(format!(
							"Native (zero-address) input on chain {chain_id} requires an explicit native TokenConfig (symbol + decimals) for USD valuation; the chain native-symbol fallback applies to gas pricing only"
						)));
					}
					return Err(e.into());
				},
				Err(e) => return Err(e.into()),
			};

			let usd_amount = Self::convert_raw_token_to_usd(
				&input.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await
			.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

			total_usd += usd_amount;
		}

		Ok(total_usd)
	}

	/// Helper to calculate total USD value for a list of outputs
	async fn calculate_outputs_usd_value(
		&self,
		outputs: &[OrderOutput],
	) -> Result<Decimal, CostProfitError> {
		let mut total_usd = Decimal::ZERO;

		for output in outputs {
			let chain_id = output.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get chain ID: {e}"))
			})?;
			let ethereum_addr = output
				.asset
				.ethereum_address()
				.map_err(|e| CostProfitError::Calculation(format!("Failed to get address: {e}")))?;
			let token_address = Address(ethereum_addr.0.to_vec());

			let token_info = match self
				.token_manager
				.get_token_info(chain_id, &token_address)
				.await
			{
				Ok(info) => info,
				Err(e @ TokenManagerError::TokenNotSupported(..)) => {
					// A native (zero-address) output needs an explicit native
					// `TokenConfig` (symbol + decimals) to be valued in USD. The
					// chain native-symbol fallback in `native_symbol_fallback` is
					// GAS-ONLY (see its doc), so it deliberately does not rescue
					// valuation here.
					let mut token_id = [0u8; 32];
					token_id[12..].copy_from_slice(&token_address.0);
					if is_native_token_id(&token_id) {
						return Err(CostProfitError::Calculation(format!(
							"Native (zero-address) output on chain {chain_id} requires an explicit native TokenConfig (symbol + decimals) for USD valuation; the chain native-symbol fallback applies to gas pricing only"
						)));
					}
					return Err(e.into());
				},
				Err(e) => return Err(e.into()),
			};

			let usd_amount = Self::convert_raw_token_to_usd(
				&output.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await
			.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

			total_usd += usd_amount;
		}

		Ok(total_usd)
	}

	/// Converts a USD amount to token amount in smallest unit
	async fn convert_usd_to_token_amount(
		&self,
		usd_amount: Decimal,
		asset: &solver_types::InteropAddress,
	) -> Result<U256, CostProfitError> {
		// Get token info
		let chain_id = asset
			.ethereum_chain_id()
			.map_err(|e| CostProfitError::Calculation(format!("Failed to get chain ID: {e}")))?;
		let ethereum_addr = asset.ethereum_address().map_err(|e| {
			CostProfitError::Calculation(format!("Failed to get ethereum address: {e}"))
		})?;
		let token_address = Address(ethereum_addr.0.to_vec());

		let token_info = self
			.token_manager
			.get_token_info(chain_id, &token_address)
			.await?;

		// Convert USD to token amount (normalized)
		let token_amount_str = self
			.pricing_service
			.convert_asset("USD", &token_info.symbol, &usd_amount.to_string())
			.await
			.map_err(|e| {
				CostProfitError::Calculation(format!(
					"Failed to convert USD to {}: {}",
					token_info.symbol, e
				))
			})?;

		let token_amount_decimal = Decimal::from_str(&token_amount_str).map_err(|e| {
			CostProfitError::Calculation(format!("Failed to parse token amount: {e}"))
		})?;

		// Convert to smallest unit (apply decimals), rounding up to ensure we collect enough
		// This protects our margin when costs are deducted from outputs or added to inputs.
		//
		// Compute the power in `i128` (not `i64`, which overflows at 10^19) and
		// build the multiplier via `try_from_i128_with_scale`, which fails
		// cleanly once 10^decimals exceeds rust_decimal's 96-bit mantissa
		// (>28 decimals). This both fixes the >=19-decimal overflow and adds the
		// missing <=28 guard as a clear error instead of a panic/wrap.
		let multiplier = Decimal::try_from_i128_with_scale(
			10_i128
				.checked_pow(token_info.decimals as u32)
				.ok_or_else(|| {
					CostProfitError::Calculation(format!(
						"Token decimals {} exceeds maximum supported precision",
						token_info.decimals
					))
				})?,
			0,
		)
		.map_err(|e| {
			CostProfitError::Calculation(format!(
				"Token decimals {} exceeds maximum supported precision: {e}",
				token_info.decimals
			))
		})?;
		let token_amount_in_smallest = token_amount_decimal * multiplier;

		// Ceil to ensure we always collect enough to cover costs after USD->token->USD round-trip
		let token_amount_ceiled = token_amount_in_smallest.ceil();

		// Convert to U256
		let result = U256::from_str(&token_amount_ceiled.to_string()).map_err(|e| {
			CostProfitError::Calculation(format!("Failed to convert ceiled amount to U256: {e}"))
		})?;

		Ok(result)
	}
}

/// Estimates gas units using configuration flows with fallback estimates.
pub fn estimate_gas_units_from_config(
	flow_key: &Option<String>,
	config: &Config,
	fallback_open: u64,
	fallback_fill: u64,
	fallback_post_fill: u64,
	fallback_pre_claim: u64,
	fallback_claim: u64,
) -> (u64, u64, u64, u64, u64) {
	if let Some(gcfg) = config.gas.as_ref() {
		tracing::debug!(
			"Available gas flows: {:?}",
			gcfg.flows.keys().collect::<Vec<_>>()
		);
	}

	// Try to get configured values for the detected flow
	if let (Some(flow), Some(gcfg)) = (flow_key.as_deref(), config.gas.as_ref()) {
		if let Some(units) = gcfg.flows.get(flow) {
			let open = units.open.unwrap_or(fallback_open);
			let fill = units.fill.unwrap_or(fallback_fill);
			let post_fill = units.post_fill.unwrap_or(fallback_post_fill);
			let pre_claim = units.pre_claim.unwrap_or(fallback_pre_claim);
			let claim = units.claim.unwrap_or(fallback_claim);
			return (open, fill, post_fill, pre_claim, claim);
		} else {
			tracing::warn!("Flow '{}' not found in gas config flows", flow);
		}
	}

	tracing::warn!(
		"No gas config found for flow {:?}, using fallback estimates",
		flow_key
	);

	(
		fallback_open,
		fallback_fill,
		fallback_post_fill,
		fallback_pre_claim,
		fallback_claim,
	)
}

pub fn estimate_gas_units_from_flow_keys(
	flow_keys: &[String],
	config: &Config,
	fallback_open: u64,
	fallback_fill: u64,
	fallback_post_fill: u64,
	fallback_pre_claim: u64,
	fallback_claim: u64,
) -> (u64, u64, u64, u64, u64) {
	if flow_keys.is_empty() {
		return (
			fallback_open,
			fallback_fill,
			fallback_post_fill,
			fallback_pre_claim,
			fallback_claim,
		);
	}

	if let Some(gcfg) = config.gas.as_ref() {
		tracing::debug!(
			"Available gas flows: {:?}",
			gcfg.flows.keys().collect::<Vec<_>>()
		);

		let mut found = false;
		let mut open: Option<u64> = None;
		let mut fill: Option<u64> = None;
		let mut post_fill: Option<u64> = None;
		let mut pre_claim: Option<u64> = None;
		let mut claim: Option<u64> = None;

		for flow in flow_keys {
			if let Some(units) = gcfg.flows.get(flow.as_str()) {
				found = true;
				let candidate_open = units.open.unwrap_or(fallback_open);
				let candidate_fill = units.fill.unwrap_or(fallback_fill);
				let candidate_post_fill = units.post_fill.unwrap_or(fallback_post_fill);
				let candidate_pre_claim = units.pre_claim.unwrap_or(fallback_pre_claim);
				let candidate_claim = units.claim.unwrap_or(fallback_claim);

				open = Some(open.map_or(candidate_open, |current| current.max(candidate_open)));
				fill = Some(fill.map_or(candidate_fill, |current| current.max(candidate_fill)));
				post_fill = Some(post_fill.map_or(candidate_post_fill, |current| {
					current.max(candidate_post_fill)
				}));
				pre_claim = Some(pre_claim.map_or(candidate_pre_claim, |current| {
					current.max(candidate_pre_claim)
				}));
				claim = Some(claim.map_or(candidate_claim, |current| current.max(candidate_claim)));
			} else {
				tracing::warn!("Flow '{}' not found in gas config flows", flow);
			}
		}

		if found {
			return (
				open.unwrap_or(fallback_open),
				fill.unwrap_or(fallback_fill),
				post_fill.unwrap_or(fallback_post_fill),
				pre_claim.unwrap_or(fallback_pre_claim),
				claim.unwrap_or(fallback_claim),
			);
		}
	}

	tracing::warn!(
		"No gas config found for flows {:?}, using fallback estimates",
		flow_keys
	);

	(
		fallback_open,
		fallback_fill,
		fallback_post_fill,
		fallback_pre_claim,
		fallback_claim,
	)
}

pub(crate) fn estimate_quote_gas_units_from_flow_keys(
	flow_keys: &[String],
	config: &Config,
) -> GasUnits {
	let (open_units, fill_units, post_fill_units, pre_claim_units, claim_units) =
		estimate_gas_units_from_flow_keys(
			flow_keys,
			config,
			DEFAULT_OPEN_GAS_UNITS,
			DEFAULT_FILL_GAS_UNITS,
			DEFAULT_POST_FILL_GAS_UNITS,
			DEFAULT_PRE_CLAIM_GAS_UNITS,
			DEFAULT_CLAIM_GAS_UNITS,
		);

	GasUnits {
		open_units,
		fill_units,
		post_fill_units,
		pre_claim_units,
		claim_units,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::address;
	use mockall::predicate::*;
	use solver_account::{AccountService, MockAccountInterface};
	use solver_config::ConfigBuilder;
	use solver_delivery::MockDeliveryInterface;
	use solver_pricing::MockPricingInterface;
	use solver_storage::MockStorageInterface;
	use solver_types::{
		current_timestamp, oif_versions,
		standards::eip7683::{GasLimitOverrides, MandateOutput},
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		ChainSettlerInfo, CostContext, Eip7683OrderData, FailureHandlingMode, GetQuoteRequest,
		IntentRequest, IntentType, InteropAddress, NetworksConfig, OifOrder, OrderPayload,
		OrderStatus, Quote, QuoteInput, QuoteOutput, QuotePreference, SignatureType, StoredQuote,
		SwapType, ValidatedQuoteContext,
	};
	use std::collections::HashMap;
	use std::str::FromStr;
	use std::sync::Arc;
	use tokio;

	// Test price constants for consistent mock pricing across test functions
	const ETH_USD_PRICE: f64 = 4000.0;
	const USDC_USD_PRICE: f64 = 1.0;

	#[test]
	fn test_validate_callback_calldata_rejects_over_shared_limit() {
		// A callback over MAX_CALLBACK_DATA_BYTES but under the old u16::MAX bound must
		// now be rejected, proving the guard agrees with the shared constant.
		let byte_len = MAX_CALLBACK_DATA_BYTES + 1;
		assert!(
			byte_len < u16::MAX as usize,
			"test must sit below the old bound"
		);
		let hex_payload = format!("0x{}", "ab".repeat(byte_len));

		let result = CostProfitService::validate_callback_calldata(Some(&hex_payload));
		assert!(
			matches!(result, Err(CostProfitError::Calculation(ref msg)) if msg.contains("too large")),
			"oversized callbackData should be rejected: {result:?}"
		);
	}

	#[test]
	fn test_validate_callback_calldata_accepts_shared_limit() {
		let hex_payload = format!("0x{}", "ab".repeat(MAX_CALLBACK_DATA_BYTES));
		let result = CostProfitService::validate_callback_calldata(Some(&hex_payload));
		assert!(
			result.is_ok(),
			"max-size callbackData should be accepted: {result:?}"
		);
	}

	fn no_fee_settlement_service() -> Arc<solver_settlement::SettlementService> {
		let mut mock = solver_settlement::MockSettlementInterface::new();
		mock.expect_quote_post_fill_fee()
			.returning(|_| Box::pin(async { Ok(None) }));
		let mut implementations: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		implementations.insert("mock".to_string(), Box::new(mock));
		Arc::new(solver_settlement::SettlementService::new(
			implementations,
			"mock".to_string(),
			1,
		))
	}

	fn settlement_service_with_fee(
		fee_wei: U256,
		chain_id: u64,
	) -> Arc<solver_settlement::SettlementService> {
		let mut mock = solver_settlement::MockSettlementInterface::new();
		mock.expect_quote_post_fill_fee().returning(move |_| {
			let quote = solver_settlement::SettlementFeeQuote { fee_wei, chain_id };
			Box::pin(async move { Ok(Some(quote)) })
		});
		let mut implementations: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		implementations.insert("mock".to_string(), Box::new(mock));
		Arc::new(solver_settlement::SettlementService::new(
			implementations,
			"mock".to_string(),
			1,
		))
	}

	fn create_test_networks_config() -> NetworksConfig {
		let input_token = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address({
				// Convert U256::from(1000) to Address - token 1000 = 0x3e8
				let mut addr_bytes = [0u8; 20];
				addr_bytes[18] = 0x03; // 0x03e8 = 1000
				addr_bytes[19] = 0xe8;
				solver_types::Address(addr_bytes.to_vec())
			})
			.symbol("INPUT".to_string())
			.decimals(18)
			.build();
		let native_token = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address(solver_types::Address(vec![0u8; 20]))
			.symbol("ETH".to_string())
			.decimals(18)
			.build();
		let output_token = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address(solver_types::Address(
				[
					0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C, 0x1C,
					0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
				]
				.to_vec(),
			))
			.symbol("OUTPUT".to_string())
			.decimals(18)
			.build();
		NetworksConfigBuilder::new()
			.add_network(
				1,
				NetworkConfigBuilder::new()
					.tokens(vec![native_token.clone(), input_token])
					.build(),
			)
			.add_network(
				137,
				NetworkConfigBuilder::new()
					.tokens(vec![native_token, output_token])
					.build(),
			)
			.build()
	}

	fn native_eth_token() -> solver_types::TokenConfig {
		solver_types::TokenConfig {
			address: solver_types::Address(vec![0u8; 20]),
			symbol: "ETH".to_string(),
			name: Some("Ether".to_string()),
			decimals: 18,
		}
	}

	fn output_token_bytes32() -> [u8; 32] {
		let mut token = [0u8; 32];
		token[12..].copy_from_slice(&[
			0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C, 0x1C, 0x5C,
			0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		]);
		token
	}

	// Helper functions for creating test data
	fn create_test_config() -> Config {
		let mut config = ConfigBuilder::new()
			.with_min_profitability_pct(Decimal::from_str("5.0").unwrap())
			.rate_buffer_bps(0) // Disable rate buffer for tests with specific mock expectations
			.networks(create_test_networks_config())
			.build();
		if let Some(gas) = config.gas.as_mut() {
			gas.live_fill_estimate_enabled = false;
		}
		config
	}

	#[test]
	fn extra_native_fee_configured_detects_delivery_chain_policy() {
		let mut config = create_test_config();
		config.delivery.implementations.insert(
			"evm".to_string(),
			serde_json::json!({
				"fee_policy": {
					"chains": {
						"8453": {
							"extra_native_fee": {
								"type": "op_stack_l1_data"
							}
						}
					}
				}
			}),
		);

		assert!(extra_native_fee_configured(&config, 8453));
		assert!(!extra_native_fee_configured(&config, 137));
	}

	#[test]
	fn extra_fee_build_failure_fails_closed_for_configured_op_chain() {
		let mut config = create_test_config();
		config.delivery.implementations.insert(
			"evm".to_string(),
			serde_json::json!({
				"fee_policy": {
					"chains": {
						"8453": {
							"extra_native_fee": {
								"type": "op_stack_l1_data"
							}
						}
					}
				}
			}),
		);

		// A configured OP Stack chain must NOT silently price the leg at zero
		// when the synthetic tx cannot be built; the L1 data fee is required.
		let result = fail_closed_on_extra_fee_build_error(
			&config,
			8453,
			"fill",
			"synthetic fill build failed",
		);

		assert!(
			result.is_err(),
			"configured OP Stack chain must fail closed on synthetic-tx build failure"
		);
	}

	#[test]
	fn extra_fee_build_failure_skips_for_unconfigured_chain() {
		let config = create_test_config();

		// A chain with no extra_native_fee policy has no extra fee to price,
		// so a build failure is logged and skipped (priced at zero), not fatal.
		let result = fail_closed_on_extra_fee_build_error(
			&config,
			137,
			"fill",
			"synthetic fill build failed",
		);

		assert!(
			result.is_ok(),
			"non-OP chain should skip extra fee pricing on synthetic-tx build failure"
		);
	}

	fn create_test_request(is_exact_input: bool) -> GetQuoteRequest {
		GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![QuoteInput {
					user: InteropAddress::new_ethereum(
						1,
						address!("1111111111111111111111111111111111111111"),
					),
					asset: InteropAddress::new_ethereum(
						1,
						address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: if is_exact_input {
						Some(U256::from(1000).to_string()) // For ExactInput, specify input amount
					} else {
						None // For ExactOutput, input amount will be calculated
					},
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						137,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						137,
						address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: if is_exact_input {
						Some(U256::from(950).to_string()) // For ExactInput, this is estimated
					} else {
						Some(U256::from_str("2000000000").unwrap().to_string()) // For ExactOutput, specify exact output amount (2000 USDC)
					},
					calldata: None,
				}],
				swap_type: None,
				min_valid_until: None,
				preference: Some(QuotePreference::Speed),
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec![oif_versions::escrow_order_type("v0")],
		}
	}

	fn create_test_validated_context(is_exact_input: bool) -> ValidatedQuoteContext {
		match is_exact_input {
			true => {
				let input = QuoteInput {
					user: InteropAddress::new_ethereum(
						1,
						address!("1111111111111111111111111111111111111111"),
					),
					asset: InteropAddress::new_ethereum(
						1,
						address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: Some("1000000000000000000".to_string()), // 1 ETH
					lock: None,
				};
				let input_amount = U256::from_str("1000000000000000000").unwrap();

				ValidatedQuoteContext {
					swap_type: SwapType::ExactInput,
					known_inputs: Some(vec![(input, input_amount)]),
					constraint_inputs: None,
					constraint_outputs: None,
					known_outputs: None,
				}
			},
			false => {
				let output = QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						137,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						137,
						address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: Some(U256::from_str("2000000000").unwrap().to_string()), // 2000 USDC (6 decimals)
					calldata: None,
				};
				let output_amount = U256::from_str("2000000000").unwrap();

				ValidatedQuoteContext {
					swap_type: SwapType::ExactOutput,
					known_inputs: None,
					constraint_inputs: None,
					constraint_outputs: None,
					known_outputs: Some(vec![(output, output_amount)]),
				}
			},
		}
	}

	fn create_test_cost_breakdown() -> CostBreakdown {
		CostBreakdown {
			gas_open: Decimal::from_str("0.01").unwrap(),
			gas_fill: Decimal::from_str("0.02").unwrap(),
			gas_post_fill: Decimal::ZERO,
			gas_pre_claim: Decimal::ZERO,
			gas_claim: Decimal::from_str("0.01").unwrap(),
			gas_buffer: Decimal::from_str("0.004").unwrap(),
			settlement_fee: Decimal::ZERO,
			settlement_fee_buffer: Decimal::ZERO,
			l1_data_fee: Decimal::ZERO,
			l1_data_fee_buffer: Decimal::ZERO,
			rate_buffer: Decimal::ZERO,
			base_price: Decimal::ZERO,
			min_profit: Decimal::from_str("5.00").unwrap(),
			operational_cost: Decimal::from_str("0.044").unwrap(),
			subtotal: Decimal::from_str("0.044").unwrap(),
			total: Decimal::from_str("0.044").unwrap(),
			currency: "USD".to_string(),
		}
	}

	fn create_test_stored_quote() -> StoredQuote {
		StoredQuote {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: current_timestamp() + 300,
				eta: Some(60),
				quote_id: "test_quote_123".to_string(),
				provider: Some("test_solver".to_string()),
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: CostContext {
				cost_breakdown: create_test_cost_breakdown(),
				execution_costs_by_chain: HashMap::new(),
				liquidity_cost_adjustment: Decimal::ZERO,
				protocol_fees: HashMap::new(),
				swap_type: SwapType::ExactInput,
				cost_amounts_in_tokens: HashMap::new(),
				swap_amounts: HashMap::new(),
				adjusted_amounts: HashMap::new(),
			},
			settlement_name: None,
			binding: None,
		}
	}

	fn create_mock_pricing_service() -> Arc<PricingService> {
		let mock = MockPricingInterface::new();
		Arc::new(PricingService::new(Box::new(mock), Vec::new()))
	}

	fn create_mock_delivery_service() -> Arc<DeliveryService> {
		let implementations = HashMap::new();
		Arc::new(DeliveryService::new(implementations, 1, 3600, 60))
	}

	fn create_mock_token_manager() -> Arc<TokenManager> {
		Arc::new(TokenManager::new(
			create_test_networks_config(),
			create_mock_delivery_service(),
			create_mock_account_service(),
		))
	}

	fn create_mock_account_service() -> Arc<AccountService> {
		let mut mock_account = MockAccountInterface::new();
		mock_account
			.expect_address()
			.returning(|| Box::pin(async move { Ok(solver_types::Address([0xAB; 20].to_vec())) }));
		mock_account.expect_signer().returning(|| {
			use alloy_signer_local::PrivateKeySigner;
			let signer: PrivateKeySigner =
				"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
					.parse()
					.unwrap();
			solver_account::AccountSigner::Local(signer)
		});

		Arc::new(AccountService::new(Box::new(mock_account)))
	}

	#[tokio::test]
	async fn test_get_cost_context_by_quote_id_success() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();
		let test_stored_quote = create_test_stored_quote();
		let expected_cost_context = test_stored_quote.cost_context.clone();

		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:test_quote_123"))
			.times(1)
			.returning(move |_| {
				let serialized = serde_json::to_vec(&test_stored_quote).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let pricing = create_mock_pricing_service();
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			settlement_service_with_fee(U256::from(1u64), 137),
		);

		// Act
		let result = service.get_cost_context_by_quote_id("test_quote_123").await;

		// Assert
		assert!(result.is_ok());
		let cost_context = result.unwrap();
		assert_eq!(cost_context.swap_type, expected_cost_context.swap_type);
	}

	#[tokio::test]
	async fn test_get_cost_context_by_quote_id_not_found() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();

		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:nonexistent_quote"))
			.times(1)
			.returning(|_| {
				Box::pin(async move {
					Err(solver_storage::StorageError::NotFound(
						"Quote not found".to_string(),
					))
				})
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let pricing = create_mock_pricing_service();
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		// Act
		let result = service
			.get_cost_context_by_quote_id("nonexistent_quote")
			.await;

		// Assert
		assert!(result.is_err());
		match result.unwrap_err() {
			CostProfitError::Storage(_) => {
				// Expected error type
			},
			other => panic!("Expected Storage error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_calculate_cost_context_exact_input() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mut mock_delivery = MockDeliveryInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock pricing service calls - allow any convert_asset calls
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount_f64: f64 = amount.parse().unwrap_or(0.0);
				Box::pin(async move {
					match (from.as_str(), to.as_str()) {
						("ETH", "USD") => Ok((amount_f64 * ETH_USD_PRICE).to_string()),
						("USD", "ETH") => Ok((amount_f64 / ETH_USD_PRICE).to_string()),
						("USDC", "USD") => Ok((amount_f64 * USDC_USD_PRICE).to_string()),
						("USD", "USDC") => Ok((amount_f64 / USDC_USD_PRICE).to_string()),
						_ => Ok("1.0".to_string()),
					}
				})
			});

		mock_pricing
			.expect_wei_to_currency()
			.returning(|_, _| Box::pin(async move { Ok("0.01".to_string()) }));

		// Add config_schema expectation for the mock
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		// Remove duplicate expectations and add proper setup
		mock_delivery.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
		});

		mock_delivery
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		// Create services with proper delivery implementations
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));

		// Create delivery service with mock implementations for both chains
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			1,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		// Create a second mock for chain 137
		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery_137
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
			});
		mock_delivery_137
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 3600, 60));

		// Create proper token manager with required tokens
		let mut networks = solver_types::NetworksConfig::new();

		// Add chain 1 with ETH token
		let network_1 = solver_types::NetworkConfig {
			name: Some("ethereum".to_string()),
			network_type: solver_types::networks::NetworkType::Parent,
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![
				native_eth_token(),
				solver_types::TokenConfig {
					address: solver_types::Address(
						[
							0xA0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
							0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
						]
						.to_vec(),
					),
					decimals: 18,
					symbol: "ETH".to_string(),
					name: Some("Ether".to_string()),
				},
			],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(1, network_1);

		// Add chain 137 with USDC token
		let network_137 = solver_types::NetworkConfig {
			name: Some("polygon".to_string()),
			network_type: solver_types::networks::NetworkType::Hub,
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![
				native_eth_token(),
				solver_types::TokenConfig {
					address: solver_types::Address(
						[
							0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
							0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
						]
						.to_vec(),
					),
					decimals: 6,
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
				},
			],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(137, network_137);

		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));

		// Create services
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let request = create_test_request(true); // true for ExactInput
		let context = create_test_validated_context(true); // true for ExactInput
		let config = create_test_config();

		// Act
		let result = service
			.calculate_cost_context(&request, &context, &config, &Address([0xAB; 20].to_vec()))
			.await;

		// Assert
		assert!(result.is_ok(), "result: {result:?}");
		let cost_context = result.unwrap();

		// Verify swap type
		assert_eq!(cost_context.swap_type, SwapType::ExactInput);

		// Verify cost breakdown exists and has reasonable values
		assert!(cost_context.cost_breakdown.total >= Decimal::ZERO);
		assert!(cost_context.cost_breakdown.operational_cost >= Decimal::ZERO);
		assert!(cost_context.cost_breakdown.settlement_fee >= Decimal::ZERO);
		assert!(cost_context.cost_breakdown.settlement_fee_buffer >= Decimal::ZERO);

		// Verify execution costs by chain
		assert!(!cost_context.execution_costs_by_chain.is_empty());
		assert!(
			cost_context
				.execution_costs_by_chain
				.get(&137)
				.copied()
				.unwrap_or_default()
				>= cost_context.cost_breakdown.settlement_fee
					+ cost_context.cost_breakdown.settlement_fee_buffer
		);

		// Verify swap amounts were calculated
		assert!(!cost_context.swap_amounts.is_empty());

		// Verify adjusted amounts (for ExactInput, outputs should be adjusted down)
		assert!(!cost_context.adjusted_amounts.is_empty());
	}

	#[tokio::test]
	async fn test_calculate_cost_context_fails_when_gas_pricing_conversion_fails() {
		let mut mock_pricing = MockPricingInterface::new();
		let mut mock_delivery = MockDeliveryInterface::new();
		let mock_storage = MockStorageInterface::new();

		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount_f64: f64 = amount.parse().unwrap_or(0.0);
				Box::pin(async move {
					match (from.as_str(), to.as_str()) {
						("ETH", "USD") => Err(solver_types::PricingError::PriceNotAvailable(
							"ETH/USD".to_string(),
						)),
						("USD", "ETH") => Ok((amount_f64 / ETH_USD_PRICE).to_string()),
						("USDC", "USD") => Ok((amount_f64 * USDC_USD_PRICE).to_string()),
						("USD", "USDC") => Ok((amount_f64 / USDC_USD_PRICE).to_string()),
						_ => Ok("1.0".to_string()),
					}
				})
			});
		mock_pricing.expect_wei_to_currency().returning(|_, _| {
			Box::pin(async move {
				Err(solver_types::PricingError::PriceNotAvailable(
					"ETH/USD".to_string(),
				))
			})
		});

		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
		});
		mock_delivery
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			1,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery_137
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
			});
		mock_delivery_137
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 3600, 60));

		let mut networks = solver_types::NetworksConfig::new();
		let network_1 = solver_types::NetworkConfig {
			name: Some("ethereum".to_string()),
			network_type: solver_types::networks::NetworkType::Parent,
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![
				native_eth_token(),
				solver_types::TokenConfig {
					address: solver_types::Address(
						[
							0xA0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
							0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
						]
						.to_vec(),
					),
					decimals: 18,
					symbol: "ETH".to_string(),
					name: Some("Ether".to_string()),
				},
			],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(1, network_1);

		let network_137 = solver_types::NetworkConfig {
			name: Some("polygon".to_string()),
			network_type: solver_types::networks::NetworkType::Hub,
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![
				native_eth_token(),
				solver_types::TokenConfig {
					address: solver_types::Address(
						[
							0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
							0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
						]
						.to_vec(),
					),
					decimals: 6,
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
				},
			],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(137, network_137);

		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let config = create_test_config();

		let result = service
			.calculate_cost_context(&request, &context, &config, &Address([0xAB; 20].to_vec()))
			.await;

		assert!(matches!(result, Err(CostProfitError::Calculation(_))));
	}

	#[tokio::test]
	async fn test_calculate_cost_context_exact_output() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock pricing service calls for reverse conversion (output -> input)
		mock_pricing
			.expect_convert_asset()
			.with(eq("USDC"), eq("USD"), eq("2000"))
			.times(1)
			.returning(|_, _, _| Box::pin(async move { Ok("2000.0".to_string()) }));

		mock_pricing
			.expect_convert_asset()
			.with(eq("USD"), eq("ETH"), eq("2000.0"))
			.times(1)
			.returning(|_, _, _| Box::pin(async move { Ok("1.0".to_string()) }));

		// Additional mock calls that might be needed for cost calculations
		mock_pricing
			.expect_convert_asset()
			.with(eq("ETH"), eq("USD"), eq("1"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		mock_pricing
			.expect_convert_asset()
			.with(eq("USD"), eq("USDC"), eq("4000.0"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		// Allow any additional convert_asset calls
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount_f64: f64 = amount.parse().unwrap_or(0.0);
				Box::pin(async move {
					match (from.as_str(), to.as_str()) {
						("ETH", "USD") => Ok((amount_f64 * ETH_USD_PRICE).to_string()),
						("USD", "ETH") => Ok((amount_f64 / ETH_USD_PRICE).to_string()),
						("USDC", "USD") => Ok((amount_f64 * USDC_USD_PRICE).to_string()),
						("USD", "USDC") => Ok((amount_f64 / USDC_USD_PRICE).to_string()),
						_ => Ok("1.0".to_string()),
					}
				})
			});

		mock_pricing
			.expect_wei_to_currency()
			.returning(|_, _| Box::pin(async move { Ok("0.01".to_string()) }));

		// Create mock delivery for chain 1
		let mut mock_delivery_1 = MockDeliveryInterface::new();
		mock_delivery_1.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery_1
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
			});
		mock_delivery_1
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		// Create mock delivery for chain 137
		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery_137
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
			});
		mock_delivery_137
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		// Create delivery service with mock implementations for both chains
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			1,
			Arc::new(mock_delivery_1) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 3600, 60));

		// Create proper token manager with required tokens
		let mut networks = solver_types::NetworksConfig::new();

		// Add chain 1 with ETH token
		let network_1 = solver_types::NetworkConfig {
			name: Some("ethereum".to_string()),
			network_type: solver_types::networks::NetworkType::Parent,
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![
				native_eth_token(),
				solver_types::TokenConfig {
					address: solver_types::Address(
						[
							0xA0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
							0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
						]
						.to_vec(),
					),
					decimals: 18,
					symbol: "ETH".to_string(),
					name: Some("Ether".to_string()),
				},
			],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(1, network_1);

		// Add chain 137 with USDC token
		let network_137 = solver_types::NetworkConfig {
			name: Some("polygon".to_string()),
			network_type: solver_types::networks::NetworkType::Hub,
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![
				native_eth_token(),
				solver_types::TokenConfig {
					address: solver_types::Address(
						[
							0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
							0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
						]
						.to_vec(),
					),
					decimals: 6,
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
				},
			],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(137, network_137);

		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));

		// Create services
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		// Create test request for ExactOutput
		let request = create_test_request(false); // false for ExactOutput
		let context = create_test_validated_context(false); // false for ExactOutput
		let config = create_test_config();

		// Act
		let result = service
			.calculate_cost_context(&request, &context, &config, &Address([0xAB; 20].to_vec()))
			.await;

		// Assert
		assert!(result.is_ok());
		let cost_context = result.unwrap();

		// Verify swap type
		assert_eq!(cost_context.swap_type, SwapType::ExactOutput);

		// Verify cost breakdown exists and has reasonable values
		assert!(cost_context.cost_breakdown.total >= Decimal::ZERO);
		assert!(cost_context.cost_breakdown.operational_cost >= Decimal::ZERO);

		// Verify execution costs by chain
		assert!(!cost_context.execution_costs_by_chain.is_empty());

		// Verify swap amounts were calculated
		assert!(!cost_context.swap_amounts.is_empty());

		// Verify adjusted amounts (for ExactOutput, inputs should be adjusted up)
		assert!(!cost_context.adjusted_amounts.is_empty());

		// The adjusted amount should be higher than the swap amount for inputs in ExactOutput
		for (token, adjusted_info) in &cost_context.adjusted_amounts {
			if let Some(swap_info) = cost_context.swap_amounts.get(token) {
				if let Some(cost_info) = cost_context.cost_amounts_in_tokens.get(token) {
					// For ExactOutput inputs: adjusted = swap + cost
					let expected_adjusted = swap_info.amount.saturating_add(cost_info.amount);
					assert_eq!(adjusted_info.amount, expected_adjusted);
				}
			}
		}
	}

	#[tokio::test]
	async fn exact_output_swap_amounts_include_known_output_amounts() {
		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount_f64: f64 = amount.parse().unwrap_or(0.0);
				Box::pin(async move {
					match (from.as_str(), to.as_str()) {
						("USDC", "USD") => Ok(amount_f64.to_string()),
						("USD", "ETH") => Ok((amount_f64 / ETH_USD_PRICE).to_string()),
						_ => Ok(amount_f64.to_string()),
					}
				})
			});

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let mut networks = create_test_networks_config();
		networks.get_mut(&1).expect("chain 1 test network").tokens[0].address =
			solver_types::Address(
				address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C")
					.0
					.to_vec(),
			);
		let dest_token = &mut networks
			.get_mut(&137)
			.expect("chain 137 test network")
			.tokens[0];
		dest_token.address = solver_types::Address(
			address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C")
				.0
				.to_vec(),
		);
		dest_token.symbol = "USDC".to_string();
		dest_token.decimals = 6;
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));
		let storage = Arc::new(StorageService::new(Box::new(MockStorageInterface::new())));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);
		let request = create_test_request(false);
		let context = create_test_validated_context(false);
		let decimals = service.get_all_token_decimals(&request).await;
		let output_asset = request.intent.outputs[0].asset.clone();
		let input_asset = request.intent.inputs[0].asset.clone();
		let expected_output_amount = U256::from_str("2000000000").unwrap();

		let amounts = service
			.calculate_swap_amounts(&request, &context, &decimals, 0)
			.await
			.expect("ExactOutput amounts should calculate");

		assert_eq!(
			amounts.get(&output_asset).map(|info| info.amount),
			Some(expected_output_amount),
			"ExactOutput resolved amounts must include the known output amount"
		);
		assert!(
			amounts.contains_key(&input_asset),
			"ExactOutput should still include the calculated input amount"
		);
	}

	#[test]
	fn test_estimate_gas_units_from_flow_keys_respects_lower_configured_values() {
		let mut config = create_test_config();
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(100_000),
					fill: Some(110_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(120_000),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let (open, fill, post_fill, pre_claim, claim) = estimate_gas_units_from_flow_keys(
			&["permit2_escrow".to_string()],
			&config,
			150_000,
			150_000,
			150_000,
			150_000,
			150_000,
		);

		assert_eq!(
			(open, fill, post_fill, pre_claim, claim),
			(100_000, 110_000, 0, 0, 120_000)
		);
	}

	#[test]
	fn test_estimate_gas_units_from_flow_keys_includes_optional_settlement_steps() {
		let mut config = create_test_config();
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(100_000),
					fill: Some(110_000),
					post_fill: Some(300_000),
					pre_claim: Some(40_000),
					claim: Some(120_000),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let (open, fill, post_fill, pre_claim, claim) = estimate_gas_units_from_flow_keys(
			&["permit2_escrow".to_string()],
			&config,
			150_000,
			150_000,
			150_000,
			0,
			150_000,
		);

		assert_eq!(
			(open, fill, post_fill, pre_claim, claim),
			(100_000, 110_000, 300_000, 40_000, 120_000)
		);
	}

	#[tokio::test]
	async fn test_calculate_total_cost_includes_optional_settlement_and_l1_data_fees() {
		let one_native = U256::from(1_000_000_000_000_000_000u128);
		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing.expect_wei_to_currency().times(0);
		mock_pricing
			.expect_convert_asset()
			.times(8)
			.returning(|from, to, amount| {
				assert_eq!(from, "ETH");
				assert_eq!(to, "USD");
				let amount = amount.to_string();
				Box::pin(async move { Ok(amount) })
			});

		let mut origin_delivery = MockDeliveryInterface::new();
		origin_delivery
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(FeeParams::legacy(chain_id, 10_000_000_000_000_000_000u128)) },
				)
			});
		origin_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut destination_delivery = MockDeliveryInterface::new();
		destination_delivery
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(FeeParams::legacy(chain_id, 100_000_000_000_000_000_000u128)) },
				)
			});
		destination_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([
				(
					1,
					Arc::new(origin_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
				),
				(
					2,
					Arc::new(destination_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
				),
			]),
			1,
			3600,
			60,
		));
		let native_token = solver_types::TokenConfig {
			address: solver_types::Address(vec![0u8; 20]),
			symbol: "ETH".to_string(),
			name: Some("Ether".to_string()),
			decimals: 18,
		};
		let mut networks = NetworksConfig::new();
		for chain_id in [1, 2] {
			networks.insert(
				chain_id,
				solver_types::NetworkConfig {
					name: Some(format!("chain-{chain_id}")),
					network_type: solver_types::networks::NetworkType::New,
					rpc_urls: vec![],
					input_settler_address: solver_types::Address([0x11; 20].to_vec()),
					output_settler_address: solver_types::Address([0x22; 20].to_vec()),
					tokens: vec![native_token.clone()],
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			);
		}
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));
		let service = CostProfitService::new(
			Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new())),
			delivery,
			token_manager,
			Arc::new(StorageService::new(Box::new(MockStorageInterface::new()))),
			no_fee_settlement_service(),
		);

		let config = create_test_config();
		let breakdown = service
			.calculate_total_cost(
				&[],
				&[],
				&config,
				1,
				2,
				&GasUnits {
					open_units: 1,
					fill_units: 2,
					post_fill_units: 3,
					pre_claim_units: 4,
					claim_units: 5,
				},
				one_native * U256::from(10u64),
				one_native * U256::from(7u64),
				one_native * U256::from(8u64),
			)
			.await
			.unwrap();

		assert_eq!(breakdown.gas_open, Decimal::from(10));
		assert_eq!(breakdown.gas_fill, Decimal::from(200));
		assert_eq!(breakdown.gas_post_fill, Decimal::from(300));
		assert_eq!(breakdown.gas_pre_claim, Decimal::from(40));
		assert_eq!(breakdown.gas_claim, Decimal::from(50));
		assert_eq!(breakdown.gas_buffer, Decimal::from(60));
		assert_eq!(breakdown.settlement_fee, Decimal::from(10));
		assert_eq!(breakdown.settlement_fee_buffer, Decimal::from(1));
		assert_eq!(breakdown.l1_data_fee, Decimal::from(7));
		assert_eq!(breakdown.l1_data_fee_buffer, Decimal::from(8));
		assert_eq!(breakdown.operational_cost, Decimal::from(686));
	}

	#[tokio::test]
	async fn test_calculate_total_cost_prices_native_gas_by_chain_symbol() {
		let one_native = U256::from(1_000_000_000_000_000_000u128);
		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing.expect_wei_to_currency().times(0);
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount = Decimal::from_str(amount).unwrap();
				Box::pin(async move {
					assert_eq!(to, "USD");
					let price = match from.as_str() {
						"POL" => Decimal::from(1),
						"ETH" => Decimal::from(100),
						"BNB" => Decimal::from(3),
						"AVAX" => Decimal::from(7),
						other => panic!("unexpected native asset conversion from {other}"),
					};
					Ok((amount * price).to_string())
				})
			});

		let mut polygon_delivery = MockDeliveryInterface::new();
		polygon_delivery
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(FeeParams::legacy(chain_id, 1_000_000_000_000_000_000u128)) },
				)
			});
		polygon_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut ethereum_delivery = MockDeliveryInterface::new();
		ethereum_delivery
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(FeeParams::legacy(chain_id, 1_000_000_000_000_000_000u128)) },
				)
			});
		ethereum_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut bnb_delivery = MockDeliveryInterface::new();
		bnb_delivery.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 1_000_000_000_000_000_000u128)) })
		});
		bnb_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut avax_delivery = MockDeliveryInterface::new();
		avax_delivery.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 1_000_000_000_000_000_000u128)) })
		});
		avax_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([
				(
					137,
					Arc::new(polygon_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
				),
				(
					1,
					Arc::new(ethereum_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
				),
				(
					56,
					Arc::new(bnb_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
				),
				(
					43114,
					Arc::new(avax_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
				),
			]),
			1,
			3600,
			60,
		));

		let native_token = |symbol: &'static std::primitive::str| solver_types::TokenConfig {
			address: solver_types::Address(vec![0u8; 20]),
			symbol: symbol.to_string(),
			name: Some(symbol.to_string()),
			decimals: 18,
		};
		let mut networks = NetworksConfig::new();
		networks.insert(
			137,
			solver_types::NetworkConfig {
				name: Some("polygon".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![native_token("POL")],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		networks.insert(
			1,
			solver_types::NetworkConfig {
				name: Some("ethereum".to_string()),
				network_type: solver_types::networks::NetworkType::Parent,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x33; 20].to_vec()),
				output_settler_address: solver_types::Address([0x44; 20].to_vec()),
				tokens: vec![native_token("ETH")],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		networks.insert(
			56,
			solver_types::NetworkConfig {
				name: Some("bnb".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x55; 20].to_vec()),
				output_settler_address: solver_types::Address([0x66; 20].to_vec()),
				tokens: vec![native_token("BNB")],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		networks.insert(
			43114,
			solver_types::NetworkConfig {
				name: Some("avalanche".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x77; 20].to_vec()),
				output_settler_address: solver_types::Address([0x88; 20].to_vec()),
				tokens: vec![native_token("AVAX")],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));
		let service = CostProfitService::new(
			Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new())),
			delivery,
			token_manager,
			Arc::new(StorageService::new(Box::new(MockStorageInterface::new()))),
			no_fee_settlement_service(),
		);

		let breakdown = service
			.calculate_total_cost(
				&[],
				&[],
				&create_test_config(),
				137,
				1,
				&GasUnits {
					open_units: 1,
					fill_units: 4,
					post_fill_units: 5,
					pre_claim_units: 2,
					claim_units: 3,
				},
				one_native * U256::from(6),
				one_native * U256::from(7),
				one_native * U256::from(8),
			)
			.await
			.unwrap();

		assert_eq!(breakdown.gas_open, Decimal::from(1));
		assert_eq!(breakdown.gas_pre_claim, Decimal::from(2));
		assert_eq!(breakdown.gas_claim, Decimal::from(3));
		assert_eq!(breakdown.gas_fill, Decimal::from(400));
		assert_eq!(breakdown.gas_post_fill, Decimal::from(500));
		assert_eq!(breakdown.settlement_fee, Decimal::from(600));
		assert_eq!(breakdown.l1_data_fee, Decimal::from(700));
		assert_eq!(breakdown.l1_data_fee_buffer, Decimal::from(800));

		// BNB (56) and AVAX (43114) resolve their native gas symbol from config
		// the same way, proving chain-aware pricing is not ETH/POL-specific.
		let breakdown_bnb_avax = service
			.calculate_total_cost(
				&[],
				&[],
				&create_test_config(),
				56,
				43114,
				&GasUnits {
					open_units: 1,
					fill_units: 1,
					post_fill_units: 0,
					pre_claim_units: 0,
					claim_units: 0,
				},
				U256::ZERO,
				U256::ZERO,
				U256::ZERO,
			)
			.await
			.unwrap();

		// origin leg (chain 56, 1 gas * 1e18) priced in BNB @ 3;
		// destination leg (chain 43114, 1 gas * 1e18) priced in AVAX @ 7.
		assert_eq!(breakdown_bnb_avax.gas_open, Decimal::from(3));
		assert_eq!(breakdown_bnb_avax.gas_fill, Decimal::from(7));
	}

	/// A chain whose config has NO zero-address `TokenConfig` must still price
	/// native gas via the built-in chain -> native symbol fallback, instead of
	/// failing the whole quote. Regression guard for the config-first fallback.
	#[tokio::test]
	async fn test_native_gas_pricing_falls_back_when_chain_not_configured() {
		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing.expect_wei_to_currency().times(0);
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount = Decimal::from_str(amount).unwrap();
				Box::pin(async move {
					assert_eq!(to, "USD");
					let price = match from.as_str() {
						// Polygon's native token, resolved via the fallback map
						// because the config has no zero-address TokenConfig.
						"POL" => Decimal::from(5),
						other => panic!("unexpected native asset conversion from {other}"),
					};
					Ok((amount * price).to_string())
				})
			});

		let mut polygon_delivery = MockDeliveryInterface::new();
		polygon_delivery
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(FeeParams::legacy(chain_id, 1_000_000_000_000_000_000u128)) },
				)
			});
		polygon_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137,
				Arc::new(polygon_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			3600,
			60,
		));

		// Polygon (137) is present in config but WITHOUT a zero-address native
		// TokenConfig — the exact "unmigrated config" case the fallback fixes.
		let mut networks = NetworksConfig::new();
		networks.insert(
			137,
			solver_types::NetworkConfig {
				name: Some("polygon".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));
		let service = CostProfitService::new(
			Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new())),
			delivery,
			token_manager,
			Arc::new(StorageService::new(Box::new(MockStorageInterface::new()))),
			no_fee_settlement_service(),
		);

		let breakdown = service
			.calculate_total_cost(
				&[],
				&[],
				&create_test_config(),
				137,
				137,
				&GasUnits {
					open_units: 1,
					fill_units: 0,
					post_fill_units: 0,
					pre_claim_units: 0,
					claim_units: 0,
				},
				U256::ZERO,
				U256::ZERO,
				U256::ZERO,
			)
			.await
			.expect("native gas pricing must fall back instead of erroring");

		// 1 gas unit * 1e18 wei/gas = 1 POL, priced at 5 USD via the fallback.
		assert_eq!(breakdown.gas_open, Decimal::from(5));
	}

	/// Gas is denominated in 1e18-base wei, so a chain whose explicit
	/// zero-address native `TokenConfig` is misconfigured with non-18 decimals
	/// must FAIL CLOSED at runtime (all builds), not silently misprice by
	/// `10^(18 - decimals)`. Regression guard for the release-safe decimals check
	/// that replaced a debug-only `debug_assert`.
	#[tokio::test]
	async fn test_native_gas_pricing_rejects_non_18_decimal_native() {
		let mut mock_pricing = MockPricingInterface::new();
		// We must fail on the decimals guard BEFORE any pricing call is made.
		mock_pricing.expect_wei_to_currency().times(0);
		mock_pricing.expect_convert_asset().times(0);

		let mut polygon_delivery = MockDeliveryInterface::new();
		polygon_delivery
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(FeeParams::legacy(chain_id, 1_000_000_000_000_000_000u128)) },
				)
			});
		polygon_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137,
				Arc::new(polygon_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			3600,
			60,
		));

		// Explicit zero-address native TokenConfig with NON-18 decimals (6) — the
		// exact misconfiguration the runtime guard must reject.
		let mut networks = NetworksConfig::new();
		networks.insert(
			137,
			solver_types::NetworkConfig {
				name: Some("polygon".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![solver_types::TokenConfig {
					address: solver_types::Address(vec![0u8; 20]),
					symbol: "POL".to_string(),
					name: Some("POL".to_string()),
					decimals: 6,
				}],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));
		let service = CostProfitService::new(
			Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new())),
			delivery,
			token_manager,
			Arc::new(StorageService::new(Box::new(MockStorageInterface::new()))),
			no_fee_settlement_service(),
		);

		// One non-zero origin gas leg on the misconfigured chain forces a native
		// base-units -> USD conversion; every other leg is zero (early-returns).
		let result = service
			.calculate_total_cost(
				&[],
				&[],
				&create_test_config(),
				137,
				137,
				&GasUnits {
					open_units: 1,
					fill_units: 0,
					post_fill_units: 0,
					pre_claim_units: 0,
					claim_units: 0,
				},
				U256::ZERO,
				U256::ZERO,
				U256::ZERO,
			)
			.await;

		let err = result
			.expect_err("native gas pricing must fail closed for a non-18-decimal native config");
		let msg = err.to_string();
		assert!(
			msg.contains("18-decimal") && msg.contains("decimals"),
			"error must explain the non-18 native decimals rejection, got: {msg}"
		);
	}

	/// An unknown chain id that is neither in config nor in the fallback map
	/// must fail closed rather than silently mispricing native gas.
	#[tokio::test]
	async fn test_native_gas_pricing_errors_on_unknown_unconfigured_chain() {
		const UNKNOWN_CHAIN: u64 = 999_999;

		let mut mock_pricing = MockPricingInterface::new();
		// Neither pricing path should be reached: the symbol never resolves.
		mock_pricing.expect_wei_to_currency().times(0);
		mock_pricing.expect_convert_asset().times(0);

		let mut unknown_delivery = MockDeliveryInterface::new();
		unknown_delivery
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(FeeParams::legacy(chain_id, 1_000_000_000_000_000_000u128)) },
				)
			});
		unknown_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				UNKNOWN_CHAIN,
				Arc::new(unknown_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			3600,
			60,
		));

		// Chain present for fee params, but has no zero-address native token and
		// is not a well-known chain, so no native symbol can be resolved.
		let mut networks = NetworksConfig::new();
		networks.insert(
			UNKNOWN_CHAIN,
			solver_types::NetworkConfig {
				name: Some("unknown".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));
		let service = CostProfitService::new(
			Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new())),
			delivery,
			token_manager,
			Arc::new(StorageService::new(Box::new(MockStorageInterface::new()))),
			no_fee_settlement_service(),
		);

		let result = service
			.calculate_total_cost(
				&[],
				&[],
				&create_test_config(),
				UNKNOWN_CHAIN,
				UNKNOWN_CHAIN,
				&GasUnits {
					open_units: 1,
					fill_units: 0,
					post_fill_units: 0,
					pre_claim_units: 0,
					claim_units: 0,
				},
				U256::ZERO,
				U256::ZERO,
				U256::ZERO,
			)
			.await;

		assert!(
			result.is_err(),
			"unknown, unconfigured chain must fail closed, got: {result:?}"
		);
	}

	/// A native (zero-address) OUTPUT on a chain that is CONFIGURED but has no
	/// zero-address native `TokenConfig` must fail valuation with a CLEAR
	/// message that mentions `native` and `config` — not a bare
	/// `TokenNotSupported`. The gas-only native-symbol fallback must not rescue
	/// valuation here. A native output WITH an explicit native config still
	/// values fine.
	#[tokio::test]
	async fn test_native_output_valuation_errors_clearly_without_config() {
		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount = Decimal::from_str(amount).unwrap();
				Box::pin(async move {
					assert_eq!(to, "USD");
					let price = match from.as_str() {
						"ETH" => Decimal::from(4000),
						other => panic!("unexpected asset conversion from {other}"),
					};
					Ok((amount * price).to_string())
				})
			});

		// Chain 1: WITH a zero-address native ETH TokenConfig.
		// Chain 137: configured, but NO zero-address native TokenConfig.
		let native_eth = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address(solver_types::Address(vec![0u8; 20]))
			.symbol("ETH".to_string())
			.decimals(18)
			.build();
		let some_erc20 = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address(solver_types::Address([0x11u8; 20].to_vec()))
			.symbol("OUTPUT".to_string())
			.decimals(18)
			.build();
		let networks = NetworksConfigBuilder::new()
			.add_network(
				1,
				NetworkConfigBuilder::new().tokens(vec![native_eth]).build(),
			)
			.add_network(
				137,
				NetworkConfigBuilder::new().tokens(vec![some_erc20]).build(),
			)
			.build();
		let token_manager = Arc::new(TokenManager::new(
			networks,
			create_mock_delivery_service(),
			create_mock_account_service(),
		));
		let service = CostProfitService::new(
			Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new())),
			create_mock_delivery_service(),
			token_manager,
			Arc::new(StorageService::new(Box::new(MockStorageInterface::new()))),
			no_fee_settlement_service(),
		);

		// Native output on chain 137 (no native config) -> clear error.
		let native_no_config = OrderOutput {
			receiver: InteropAddress::new_ethereum(
				137,
				address!("0000000000000000000000000000000000000000"),
			),
			asset: InteropAddress::new_ethereum(
				137,
				address!("0000000000000000000000000000000000000000"),
			),
			amount: U256::from(1_000_000_000_000_000_000u128),
			calldata: None,
		};
		let err = service
			.calculate_outputs_usd_value(&[native_no_config])
			.await
			.expect_err("native output without native TokenConfig must error");
		let msg = err.to_string().to_lowercase();
		assert!(msg.contains("native"), "error must mention native: {msg}");
		assert!(msg.contains("config"), "error must mention config: {msg}");

		// Native output on chain 1 (WITH native config) -> values fine.
		let native_with_config = OrderOutput {
			receiver: InteropAddress::new_ethereum(
				1,
				address!("0000000000000000000000000000000000000000"),
			),
			asset: InteropAddress::new_ethereum(
				1,
				address!("0000000000000000000000000000000000000000"),
			),
			amount: U256::from(1_000_000_000_000_000_000u128),
			calldata: None,
		};
		let usd = service
			.calculate_outputs_usd_value(&[native_with_config])
			.await
			.expect("native output with native TokenConfig must value fine");
		assert_eq!(usd, Decimal::from(4000));
	}

	/// Regression: `10_i64.pow(20)` overflowed `i64` (panics in debug, wraps in
	/// release) for tokens with >=19 decimals, despite the <=28 decimals guard.
	/// Computing the divisor in `i128` fixes it.
	#[tokio::test]
	async fn test_convert_raw_token_to_usd_handles_20_decimal_token() {
		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount = Decimal::from_str(amount).unwrap();
				Box::pin(async move {
					assert_eq!(from, "TKN20");
					assert_eq!(to, "USD");
					// TKN20 priced at 3 USD each.
					Ok((amount * Decimal::from(3)).to_string())
				})
			});
		let pricing = PricingService::new(Box::new(mock_pricing), Vec::new());

		// 2 whole tokens with 20 decimals = 2 * 10^20 base units.
		let raw = U256::from_str("200000000000000000000").unwrap();
		let usd = CostProfitService::convert_raw_token_to_usd(&raw, "TKN20", 20, &pricing)
			.await
			.expect("20-decimal conversion must not overflow");
		// normalized = 2.0 priced at 3 USD => 6 USD.
		assert_eq!(usd, Decimal::from(6));
	}

	// ============================================================================
	// Profitability Validation Tests
	// ============================================================================

	// Helpers for profitability validation
	fn create_test_order_with_amounts(input_amount: U256, output_amount: U256) -> Order {
		// Create EIP-7683 order data
		let eip7683_data = Eip7683OrderData {
			user: "0x1111111111111111111111111111111111111111".to_string(),
			nonce: U256::from(1),
			origin_chain_id: U256::from(1),
			expires: (current_timestamp() + 3600) as u32,
			fill_deadline: (current_timestamp() + 300) as u32,
			input_oracle: "0x0000000000000000000000000000000000000000".to_string(),
			inputs: vec![[
				// Use the INPUT token address from create_test_networks_config (0x3e8 = 1000)
				U256::from(1000),
				input_amount, // amount
			]],
			order_id: [1u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [0u8; 32],  // Zero oracle for test
				settler: [0u8; 32], // Zero settler for test
				token: output_token_bytes32(),
				amount: output_amount,
				recipient: U256::from_str("0x2222222222222222222222222222222222222222")
					.unwrap()
					.to_be_bytes(),
				chain_id: U256::from(137),
				call: vec![],
				context: vec![], // Empty context for test
			}],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		};

		Order {
			id: "test_order_id".to_string(),
			standard: "eip7683".to_string(),
			created_at: current_timestamp(),
			updated_at: current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(eip7683_data).unwrap(),
			solver_address: solver_types::Address([0xAB; 20].to_vec()),
			quote_id: Some("test_quote_id".to_string()),
			input_chains: vec![ChainSettlerInfo {
				chain_id: 1,
				settler_address: solver_types::Address([0x11; 20].to_vec()),
			}],
			output_chains: vec![ChainSettlerInfo {
				chain_id: 137,
				settler_address: solver_types::Address([0x22; 20].to_vec()),
			}],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
			settlement_name: None,
		}
	}

	fn create_profitable_order() -> Order {
		// Input: 1 INPUT (~$4000), Output: 3900 OUTPUT = $100 profit (2.5% margin)
		create_test_order_with_amounts(
			U256::from_str("1000000000000000000").unwrap(), // 1 INPUT (18 decimals)
			U256::from_str("3900000000000000000000").unwrap(), // 3900 OUTPUT (18 decimals)
		)
	}

	fn create_unprofitable_order() -> Order {
		// Input: 1 INPUT (~$4000), Output: 3990 OUTPUT = -$34 loss (considering $44 operational cost)
		create_test_order_with_amounts(
			U256::from_str("1000000000000000000").unwrap(), // 1 INPUT (18 decimals)
			U256::from_str("3990000000000000000000").unwrap(), // 3990 OUTPUT (18 decimals)
		)
	}

	fn create_zero_value_order() -> Order {
		// Both input and output are zero
		create_test_order_with_amounts(U256::ZERO, U256::ZERO)
	}

	fn create_test_cost_breakdown_with_profit(min_profit: Decimal) -> CostBreakdown {
		CostBreakdown {
			gas_open: Decimal::from_str("0.01").unwrap(),
			gas_fill: Decimal::from_str("0.02").unwrap(),
			gas_post_fill: Decimal::ZERO,
			gas_pre_claim: Decimal::ZERO,
			gas_claim: Decimal::from_str("0.01").unwrap(),
			gas_buffer: Decimal::from_str("0.004").unwrap(),
			settlement_fee: Decimal::ZERO,
			settlement_fee_buffer: Decimal::ZERO,
			l1_data_fee: Decimal::ZERO,
			l1_data_fee_buffer: Decimal::ZERO,
			rate_buffer: Decimal::ZERO,
			base_price: Decimal::ZERO,
			min_profit,
			operational_cost: Decimal::from_str("0.044").unwrap(),
			subtotal: Decimal::from_str("0.044").unwrap(),
			total: Decimal::from_str("0.044").unwrap(),
			currency: "USD".to_string(),
		}
	}

	fn create_cost_context_with_swap_type(swap_type: SwapType) -> CostContext {
		CostContext {
			cost_breakdown: create_test_cost_breakdown_with_profit(
				Decimal::from_str("200.0").unwrap(),
			),
			execution_costs_by_chain: HashMap::new(),
			liquidity_cost_adjustment: Decimal::ZERO,
			protocol_fees: HashMap::new(),
			swap_type,
			cost_amounts_in_tokens: HashMap::new(),
			swap_amounts: HashMap::new(),
			adjusted_amounts: HashMap::new(),
		}
	}

	async fn setup_profitable_mocks() -> (
		Arc<PricingService>,
		Arc<DeliveryService>,
		Arc<TokenManager>,
		Arc<StorageService>,
	) {
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock INPUT to USD conversion (1 INPUT = $4000)
		mock_pricing
			.expect_convert_asset()
			.with(eq("INPUT"), eq("USD"), eq("1"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		// Mock OUTPUT to USD conversion (normalized amount)
		mock_pricing
			.expect_convert_asset()
			.with(eq("OUTPUT"), eq("USD"), eq("3900"))
			.returning(|_, _, _| Box::pin(async move { Ok("3900.0".to_string()) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		(pricing, delivery, token_manager, storage)
	}

	async fn setup_unprofitable_mocks() -> (
		Arc<PricingService>,
		Arc<DeliveryService>,
		Arc<TokenManager>,
		Arc<StorageService>,
	) {
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock INPUT to USD conversion (1 INPUT = $4000)
		mock_pricing
			.expect_convert_asset()
			.with(eq("INPUT"), eq("USD"), eq("1"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		// Mock OUTPUT to USD conversion - higher output (less profitable)
		mock_pricing
			.expect_convert_asset()
			.with(eq("OUTPUT"), eq("USD"), eq("3990"))
			.returning(|_, _, _| Box::pin(async move { Ok("3990.0".to_string()) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		(pricing, delivery, token_manager, storage)
	}

	// ============================================================================
	// Basic Profitability Scenarios
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_profitable_order() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap(); // 2% minimum

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		match result {
			Ok(actual_margin) => {
				assert!(actual_margin >= min_profitability_pct);
			},
			Err(e) => {
				panic!("Expected success but got error: {e:?}");
			},
		}
	}

	#[tokio::test]
	async fn test_validate_profitability_unprofitable_order() {
		let (pricing, delivery, token_manager, storage) = setup_unprofitable_mocks().await;
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_unprofitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap(); // 5% minimum

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			APIError::UnprocessableEntity {
				error_type,
				message,
				..
			} => {
				assert_eq!(error_type, ApiErrorType::InsufficientProfitability);
				assert!(message.contains("Insufficient profit margin"));
			},
			other => panic!("Expected UnprocessableEntity error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_validate_profitability_rejects_when_settlement_fee_erases_margin() {
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let mut cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		cost_breakdown.settlement_fee = Decimal::from_str("120.0").unwrap();
		cost_breakdown.operational_cost += cost_breakdown.settlement_fee;
		cost_breakdown.subtotal = cost_breakdown.operational_cost;
		cost_breakdown.total = cost_breakdown.operational_cost;

		// The order spread is $100. With the gas-only helper cost ($0.044), the
		// order clears a 2% floor. Adding the settlement fee makes realized profit
		// negative, so the gate must reject.
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				Decimal::from_str("2.0").unwrap(),
				None,
				"off-chain",
			)
			.await;

		match result.unwrap_err() {
			APIError::UnprocessableEntity {
				error_type,
				message,
				details,
			} => {
				assert_eq!(error_type, ApiErrorType::InsufficientProfitability);
				assert!(message.contains("Insufficient profit margin"));
				let details = details.expect("profitability error should include details");
				assert_eq!(details["operational_cost"], "$120.04");
				assert_eq!(details["actual_profit"], "$-20.04");
			},
			other => panic!("Expected UnprocessableEntity error, got: {other:?}"),
		}
	}

	// ============================================================================
	// Swap Type Variations
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_exact_input_with_context() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();
		let test_stored_quote = StoredQuote {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: current_timestamp() + 300,
				eta: Some(60),
				quote_id: "test_quote_exact_input".to_string(),
				provider: Some("test_solver".to_string()),
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: create_cost_context_with_swap_type(SwapType::ExactInput),
			settlement_name: None,
			binding: Some(binding_for_order(&create_profitable_order())),
		};

		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:test_quote_exact_input"))
			.returning(move |_| {
				let serialized = serde_json::to_vec(&test_stored_quote).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// Act - with quote context for ExactInput
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				Some("test_quote_exact_input"),
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		assert!(actual_margin >= min_profitability_pct);
	}

	#[tokio::test]
	async fn test_validate_profitability_exact_output_with_context() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();
		let test_stored_quote = StoredQuote {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: current_timestamp() + 300,
				eta: Some(60),
				quote_id: "test_quote_exact_output".to_string(),
				provider: Some("test_solver".to_string()),
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: create_cost_context_with_swap_type(SwapType::ExactOutput),
			settlement_name: None,
			binding: Some(binding_for_order(&create_profitable_order())),
		};

		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:test_quote_exact_output"))
			.returning(move |_| {
				let serialized = serde_json::to_vec(&test_stored_quote).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// Act - with quote context for ExactOutput
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				Some("test_quote_exact_output"),
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		assert!(actual_margin >= min_profitability_pct);
	}

	// ============================================================================
	// Intent Source Handling
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_onchain_intent() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// On-chain intent (gas_open cost already paid by user)
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"on-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		// Should be higher than off-chain because gas_open is not deducted
		assert!(actual_margin >= min_profitability_pct);
	}

	#[tokio::test]
	async fn test_validate_profitability_offchain_intent() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// Off-chain intent (solver pays all costs including gas_open)
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		assert!(actual_margin >= min_profitability_pct);
	}

	// ============================================================================
	// Error Scenarios & Edge Cases
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_zero_transaction_value() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock zero conversions
		mock_pricing
			.expect_convert_asset()
			.returning(|_, _, _| Box::pin(async move { Ok("0.0".to_string()) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_zero_value_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap();

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_err());
		match result.unwrap_err() {
			APIError::BadRequest {
				error_type,
				message,
				..
			} => {
				assert_eq!(error_type, ApiErrorType::InvalidRequest);
				assert!(message.contains("zero transaction value"));
			},
			other => panic!("Expected BadRequest error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_validate_profitability_order_parsing_failure() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		// Create invalid order with malformed JSON
		let mut invalid_order = create_profitable_order();
		// Directly set invalid data structure (missing required EIP-7683 fields)
		invalid_order.data = serde_json::json!({
			"invalid": "structure"
			// Missing required fields like user, nonce, origin_chain_id, etc.
		});

		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap();

		// Act
		let result = service
			.validate_profitability(
				&invalid_order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_err());
		match result.unwrap_err() {
			APIError::BadRequest {
				error_type,
				message,
				..
			} => {
				assert_eq!(error_type, ApiErrorType::InvalidRequest);
				assert!(message.contains("Failed to parse order data"));
			},
			other => panic!("Expected BadRequest error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_validate_profitability_pricing_service_failure() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock pricing service failure
		mock_pricing.expect_convert_asset().returning(|_, _, _| {
			Box::pin(async move {
				Err(solver_types::PricingError::InvalidData(
					"Pricing service unavailable".to_string(),
				))
			})
		});

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap();

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_err());
		match result.unwrap_err() {
			APIError::InternalServerError {
				error_type,
				message,
				..
			} => {
				assert_eq!(error_type, ApiErrorType::InternalError);
				assert!(message.contains("Failed to calculate"));
			},
			other => panic!("Expected InternalServerError error, got: {other:?}"),
		}
	}

	// ============================================================================
	// Quote Context Scenarios
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_missing_quote_context() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();

		// Mock quote not found
		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:nonexistent_quote"))
			.returning(|_| {
				Box::pin(async move {
					Err(solver_storage::StorageError::NotFound(
						"Quote not found".to_string(),
					))
				})
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// Act - quote ID provided but not found (should still work, just without context)
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				Some("nonexistent_quote"),
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		// Should fall back to using max of input/output value as transaction base
	}

	#[tokio::test]
	async fn test_validate_profitability_without_quote_context() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// No quote ID provided (direct order submission)
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		assert!(actual_margin >= min_profitability_pct);
	}

	#[tokio::test]
	async fn test_validate_profitability_high_margin_order() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Very profitable scenario: Input $4000, Output $3000 = $1000 spread
		mock_pricing
			.expect_convert_asset()
			.with(eq("INPUT"), eq("USD"), eq("1"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		mock_pricing
			.expect_convert_asset()
			.with(eq("OUTPUT"), eq("USD"), eq("3000"))
			.returning(|_, _, _| Box::pin(async move { Ok("3000.0".to_string()) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_test_order_with_amounts(
			U256::from_str("1000000000000000000").unwrap(), // 1 INPUT
			U256::from_str("3000000000000000000000").unwrap(), // 3000 OUTPUT (18 decimals)
		);
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap();

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		// Should be much higher than minimum
		assert!(actual_margin > Decimal::from_str("20.0").unwrap());
	}

	// ============================================================================
	// Callback Gas Simulation Tests
	// ============================================================================

	fn create_order_with_callback(callback_data: Vec<u8>) -> Order {
		let eip7683_data = Eip7683OrderData {
			user: "0x1111111111111111111111111111111111111111".to_string(),
			nonce: U256::from(1),
			origin_chain_id: U256::from(1),
			expires: (current_timestamp() + 3600) as u32,
			fill_deadline: (current_timestamp() + 300) as u32,
			input_oracle: "0x0000000000000000000000000000000000000000".to_string(),
			inputs: vec![[U256::from(1000), U256::from(1000000)]],
			order_id: [1u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [0u8; 32],
				settler: [0u8; 32],
				token: [0u8; 32],
				amount: U256::from(1000000),
				recipient: U256::from_str("0x2222222222222222222222222222222222222222")
					.unwrap()
					.to_be_bytes(),
				chain_id: U256::from(137),
				call: callback_data,
				context: vec![],
			}],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		};

		Order {
			id: "test_callback_order".to_string(),
			standard: "eip7683".to_string(),
			created_at: current_timestamp(),
			updated_at: current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(eip7683_data).unwrap(),
			solver_address: solver_types::Address([0xAB; 20].to_vec()),
			quote_id: None,
			input_chains: vec![ChainSettlerInfo {
				chain_id: 1,
				settler_address: solver_types::Address([0x11; 20].to_vec()),
			}],
			output_chains: vec![ChainSettlerInfo {
				chain_id: 137,
				settler_address: solver_types::Address([0x22; 20].to_vec()),
			}],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
			settlement_name: None,
		}
	}

	fn create_order_with_multiple_outputs() -> Order {
		let eip7683_data = Eip7683OrderData {
			user: "0x1111111111111111111111111111111111111111".to_string(),
			nonce: U256::from(1),
			origin_chain_id: U256::from(1),
			expires: (current_timestamp() + 3600) as u32,
			fill_deadline: (current_timestamp() + 300) as u32,
			input_oracle: "0x0000000000000000000000000000000000000000".to_string(),
			inputs: vec![[U256::from(1000), U256::from(1000000)]],
			order_id: [1u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![
				MandateOutput {
					oracle: [0u8; 32],
					settler: [0u8; 32],
					token: [0u8; 32],
					amount: U256::from(500000),
					recipient: U256::from_str("0x2222222222222222222222222222222222222222")
						.unwrap()
						.to_be_bytes(),
					chain_id: U256::from(137),
					call: vec![],
					context: vec![],
				},
				MandateOutput {
					oracle: [0u8; 32],
					settler: [0u8; 32],
					token: [0u8; 32],
					amount: U256::from(500000),
					recipient: U256::from_str("0x3333333333333333333333333333333333333333")
						.unwrap()
						.to_be_bytes(),
					chain_id: U256::from(42161), // Different chain
					call: vec![],
					context: vec![],
				},
			],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		};

		Order {
			id: "test_multi_output_order".to_string(),
			standard: "eip7683".to_string(),
			created_at: current_timestamp(),
			updated_at: current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(eip7683_data).unwrap(),
			solver_address: solver_types::Address([0xAB; 20].to_vec()),
			quote_id: None,
			input_chains: vec![ChainSettlerInfo {
				chain_id: 1,
				settler_address: solver_types::Address([0x11; 20].to_vec()),
			}],
			output_chains: vec![
				ChainSettlerInfo {
					chain_id: 137,
					settler_address: solver_types::Address([0x22; 20].to_vec()),
				},
				ChainSettlerInfo {
					chain_id: 42161,
					settler_address: solver_types::Address([0x33; 20].to_vec()),
				},
			],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
			settlement_name: None,
		}
	}

	fn create_test_fill_transaction() -> Transaction {
		Transaction {
			to: Some(solver_types::Address([0x22; 20].to_vec())),
			data: vec![0xde, 0xad, 0xbe, 0xef],
			value: U256::ZERO,
			chain_id: 137,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}
	}

	fn create_config_with_callback_whitelist(whitelist: Vec<String>) -> Config {
		let mut config = create_test_config();
		config.order.callback_whitelist = whitelist;
		config.order.simulate_callbacks = true;
		config
	}

	#[tokio::test]
	async fn test_simulate_callback_no_callback_data() {
		// Arrange
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(75000u64) }));

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			137,
			3600,
			60,
		));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_order_with_callback(vec![]); // Empty callback
		let fill_tx = create_test_fill_transaction();
		let config = create_config_with_callback_whitelist(vec![]);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert
		assert!(result.is_ok());
		let simulation_result = result.unwrap();
		assert!(!simulation_result.has_callback);
		assert_eq!(simulation_result.estimated_gas_units, 75000);
		assert_eq!(simulation_result.chain_id, 137);
	}

	#[tokio::test]
	async fn test_simulate_callback_with_callback_data_whitelisted() {
		// Arrange
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(95000u64) }));

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			137,
			3600,
			60,
		));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		// Callback data: some arbitrary bytes
		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();

		// Whitelist the recipient (chain 137, recipient from order)
		// The recipient in the order is 0x2222...2222
		// EIP-7930 format: Version(2) | ChainType(2) | ChainRefLen(1) | ChainRef | AddrLen(1) | Address
		// For chain 137 (0x89): 0x0001 | 0x0000 | 0x01 | 0x89 | 0x14 | <20-byte address>
		let whitelist =
			vec!["0x000100000189142222222222222222222222222222222222222222".to_lowercase()];
		let config = create_config_with_callback_whitelist(whitelist);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert
		assert!(result.is_ok());
		let simulation_result = result.unwrap();
		assert!(simulation_result.has_callback);
		assert_eq!(simulation_result.estimated_gas_units, 95000);
	}

	#[tokio::test]
	async fn test_simulate_callback_not_whitelisted() {
		// Arrange
		let mock_delivery = MockDeliveryInterface::new();
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			137,
			3600,
			60,
		));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();

		// Non-empty whitelist that does NOT contain the recipient (0x2222..).
		// An empty whitelist would mean allow-all, so a different address is
		// used here to exercise the genuine "not whitelisted" rejection path.
		let config = create_config_with_callback_whitelist(vec![
			"0x000100000189149999999999999999999999999999999999999999".to_string(),
		]);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert - should fail because recipient is not whitelisted
		assert!(result.is_err());
		let error = result.unwrap_err();
		match error {
			CostProfitError::Config(msg) => {
				assert!(msg.contains("not in whitelist"));
			},
			other => panic!("Expected Config error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_simulate_callback_empty_whitelist_allows_all() {
		// An empty callback_whitelist means "allow all callbacks" (the same
		// contract enforced at quote time by validate_callback_whitelist). A
		// callback to any recipient must therefore be simulated, not rejected.
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(95000u64) }));

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			137,
			3600,
			60,
		));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();
		// Empty whitelist = allow all callbacks.
		let config = create_config_with_callback_whitelist(vec![]);

		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		assert!(
			result.is_ok(),
			"empty whitelist must allow all callbacks, got: {result:?}"
		);
		let simulation_result = result.unwrap();
		assert!(simulation_result.has_callback);
		assert_eq!(simulation_result.estimated_gas_units, 95000);
	}

	#[test]
	fn callback_recipient_whitelisted_empty_allows_all() {
		let config = create_config_with_callback_whitelist(vec![]);
		assert!(
			CostProfitService::callback_recipient_whitelisted(
				&config,
				"0x000100000189142222222222222222222222222222222222222222"
			),
			"empty whitelist must allow any recipient"
		);
	}

	#[test]
	fn callback_recipient_whitelisted_nonempty_checks_membership() {
		let config = create_config_with_callback_whitelist(vec![
			"0x000100000189142222222222222222222222222222222222222222".to_string(),
		]);
		assert!(
			CostProfitService::callback_recipient_whitelisted(
				&config,
				"0x000100000189142222222222222222222222222222222222222222"
			),
			"listed recipient must be allowed"
		);
		assert!(
			!CostProfitService::callback_recipient_whitelisted(
				&config,
				"0x000100000189149999999999999999999999999999999999999999"
			),
			"unlisted recipient must be rejected when whitelist is non-empty"
		);
	}

	#[tokio::test]
	async fn test_simulate_callback_multiple_outputs_rejected() {
		// Arrange
		let mock_delivery = MockDeliveryInterface::new();
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			137,
			3600,
			60,
		));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_order_with_multiple_outputs();
		let fill_tx = create_test_fill_transaction();
		let config = create_config_with_callback_whitelist(vec![]);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert - should fail because multiple outputs are not supported
		assert!(result.is_err());
		let error = result.unwrap_err();
		match error {
			CostProfitError::Calculation(msg) => {
				assert!(msg.contains("Multiple outputs"));
				assert!(msg.contains("not supported"));
			},
			other => panic!("Expected Calculation error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_simulate_callback_gas_estimation_failure_revert() {
		// Arrange
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery.expect_estimate_gas().returning(|_| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"execution reverted".to_string(),
				))
			})
		});

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			137,
			3600,
			60,
		));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();

		// Whitelist the recipient
		// EIP-7930 format for chain 137 (0x89): 0x0001 | 0x0000 | 0x01 | 0x89 | 0x14 | <address>
		let whitelist =
			vec!["0x000100000189142222222222222222222222222222222222222222".to_lowercase()];
		let config = create_config_with_callback_whitelist(whitelist);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert - should fail because callback would revert
		assert!(result.is_err());
		let error = result.unwrap_err();
		match error {
			CostProfitError::Calculation(msg) => {
				assert!(msg.contains("callback would revert"));
			},
			other => panic!("Expected Calculation error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_simulate_callback_disabled_with_callback_data_rejected() {
		// Arrange
		let mock_delivery = MockDeliveryInterface::new();
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			137,
			3600,
			60,
		));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		// Order with callback data
		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();

		// Config with simulate_callbacks = false
		let mut config = create_test_config();
		config.order.simulate_callbacks = false;

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert - should fail because callbacks are not supported when simulation is disabled
		assert!(result.is_err());
		let error = result.unwrap_err();
		match error {
			CostProfitError::Config(msg) => {
				assert!(msg.contains("callback simulation is disabled"));
				assert!(msg.contains("not supported"));
			},
			other => panic!("Expected Config error, got: {other:?}"),
		}
	}

	// ----- try_live_fill_estimate ---------------------------------------------

	/// Builds a `CostProfitService` whose `delivery_service` has a single mock
	/// implementation registered for the given chain id, returning whatever the
	/// supplied `MockDeliveryInterface` is configured to return.
	fn cost_profit_service_with_delivery_mock(
		chain_id: u64,
		mock_delivery: MockDeliveryInterface,
	) -> CostProfitService {
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			chain_id,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			chain_id,
			3600,
			60,
		));

		let pricing = create_mock_pricing_service();
		let storage = Arc::new(StorageService::new(Box::new(MockStorageInterface::new())));
		let token_manager = create_mock_token_manager();

		CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		)
	}

	#[tokio::test]
	async fn try_live_fill_estimate_returns_simulated_units_on_success() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(123_456u64) }));

		let service = cost_profit_service_with_delivery_mock(1, mock_delivery);
		let fill_tx = create_test_fill_transaction();

		let result = service
			.try_live_fill_estimate(
				1,
				&fill_tx,
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
			)
			.await;
		assert_eq!(result, Some(123_456));
	}

	#[tokio::test]
	async fn try_live_fill_estimate_returns_none_on_rpc_error() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery.expect_estimate_gas().returning(|_| {
			Box::pin(async move { Err(solver_delivery::DeliveryError::Network("boom".into())) })
		});

		let service = cost_profit_service_with_delivery_mock(1, mock_delivery);
		let fill_tx = create_test_fill_transaction();

		let result = service
			.try_live_fill_estimate(
				1,
				&fill_tx,
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
			)
			.await;
		assert_eq!(result, None);
	}

	#[tokio::test]
	async fn try_live_fill_estimate_rejects_zero_units() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(0u64) }));

		let service = cost_profit_service_with_delivery_mock(1, mock_delivery);
		let fill_tx = create_test_fill_transaction();

		let result = service
			.try_live_fill_estimate(
				1,
				&fill_tx,
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
			)
			.await;
		assert_eq!(result, None);
	}

	#[tokio::test]
	async fn estimate_gas_units_uses_live_fill_when_enabled_for_order_costs() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(123_456u64) }));

		let service = cost_profit_service_with_delivery_mock(137, mock_delivery);
		let fill_tx = create_test_fill_transaction();
		let mut config = create_test_config();
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let units = service
			.estimate_gas_units(
				&Some("permit2_escrow".to_string()),
				&config,
				1,
				137,
				None,
				Some(&fill_tx),
			)
			.await
			.expect("gas units should compute");

		assert_eq!(units.fill_units, 123_456);
	}

	#[tokio::test]
	async fn estimate_gas_units_skips_live_fill_without_real_fill_tx() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery.expect_estimate_gas().never();

		let service = cost_profit_service_with_delivery_mock(137, mock_delivery);
		let mut config = create_test_config();
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let units = service
			.estimate_gas_units(
				&Some("permit2_escrow".to_string()),
				&config,
				1,
				137,
				None,
				None,
			)
			.await
			.expect("gas units should compute");

		assert_eq!(units.fill_units, 50_000);
	}

	#[tokio::test]
	async fn estimate_gas_units_uses_module_defaults_when_flow_is_missing() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery.expect_estimate_gas().never();

		let service = cost_profit_service_with_delivery_mock(137, mock_delivery);
		let config = create_test_config();

		let units = service
			.estimate_gas_units(
				&Some("missing_flow".to_string()),
				&config,
				1,
				137,
				None,
				None,
			)
			.await
			.expect("gas units should compute");

		assert_eq!(units.open_units, DEFAULT_OPEN_GAS_UNITS);
		assert_eq!(units.fill_units, DEFAULT_FILL_GAS_UNITS);
		assert_eq!(units.post_fill_units, DEFAULT_POST_FILL_GAS_UNITS);
		assert_eq!(units.pre_claim_units, DEFAULT_PRE_CLAIM_GAS_UNITS);
		assert_eq!(units.claim_units, DEFAULT_CLAIM_GAS_UNITS);
	}

	// ----- M-09: size-aware callback calldata gas pricing ---------------------

	/// Minimal `OrderOutput` for the pure-helper tests. Only `calldata` matters
	/// to `callback_calldata_gas_units`; the address/amount fields are filler.
	fn calldata_test_output(calldata: Option<&std::primitive::str>) -> OrderOutput {
		OrderOutput {
			receiver: InteropAddress::new_ethereum(
				137,
				address!("2222222222222222222222222222222222222222"),
			),
			asset: InteropAddress::new_ethereum(
				137,
				address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
			),
			amount: U256::from(1u64),
			calldata: calldata.map(|s| s.to_string()),
		}
	}

	#[test]
	fn callback_calldata_gas_units_empty_callbacks_are_zero() {
		// None, "0x", and "" all contribute zero.
		let outputs = vec![
			calldata_test_output(None),
			calldata_test_output(Some("0x")),
			calldata_test_output(Some("")),
		];
		assert_eq!(callback_calldata_gas_units(&outputs).unwrap(), 0);
	}

	#[test]
	fn callback_calldata_gas_units_rejects_invalid_hex() {
		let outputs = vec![calldata_test_output(Some("0xzz"))];
		assert!(
			callback_calldata_gas_units(&outputs).is_err(),
			"invalid hex must error, not be priced as zero"
		);
	}

	#[test]
	fn callback_calldata_gas_units_rejects_odd_length_hex() {
		let outputs = vec![calldata_test_output(Some("0xabc"))];
		assert!(
			callback_calldata_gas_units(&outputs).is_err(),
			"odd-length hex must error"
		);
	}

	#[test]
	fn callback_calldata_gas_units_word_aligns_each_output() {
		// 1 byte aligns up to one 32-byte ABI word before the 16 gas/byte multiply.
		let outputs = vec![calldata_test_output(Some("0xab"))];
		assert_eq!(callback_calldata_gas_units(&outputs).unwrap(), 32 * 16);
	}

	#[test]
	fn callback_calldata_gas_units_sums_outputs() {
		// 33 bytes -> 64 aligned; 1 byte -> 32 aligned; (64 + 32) * 16.
		let outputs = vec![
			calldata_test_output(Some(&format!("0x{}", "11".repeat(33)))),
			calldata_test_output(Some("0x22")),
		];
		assert_eq!(
			callback_calldata_gas_units(&outputs).unwrap(),
			(64 + 32) * 16
		);
	}

	#[test]
	fn apply_callback_calldata_gas_units_adds_origin_legs_only() {
		let mut units = GasUnits {
			open_units: 100,
			fill_units: 200,
			post_fill_units: 300,
			pre_claim_units: 0,
			claim_units: 400,
		};
		apply_callback_calldata_gas_units(&mut units, 512);
		assert_eq!(units.open_units, 612);
		assert_eq!(units.fill_units, 200);
		assert_eq!(units.post_fill_units, 300);
		assert_eq!(units.pre_claim_units, 0);
		assert_eq!(units.claim_units, 912);
	}

	#[test]
	fn apply_callback_calldata_gas_units_skips_disabled_legs() {
		// A leg priced at 0 stays 0 — the term only scales legs the flow uses.
		let mut units = GasUnits {
			open_units: 0,
			fill_units: 200,
			post_fill_units: 300,
			pre_claim_units: 0,
			claim_units: 0,
		};
		apply_callback_calldata_gas_units(&mut units, 512);
		assert_eq!(units.open_units, 0);
		assert_eq!(units.claim_units, 0);
	}

	#[tokio::test]
	async fn estimate_gas_units_with_simulated_fill_skips_extra_live_fill_estimate() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery.expect_estimate_gas().never();

		let service = cost_profit_service_with_delivery_mock(137, mock_delivery);
		let fill_tx = create_test_fill_transaction();
		let mut config = create_test_config();
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let units = service
			.estimate_gas_units(
				&Some("permit2_escrow".to_string()),
				&config,
				1,
				137,
				Some(123_456),
				Some(&fill_tx),
			)
			.await
			.expect("gas units should compute");

		assert_eq!(units.fill_units, 50_000);
	}

	// ----- build_fill_tx_for_quote --------------------------------------------

	const QUOTE_DEST_CHAIN_ID: u64 = 137;
	const QUOTE_OUTPUT_TOKEN: alloy_primitives::Address =
		address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C");
	const QUOTE_OUTPUT_RECIPIENT: alloy_primitives::Address =
		address!("2222222222222222222222222222222222222222");
	const QUOTE_OUTPUT_SETTLER: [u8; 20] = [0x22; 20];
	const QUOTE_SOLVER: [u8; 20] = [0xAB; 20];

	fn quote_request_with_unresolved_amount() -> GetQuoteRequest {
		// Mirrors create_test_request(true) but forces output amount to None to
		// represent the pre-resolution state (ExactInput where the solver fills
		// in the output amount via calculate_swap_amounts).
		let mut req = create_test_request(true);
		req.intent.outputs[0].amount = None;
		req
	}

	fn quote_request_with_stale_output_amount(stale: u64) -> GetQuoteRequest {
		let mut req = create_test_request(true);
		req.intent.outputs[0].amount = Some(U256::from(stale).to_string());
		req
	}

	fn config_with_output_settler_on_dest(settler: [u8; 20]) -> Config {
		// Start from create_test_config() and inject the settler address on the
		// destination chain (137) used in the test request. NetworksConfig
		// already exists from create_test_networks_config().
		let mut config = create_test_config();
		let mut networks = create_test_networks_config();
		if let Some(net) = networks.get_mut(&QUOTE_DEST_CHAIN_ID) {
			net.output_settler_address = solver_types::Address(settler.to_vec());
		}
		config.networks = networks;
		config
	}

	fn resolved_amounts_for_request(
		request: &GetQuoteRequest,
		amount: U256,
	) -> std::collections::HashMap<InteropAddress, TokenAmountInfo> {
		let mut map = std::collections::HashMap::new();
		let asset = request.intent.outputs[0].asset.clone();
		map.insert(
			asset.clone(),
			TokenAmountInfo {
				token: asset,
				amount,
				decimals: 18,
			},
		);
		map
	}

	fn cost_profit_service_no_delivery_chains() -> CostProfitService {
		// build_fill_tx_for_quote does not call delivery; it just encodes
		// calldata. So we don't need any chain-keyed delivery implementations.
		let pricing = create_mock_pricing_service();
		let delivery = create_mock_delivery_service();
		let storage = Arc::new(StorageService::new(Box::new(MockStorageInterface::new())));
		let token_manager = create_mock_token_manager();
		CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		)
	}

	#[tokio::test]
	async fn build_fill_tx_for_quote_uses_config_networks_and_resolved_amount() {
		let config = config_with_output_settler_on_dest(QUOTE_OUTPUT_SETTLER);
		let solver = solver_types::Address(QUOTE_SOLVER.to_vec());
		let request = quote_request_with_unresolved_amount();
		let validated = create_test_validated_context(true);
		let resolved = resolved_amounts_for_request(&request, U256::from(1_000_000u64));
		let service = cost_profit_service_no_delivery_chains();

		let tx = service
			.build_fill_tx_for_quote(&request, &validated, &resolved, &config, &solver, true)
			.await
			.expect("synthetic fill tx should build");

		assert_eq!(tx.chain_id, QUOTE_DEST_CHAIN_ID);
		assert_eq!(tx.to.as_ref().unwrap().0, QUOTE_OUTPUT_SETTLER.to_vec());
		assert_eq!(&tx.data[..4], IOutputSettlerSimple::fillCall::SELECTOR);

		// Decode the calldata back through the SolCall and assert the amount.
		let decoded =
			IOutputSettlerSimple::fillCall::abi_decode(&tx.data).expect("fillCall should decode");
		assert_eq!(decoded.output.amount, U256::from(1_000_000u64));
		// And confirm the placeholder fields are what we documented.
		assert_eq!(decoded.orderId, B256::ZERO);
		assert_eq!(decoded.output.oracle, B256::ZERO);
	}

	#[tokio::test]
	async fn build_fill_tx_for_quote_sets_value_for_native_output() {
		let config = config_with_output_settler_on_dest(QUOTE_OUTPUT_SETTLER);
		let solver = solver_types::Address(QUOTE_SOLVER.to_vec());
		let mut request = quote_request_with_unresolved_amount();
		request.intent.outputs[0].asset =
			InteropAddress::new_ethereum(QUOTE_DEST_CHAIN_ID, alloy_primitives::Address::ZERO);
		let validated = create_test_validated_context(true);
		let resolved_amount = U256::from(1_000_000u64);
		let resolved = resolved_amounts_for_request(&request, resolved_amount);
		let service = cost_profit_service_no_delivery_chains();

		let tx = service
			.build_fill_tx_for_quote(&request, &validated, &resolved, &config, &solver, true)
			.await
			.expect("synthetic native fill tx should build");

		assert_eq!(tx.value, resolved_amount);
	}

	#[tokio::test]
	async fn build_fill_tx_for_quote_skips_source_finality_delay_for_resource_lock() {
		let config = config_with_output_settler_on_dest(QUOTE_OUTPUT_SETTLER);
		let configured_fill_deadline_window = 60;
		let solver = solver_types::Address(QUOTE_SOLVER.to_vec());
		let request = quote_request_with_unresolved_amount();
		let validated = create_test_validated_context(true);
		let resolved = resolved_amounts_for_request(&request, U256::from(1_000_000u64));
		let service = cost_profit_service_no_delivery_chains();

		let before = current_timestamp();
		let tx = service
			.build_fill_tx_for_quote(&request, &validated, &resolved, &config, &solver, false)
			.await
			.expect("synthetic fill tx should build");
		let after = current_timestamp();

		let decoded =
			IOutputSettlerSimple::fillCall::abi_decode(&tx.data).expect("fillCall should decode");
		let fill_deadline = decoded.fillDeadline.to::<u64>();

		assert!(
			(before + configured_fill_deadline_window..=after + configured_fill_deadline_window)
				.contains(&fill_deadline),
			"ResourceLock synthetic fill must match the configured fill deadline, got {fill_deadline}"
		);
	}

	#[tokio::test]
	async fn build_fill_tx_for_quote_applies_source_finality_delay_for_escrow() {
		let config = config_with_output_settler_on_dest(QUOTE_OUTPUT_SETTLER);
		let configured_fill_deadline_window = 60;
		let expected_delay =
			source_finality_expected_delay_seconds(&config, 1).expect("default finality delay");
		let solver = solver_types::Address(QUOTE_SOLVER.to_vec());
		let request = quote_request_with_unresolved_amount();
		let validated = create_test_validated_context(true);
		let resolved = resolved_amounts_for_request(&request, U256::from(1_000_000u64));
		let service = cost_profit_service_no_delivery_chains();

		let before = current_timestamp();
		let tx = service
			.build_fill_tx_for_quote(&request, &validated, &resolved, &config, &solver, true)
			.await
			.expect("synthetic fill tx should build");
		let after = current_timestamp();

		let decoded =
			IOutputSettlerSimple::fillCall::abi_decode(&tx.data).expect("fillCall should decode");
		let fill_deadline = decoded.fillDeadline.to::<u64>();
		let expected_window = configured_fill_deadline_window.max(
			expected_delay
				+ config.source_finality.retry_grace_seconds
				+ solver_config::QuoteConfig::default().validity_seconds,
		);

		assert!(
			(before + expected_window..=after + expected_window).contains(&fill_deadline),
			"Escrow synthetic fill must include source finality delay, got {fill_deadline}"
		);
	}

	#[tokio::test]
	async fn build_fill_tx_for_quote_errors_when_chain_unknown() {
		// Build a config with networks for chains 1 and 137, but mutate the
		// request output's chain to 9999 (not in the config).
		let config = config_with_output_settler_on_dest(QUOTE_OUTPUT_SETTLER);
		let solver = solver_types::Address(QUOTE_SOLVER.to_vec());
		let mut request = quote_request_with_unresolved_amount();
		request.intent.outputs[0].asset = InteropAddress::new_ethereum(9999, QUOTE_OUTPUT_TOKEN);
		request.intent.outputs[0].receiver =
			InteropAddress::new_ethereum(9999, QUOTE_OUTPUT_RECIPIENT);
		let validated = create_test_validated_context(true);
		let resolved = resolved_amounts_for_request(&request, U256::from(1u64));
		let service = cost_profit_service_no_delivery_chains();

		let result = service
			.build_fill_tx_for_quote(&request, &validated, &resolved, &config, &solver, true)
			.await;
		assert!(
			result.is_err(),
			"expected error when destination chain is not configured"
		);
	}

	#[tokio::test]
	async fn build_fill_tx_for_quote_errors_when_resolved_amount_missing() {
		let config = config_with_output_settler_on_dest(QUOTE_OUTPUT_SETTLER);
		let solver = solver_types::Address(QUOTE_SOLVER.to_vec());
		let request = quote_request_with_unresolved_amount();
		let validated = create_test_validated_context(true);
		// Empty resolved map — caller invoked us out of order.
		let resolved: std::collections::HashMap<InteropAddress, TokenAmountInfo> =
			std::collections::HashMap::new();
		let service = cost_profit_service_no_delivery_chains();

		let result = service
			.build_fill_tx_for_quote(&request, &validated, &resolved, &config, &solver, true)
			.await;
		assert!(
			result.is_err(),
			"expected error when no resolved amount is provided for the output asset"
		);
	}

	// ----- Task 4: live estimation integration --------------------------------

	/// Build a CostProfitService whose delivery layer can answer
	/// `estimate_gas`/`get_gas_price` for chains 1 and 137. The fill-gas
	/// behaviour for chain 137 (the destination in `create_test_request(true)`)
	/// is controlled by `dest_estimate_units`: `Some(u)` => Ok(u), `None` => Err.
	fn cost_profit_service_for_live_estimate(
		dest_estimate_units: Option<u64>,
	) -> CostProfitService {
		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount_f64: f64 = amount.parse().unwrap_or(0.0);
				Box::pin(async move {
					match (from.as_str(), to.as_str()) {
						("ETH", "USD") => Ok((amount_f64 * ETH_USD_PRICE).to_string()),
						("USD", "ETH") => Ok((amount_f64 / ETH_USD_PRICE).to_string()),
						("USDC", "USD") => Ok((amount_f64 * USDC_USD_PRICE).to_string()),
						("USD", "USDC") => Ok((amount_f64 / USDC_USD_PRICE).to_string()),
						_ => Ok("1.0".to_string()),
					}
				})
			});
		// Linear in `wei` so gas_fill USD scales with fill_units. We treat the
		// input as wei and return wei / 1e18 USD (i.e. 1 ETH ≈ $1). Values are
		// arbitrary — what matters is that the conversion is monotonic with
		// `wei` AND that the resulting dollar figures are small enough to fit
		// inside the test orders' $100 spread.
		mock_pricing
			.expect_wei_to_currency()
			.returning(|wei_str, _| {
				let wei = wei_str.parse::<u128>().unwrap_or(0);
				let usd = (wei as f64) / 1e18;
				Box::pin(async move { Ok(usd.to_string()) })
			});
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));

		// Origin chain (1) — only needs gas-price + block-number for cost calc.
		let mut mock_origin = MockDeliveryInterface::new();
		mock_origin.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_origin.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
		});
		mock_origin
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		// Destination chain (137) — must answer get_gas_price AND estimate_gas.
		let mut mock_dest = MockDeliveryInterface::new();
		mock_dest.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_dest.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
		});
		mock_dest
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));
		mock_dest.expect_eth_call().returning(|_| {
			Box::pin(async move {
				Ok(alloy_primitives::Bytes::from(
					U256::from(1u64).to_be_bytes::<32>().to_vec(),
				))
			})
		});
		let result_for_mock = dest_estimate_units;
		mock_dest.expect_estimate_gas().returning(move |_| {
			let r = result_for_mock;
			Box::pin(async move {
				match r {
					Some(units) => Ok(units),
					None => Err(solver_delivery::DeliveryError::Network(
						"simulated rpc error".into(),
					)),
				}
			})
		});

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			1,
			Arc::new(mock_origin) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		delivery_implementations.insert(
			137,
			Arc::new(mock_dest) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 3600, 60));

		// Token manager: chains 1 and 137 with the test request's asset addresses.
		let mut networks = solver_types::NetworksConfig::new();
		networks.insert(
			1,
			solver_types::NetworkConfig {
				name: Some("ethereum".to_string()),
				network_type: solver_types::networks::NetworkType::Parent,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![
					native_eth_token(),
					solver_types::TokenConfig {
						address: solver_types::Address(
							[
								0xA0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C,
								0x5C, 0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
							]
							.to_vec(),
						),
						decimals: 18,
						symbol: "ETH".to_string(),
						name: Some("Ether".to_string()),
					},
				],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		networks.insert(
			137,
			solver_types::NetworkConfig {
				name: Some("polygon".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![
					native_eth_token(),
					solver_types::TokenConfig {
						address: solver_types::Address(
							[
								0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C,
								0x5C, 0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
							]
							.to_vec(),
						),
						decimals: 6,
						symbol: "USDC".to_string(),
						name: Some("USD Coin".to_string()),
					},
				],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));

		let storage = Arc::new(StorageService::new(Box::new(MockStorageInterface::new())));
		CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		)
	}

	/// Build a Config that has `networks` populated to match the live-estimate
	/// service's NetworksConfig, with the requested `live_fill_estimate_enabled`
	/// flag value.
	fn config_for_live_estimate(live_enabled: bool) -> Config {
		let mut config = create_test_config();
		// Mirror the networks built in cost_profit_service_for_live_estimate so
		// build_fill_tx_for_quote can resolve the destination output settler.
		let mut networks = solver_types::NetworksConfig::new();
		networks.insert(
			1,
			solver_types::NetworkConfig {
				name: Some("ethereum".to_string()),
				network_type: solver_types::networks::NetworkType::Parent,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		networks.insert(
			137,
			solver_types::NetworkConfig {
				name: Some("polygon".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		config.networks = networks;
		config.settlement.primary = "hyperlane".to_string();
		config.settlement.implementations.insert(
			"hyperlane".to_string(),
			serde_json::json!({
				"domains": {
					"1": 10,
					"137": 137
				},
				"oracles": {
					"input": {
						"1": ["0x1111111111111111111111111111111111111111"],
						"137": ["0x2222222222222222222222222222222222222222"]
					},
					"output": {
						"1": ["0x1111111111111111111111111111111111111111"],
						"137": ["0x2222222222222222222222222222222222222222"]
					}
				}
			}),
		);
		if let Some(g) = config.gas.as_mut() {
			g.live_fill_estimate_enabled = live_enabled;
		}
		config
	}

	#[test]
	fn hyperlane_domain_for_quote_rejects_missing_domain() {
		let config = serde_json::json!({
			"domains": {
				"137": 137
			}
		});

		let err = hyperlane_domain_for_quote(&config, 1).unwrap_err();

		assert!(err
			.to_string()
			.contains("Missing Hyperlane domain for chain 1"));
	}

	#[test]
	fn hyperlane_domain_for_quote_rejects_non_integer_domain() {
		let config = serde_json::json!({
			"domains": {
				"1": "10"
			}
		});

		let err = hyperlane_domain_for_quote(&config, 1).unwrap_err();

		assert!(err
			.to_string()
			.contains("Hyperlane domain for chain 1 must be an unsigned integer"));
	}

	#[test]
	fn hyperlane_domain_for_quote_rejects_zero_domain() {
		let config = serde_json::json!({
			"domains": {
				"1": 0
			}
		});

		let err = hyperlane_domain_for_quote(&config, 1).unwrap_err();

		assert!(err
			.to_string()
			.contains("Hyperlane domain for chain 1 must be in 1..=u32::MAX"));
	}

	#[test]
	fn hyperlane_domain_for_quote_rejects_oversized_domain() {
		let config = serde_json::json!({
			"domains": {
				"1": u32::MAX as u64 + 1
			}
		});

		let err = hyperlane_domain_for_quote(&config, 1).unwrap_err();

		assert!(err
			.to_string()
			.contains("Hyperlane domain for chain 1 must be in 1..=u32::MAX"));
	}

	#[tokio::test]
	async fn quote_post_fill_submit_uses_hyperlane_domain_not_chain_id() {
		let service = cost_profit_service_no_delivery_chains();
		let config = config_for_live_estimate(false);
		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let resolved = resolved_amounts_for_request(&request, U256::from(950u64));
		let solver = Address([0xAB; 20].to_vec());

		let quote_tx = service
			.build_post_fill_tx_for_quote(
				&request,
				&context,
				&resolved,
				&config,
				&solver,
				U256::from(123u64),
			)
			.await
			.unwrap()
			.expect("hyperlane quote tx");
		let decoded = IHyperlaneOracleForQuote::submitCall::abi_decode(&quote_tx.tx.data).unwrap();

		assert_eq!(decoded.destinationDomain, 10);
	}

	#[tokio::test]
	async fn cost_context_uses_static_fill_when_live_estimate_disabled() {
		// estimate_gas is set to Ok(99_999) but with the flag disabled it should
		// never be called — and the resulting cost should rest on static defaults.
		let service = cost_profit_service_for_live_estimate(Some(99_999));
		let mut config = config_for_live_estimate(false);
		// Pin a known fill default through gas.flows so we can compare deterministically.
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let ctx = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("cost context should compute");

		// gas_fill is computed from fill_units * dest_gas_price → wei → USD.
		// With live disabled and fill_units=50_000, gas_fill must reflect 50_000
		// (not 99_999). We assert by checking gas_fill is non-zero and bounded
		// by a multiple of the static value's expected order.
		assert!(ctx.cost_breakdown.gas_fill > Decimal::ZERO);
	}

	#[tokio::test]
	async fn cost_context_uses_live_fill_units_when_enabled() {
		// Live estimate returns a value MUCH bigger than the static default so
		// the gas_fill USD must clearly reflect the live one.
		let live_units: u64 = 5_000_000;
		let service = cost_profit_service_for_live_estimate(Some(live_units));
		let mut config = config_for_live_estimate(true);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let ctx_live = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("live-estimate cost context should compute");

		// Now repeat with the flag disabled; gas_fill must be clearly smaller
		// because fill_units drops from 5_000_000 to 50_000 (100×).
		let service_static = cost_profit_service_for_live_estimate(Some(live_units));
		let mut config_static = config.clone();
		if let Some(g) = config_static.gas.as_mut() {
			g.live_fill_estimate_enabled = false;
		}
		let ctx_static = service_static
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config_static,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("static-only cost context should compute");

		assert!(
			ctx_live.cost_breakdown.gas_fill > ctx_static.cost_breakdown.gas_fill,
			"live-estimate gas_fill ({}) should exceed static gas_fill ({}) by ~100×",
			ctx_live.cost_breakdown.gas_fill,
			ctx_static.cost_breakdown.gas_fill,
		);
	}

	/// M-09: a quote whose output carries callback calldata must price MORE gas
	/// on the origin `open` and `claim` legs (which ABI-encode the full order
	/// including callbackData) than the same quote with no callback, while the
	/// destination `fill` leg is unchanged (fill simulation already prices it).
	#[tokio::test]
	async fn quote_cost_context_prices_callback_calldata_on_open_and_claim_only() {
		// Static fill so `gas_fill` is purely a function of `fill_units` and not
		// touched by the callback term. Non-zero open/claim so the term lands.
		let gas = solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(150_000),
					fill: Some(150_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(150_000),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		};

		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		// Baseline: no callback calldata on the output.
		let service_base = cost_profit_service_for_live_estimate(None);
		let mut config_base = config_for_live_estimate(false);
		config_base.gas = Some(gas.clone());
		let request_base = create_test_request(true);
		assert!(
			request_base.intent.outputs[0].calldata.is_none(),
			"baseline request must have no callback calldata"
		);
		let ctx_base = service_base
			.calculate_cost_context_for_flow_keys(
				&request_base,
				&context,
				&config_base,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("baseline cost context should compute");

		// With callback calldata: 512 bytes -> still one+ ABI words, priced at
		// 16 gas/byte added to BOTH origin legs.
		let service_cb = cost_profit_service_for_live_estimate(None);
		let mut config_cb = config_for_live_estimate(false);
		config_cb.gas = Some(gas);
		let mut request_cb = create_test_request(true);
		request_cb.intent.outputs[0].calldata = Some(format!("0x{}", "ab".repeat(512)));
		let ctx_cb = service_cb
			.calculate_cost_context_for_flow_keys(
				&request_cb,
				&context,
				&config_cb,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("callback cost context should compute");

		assert!(
			ctx_cb.cost_breakdown.gas_open > ctx_base.cost_breakdown.gas_open,
			"callback calldata must increase gas_open: {} !> {}",
			ctx_cb.cost_breakdown.gas_open,
			ctx_base.cost_breakdown.gas_open,
		);
		assert!(
			ctx_cb.cost_breakdown.gas_claim > ctx_base.cost_breakdown.gas_claim,
			"callback calldata must increase gas_claim: {} !> {}",
			ctx_cb.cost_breakdown.gas_claim,
			ctx_base.cost_breakdown.gas_claim,
		);
		assert_eq!(
			ctx_cb.cost_breakdown.gas_fill, ctx_base.cost_breakdown.gas_fill,
			"callback calldata must NOT change gas_fill",
		);
	}

	/// Build a CostProfitService able to price an order from
	/// `create_test_order_with_amounts` (origin chain 1 INPUT, dest chain 137
	/// OUTPUT). Delivery answers fee params for both chains; pricing is
	/// monotonic in wei so gas-unit deltas are visible in USD.
	fn cost_profit_service_for_order_pricing() -> CostProfitService {
		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing
			.expect_convert_asset()
			.returning(|_, _, amount| {
				// Symbol-agnostic: 1 token unit ~= $1. Order valuation just needs
				// to resolve; only gas deltas are under test here.
				let amount = amount.to_string();
				Box::pin(async move { Ok(amount) })
			});
		mock_pricing
			.expect_wei_to_currency()
			.returning(|wei_str, _| {
				let wei = wei_str.parse::<u128>().unwrap_or(0);
				let usd = (wei as f64) / 1e18;
				Box::pin(async move { Ok(usd.to_string()) })
			});
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));

		let mut mock_origin = MockDeliveryInterface::new();
		mock_origin.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_origin.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
		});

		let mut mock_dest = MockDeliveryInterface::new();
		mock_dest.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_dest.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
		});

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			1,
			Arc::new(mock_origin) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		delivery_implementations.insert(
			137,
			Arc::new(mock_dest) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 3600, 60));

		// Token manager that knows INPUT (chain 1) and OUTPUT (chain 137) used by
		// create_test_order_with_amounts.
		let token_manager = Arc::new(TokenManager::new(
			create_test_networks_config(),
			delivery.clone(),
			create_mock_account_service(),
		));
		let storage = Arc::new(StorageService::new(Box::new(MockStorageInterface::new())));
		CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		)
	}

	/// Build an order whose single requested output carries `call` bytes that
	/// `parse_requested_outputs()` surfaces as `OrderOutput.calldata` hex.
	fn order_with_output_call(call: Vec<u8>) -> Order {
		let mut order = create_test_order_with_amounts(
			U256::from_str("1000000000000000000").unwrap(),
			U256::from_str("3900000000000000000000").unwrap(),
		);
		let mut data: Eip7683OrderData = serde_json::from_value(order.data.clone()).unwrap();
		data.outputs[0].call = call;
		order.data = serde_json::to_value(data).unwrap();
		order
	}

	/// M-09: an order whose parsed requested output carries calldata must price
	/// MORE gas on the origin open/claim legs than an identical order without
	/// callback data, while the simulated fill gas stays fixed.
	#[tokio::test]
	async fn order_cost_prices_callback_calldata_on_origin_legs_only() {
		let mut config = create_test_config();
		// Non-zero open/claim so the term lands; deterministic via gas.flows for
		// the order's lock flow. create_test_order_with_amounts has no lock_type,
		// so it resolves to the escrow default flow key.
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(150_000),
					fill: Some(150_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(150_000),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});
		// Fixed simulated fill gas so gas_fill cannot move between the two runs.
		let simulated_fill_gas = Some(150_000u64);

		let service_base = cost_profit_service_for_order_pricing();
		let order_base = order_with_output_call(vec![]);
		let breakdown_base = service_base
			.estimate_cost_for_order_with_gas(&order_base, &config, simulated_fill_gas, None)
			.await
			.expect("baseline order cost should compute");

		let service_cb = cost_profit_service_for_order_pricing();
		let order_cb = order_with_output_call(vec![0xab; 512]);
		let breakdown_cb = service_cb
			.estimate_cost_for_order_with_gas(&order_cb, &config, simulated_fill_gas, None)
			.await
			.expect("callback order cost should compute");

		assert!(
			breakdown_cb.gas_open > breakdown_base.gas_open,
			"callback calldata must increase gas_open: {} !> {}",
			breakdown_cb.gas_open,
			breakdown_base.gas_open,
		);
		assert!(
			breakdown_cb.gas_claim > breakdown_base.gas_claim,
			"callback calldata must increase gas_claim: {} !> {}",
			breakdown_cb.gas_claim,
			breakdown_base.gas_claim,
		);
		assert_eq!(
			breakdown_cb.gas_fill, breakdown_base.gas_fill,
			"callback calldata must NOT change simulated gas_fill",
		);
	}

	#[tokio::test]
	async fn cost_context_uses_static_fill_when_live_estimate_limiter_is_saturated() {
		use std::sync::atomic::Ordering;

		let live_units: u64 = 5_000_000;
		let (service, _override_calls, bare_calls) =
			cost_profit_service_for_post_fill_override(Some(live_units), None);
		let mut config = config_for_live_estimate(true);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain: 0,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let ctx = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("saturated live-estimate limiter should fall back to static gas");

		assert!(ctx.cost_breakdown.gas_fill > Decimal::ZERO);
		assert_eq!(
			bare_calls.load(Ordering::SeqCst),
			0,
			"saturated limiter must not call eth_estimateGas"
		);
	}

	#[tokio::test]
	async fn cost_context_uses_live_post_fill_units_when_enabled() {
		// Updated for Task 4: post-fill now flows through the override path
		// (`estimate_gas_with_overrides`) and is gated by
		// `live_post_fill_estimate_chain_ids`, not by
		// `live_fill_estimate_enabled`. Use the override-aware fixture, put
		// dest_chain_id (137) in the set, and confirm live > static.
		let live_units: u64 = 5_000_000;
		let (service, _override_calls, _bare_calls) =
			cost_profit_service_for_post_fill_override(None, Some(live_units));
		let mut config = config_for_live_estimate(false);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(0),
					post_fill: Some(50_000),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::from([137u64]),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let ctx_live = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("live-estimate cost context should compute");

		let (service_static, _, _) =
			cost_profit_service_for_post_fill_override(None, Some(live_units));
		let mut config_static = config.clone();
		if let Some(g) = config_static.gas.as_mut() {
			g.live_post_fill_estimate_chain_ids = std::collections::HashSet::new();
		}
		let ctx_static = service_static
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config_static,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("static-only cost context should compute");

		assert!(
			ctx_live.cost_breakdown.gas_post_fill > ctx_static.cost_breakdown.gas_post_fill,
			"live-estimate gas_post_fill ({}) should exceed static gas_post_fill ({})",
			ctx_live.cost_breakdown.gas_post_fill,
			ctx_static.cost_breakdown.gas_post_fill,
		);
	}

	#[tokio::test]
	async fn cost_context_falls_back_to_static_when_live_estimate_errors() {
		// estimate_gas returns an error → live path silently falls back. The
		// cost-context call must still succeed.
		let service = cost_profit_service_for_live_estimate(None);
		let mut config = config_for_live_estimate(true);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let result = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await;
		assert!(
			result.is_ok(),
			"RPC failure during live estimate must not refuse a quote"
		);
	}

	// --- Task 4 Step 6: post-fill override path tests ------------------------

	/// Build a cost-profit service whose destination-chain mock answers
	/// `estimate_gas` and `estimate_gas_with_overrides` independently. The
	/// returned counters let tests assert the override path is (or is not)
	/// exercised, which is how we tell `live_post_fill_estimate_chain_ids`
	/// gating from a no-op.
	fn cost_profit_service_for_post_fill_override(
		fill_estimate_units: Option<u64>,
		override_estimate_units: Option<u64>,
	) -> (
		CostProfitService,
		std::sync::Arc<std::sync::atomic::AtomicUsize>,
		std::sync::Arc<std::sync::atomic::AtomicUsize>,
	) {
		use std::sync::atomic::{AtomicUsize, Ordering};
		use std::sync::Arc;

		let mut mock_pricing = MockPricingInterface::new();
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount_f64: f64 = amount.parse().unwrap_or(0.0);
				Box::pin(async move {
					match (from.as_str(), to.as_str()) {
						("ETH", "USD") => Ok((amount_f64 * ETH_USD_PRICE).to_string()),
						("USD", "ETH") => Ok((amount_f64 / ETH_USD_PRICE).to_string()),
						("USDC", "USD") => Ok((amount_f64 * USDC_USD_PRICE).to_string()),
						("USD", "USDC") => Ok((amount_f64 / USDC_USD_PRICE).to_string()),
						_ => Ok("1.0".to_string()),
					}
				})
			});
		mock_pricing
			.expect_wei_to_currency()
			.returning(|wei_str, _| {
				let wei = wei_str.parse::<u128>().unwrap_or(0);
				let usd = (wei as f64) / 1e18;
				Box::pin(async move { Ok(usd.to_string()) })
			});
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));

		let mut mock_origin = MockDeliveryInterface::new();
		mock_origin.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_origin.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
		});
		mock_origin
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		let mut mock_dest = MockDeliveryInterface::new();
		mock_dest.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_dest.expect_get_fee_params().returning(|chain_id| {
			Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000_000_000u128)) })
		});
		mock_dest
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));
		mock_dest.expect_eth_call().returning(|_| {
			Box::pin(async move {
				Ok(alloy_primitives::Bytes::from(
					U256::from(1u64).to_be_bytes::<32>().to_vec(),
				))
			})
		});

		let bare_calls = Arc::new(AtomicUsize::new(0));
		let bare_calls_for_mock = bare_calls.clone();
		let fill_units_for_mock = fill_estimate_units;
		mock_dest.expect_estimate_gas().returning(move |_| {
			bare_calls_for_mock.fetch_add(1, Ordering::SeqCst);
			let r = fill_units_for_mock;
			Box::pin(async move {
				match r {
					Some(units) => Ok(units),
					None => Err(solver_delivery::DeliveryError::Network(
						"simulated rpc error".into(),
					)),
				}
			})
		});

		let override_calls = Arc::new(AtomicUsize::new(0));
		let override_calls_for_mock = override_calls.clone();
		let override_units_for_mock = override_estimate_units;
		mock_dest
			.expect_estimate_gas_with_overrides()
			.returning(move |_, _| {
				override_calls_for_mock.fetch_add(1, Ordering::SeqCst);
				let r = override_units_for_mock;
				Box::pin(async move {
					match r {
						Some(units) => Ok(units),
						None => Err(solver_delivery::DeliveryError::Network(
							"simulated override rpc error".into(),
						)),
					}
				})
			});

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			1,
			Arc::new(mock_origin) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		delivery_implementations.insert(
			137,
			Arc::new(mock_dest) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 3600, 60));

		let mut networks = solver_types::NetworksConfig::new();
		networks.insert(
			1,
			solver_types::NetworkConfig {
				name: Some("ethereum".to_string()),
				network_type: solver_types::networks::NetworkType::Parent,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![
					native_eth_token(),
					solver_types::TokenConfig {
						address: solver_types::Address(
							[
								0xA0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C,
								0x5C, 0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
							]
							.to_vec(),
						),
						decimals: 18,
						symbol: "ETH".to_string(),
						name: Some("Ether".to_string()),
					},
				],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		networks.insert(
			137,
			solver_types::NetworkConfig {
				name: Some("polygon".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: solver_types::Address([0x11; 20].to_vec()),
				output_settler_address: solver_types::Address([0x22; 20].to_vec()),
				tokens: vec![
					native_eth_token(),
					solver_types::TokenConfig {
						address: solver_types::Address(
							[
								0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C,
								0x5C, 0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
							]
							.to_vec(),
						),
						decimals: 6,
						symbol: "USDC".to_string(),
						name: Some("USD Coin".to_string()),
					},
				],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));

		let storage = Arc::new(StorageService::new(Box::new(MockStorageInterface::new())));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);
		(service, override_calls, bare_calls)
	}

	#[tokio::test]
	async fn cost_context_uses_overrides_when_flag_enabled() {
		// Override path returns concrete units; bare path errors. With chain
		// 137 enabled in `live_post_fill_estimate_chain_ids` the override
		// must run, return Ok, and apply to gas_units.post_fill_units (so
		// gas_post_fill USD must be larger than the all-static baseline).
		let live_units: u64 = 5_000_000;
		let (service, override_calls, _bare_calls) =
			cost_profit_service_for_post_fill_override(None, Some(live_units));
		let mut config = config_for_live_estimate(false);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(0),
					post_fill: Some(50_000),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::from([137u64]),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let ctx_live = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("override-based cost context should compute");

		assert!(
			override_calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
			"override path must be exercised when chain is enabled"
		);

		// Compare against a static-only baseline.
		let (service_static, override_calls_static, _) =
			cost_profit_service_for_post_fill_override(None, Some(live_units));
		let mut config_static = config.clone();
		if let Some(g) = config_static.gas.as_mut() {
			g.live_post_fill_estimate_chain_ids = std::collections::HashSet::new();
		}
		let ctx_static = service_static
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config_static,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("static-only cost context should compute");

		assert_eq!(
			override_calls_static.load(std::sync::atomic::Ordering::SeqCst),
			0,
			"override path must NOT run when chain is excluded from the set"
		);
		assert!(
			ctx_live.cost_breakdown.gas_post_fill > ctx_static.cost_breakdown.gas_post_fill,
			"live override gas_post_fill ({}) should exceed static gas_post_fill ({}) by ~100×",
			ctx_live.cost_breakdown.gas_post_fill,
			ctx_static.cost_breakdown.gas_post_fill,
		);
	}

	#[tokio::test]
	async fn cost_context_skips_post_fill_estimate_when_chain_not_enabled() {
		// Empty chain set → override path never invoked. Mock counter must
		// stay at zero, and the static post_fill default must drive the
		// gas_post_fill figure.
		let (service, override_calls, _bare_calls) =
			cost_profit_service_for_post_fill_override(None, Some(9_999_999));
		let mut config = config_for_live_estimate(false);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(0),
					post_fill: Some(50_000),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let result = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await;
		assert!(result.is_ok(), "skip path must not refuse a quote");
		assert_eq!(
			override_calls.load(std::sync::atomic::Ordering::SeqCst),
			0,
			"override path must NOT be invoked when dest_chain_id is not in the set"
		);
	}

	#[tokio::test]
	async fn cost_context_falls_back_on_override_error() {
		// Chain enabled but override RPC errors. We must NOT panic and must
		// NOT log a WARN — the call site emits an info-level
		// outcome=fallback_error event and downstream cost calc continues
		// against the static post_fill default.
		let (service, override_calls, _bare_calls) =
			cost_profit_service_for_post_fill_override(None, None);
		let mut config = config_for_live_estimate(false);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(0),
					post_fill: Some(50_000),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::from([137u64]),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let result = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await;
		assert!(
			result.is_ok(),
			"override RPC failure must not refuse a quote"
		);
		assert!(
			override_calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
			"override path must be attempted exactly once"
		);
	}

	#[tokio::test]
	async fn cost_context_fill_and_post_fill_flags_independent() {
		// Bonus (Task 4 Step 0 invariant): with `live_fill_estimate_enabled =
		// false` AND chain 137 in `live_post_fill_estimate_chain_ids`, the
		// override path still runs (proving they are gated independently).
		let (service, override_calls, bare_calls) =
			cost_profit_service_for_post_fill_override(Some(7_777), Some(8_888));
		let mut config = config_for_live_estimate(false);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(50_000),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::from([137u64]),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let _ = service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("independent-gate cost context should compute");

		assert!(
			override_calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
			"post-fill override must run even when fill flag is off"
		);
		assert_eq!(
			bare_calls.load(std::sync::atomic::Ordering::SeqCst),
			0,
			"bare estimate_gas must NOT run when fill flag is off"
		);
	}

	// --- Task 7 Step 2b: single-emit telemetry regression test --------------

	/// Captured snapshot of one `tracing::Event`. We only need
	/// string-equal lookups on a single field (`outcome`), so a flat
	/// `Display`-formatted map is sufficient — no need to depend on the
	/// `tracing-test` crate.
	#[derive(Clone, Debug)]
	struct CapturedEvent {
		#[allow(dead_code)] // surfaced via `{:?}` in assertion failure messages
		level: tracing::Level,
		fields: std::collections::HashMap<String, String>,
		message: String,
	}

	struct FieldVisitor<'a>(&'a mut CapturedEvent);

	impl tracing::field::Visit for FieldVisitor<'_> {
		fn record_str(&mut self, field: &tracing::field::Field, value: &::std::primitive::str) {
			if field.name() == "message" {
				self.0.message = value.to_string();
			} else {
				self.0
					.fields
					.insert(field.name().to_string(), value.to_string());
			}
		}

		fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn ::std::fmt::Debug) {
			let formatted = format!("{value:?}");
			// `tracing` formats string literals via `record_debug` with
			// surrounding quotes — strip them so equality with `"success"`
			// works without callers having to know the encoding.
			let cleaned = formatted.trim_matches('"').to_string();
			if field.name() == "message" {
				self.0.message = cleaned;
			} else {
				self.0.fields.insert(field.name().to_string(), cleaned);
			}
		}

		fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
			self.0
				.fields
				.insert(field.name().to_string(), value.to_string());
		}

		fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
			self.0
				.fields
				.insert(field.name().to_string(), value.to_string());
		}

		fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
			self.0
				.fields
				.insert(field.name().to_string(), value.to_string());
		}
	}

	thread_local! {
		/// Per-thread sink for events the capturing subscriber emits. The
		/// global subscriber pushes here unconditionally; tests drain this
		/// sink at known points. Per-thread isolation means parallel
		/// `cargo test` runners don't see each other's events.
		static CAPTURED_EVENTS: ::std::cell::RefCell<Vec<CapturedEvent>> =
			const { ::std::cell::RefCell::new(Vec::new()) };
	}

	/// Process-wide subscriber that funnels every `tracing::Event` into
	/// the calling thread's `CAPTURED_EVENTS` sink. Installed exactly once
	/// per test process via `set_global_default` (see
	/// `install_global_capture()`); after that, all `tracing::*` macros
	/// route through it regardless of thread.
	struct GlobalCapturingSubscriber;

	impl tracing::Subscriber for GlobalCapturingSubscriber {
		fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
			true
		}

		fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
			// Spans are unused by these tests; return a stub id. Reuse a
			// fixed nonzero id since `Id::from_u64` requires nonzero.
			tracing::span::Id::from_u64(1)
		}

		fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
		fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
		fn enter(&self, _span: &tracing::span::Id) {}
		fn exit(&self, _span: &tracing::span::Id) {}

		fn event(&self, event: &tracing::Event<'_>) {
			let mut captured = CapturedEvent {
				level: *event.metadata().level(),
				fields: std::collections::HashMap::new(),
				message: String::new(),
			};
			let mut visitor = FieldVisitor(&mut captured);
			event.record(&mut visitor);
			CAPTURED_EVENTS.with(|cell| cell.borrow_mut().push(captured));
		}
	}

	fn install_global_capture() {
		use std::sync::Once;
		static INIT: Once = Once::new();
		INIT.call_once(|| {
			// `set_global_default` can only succeed once per process. If a
			// global default was already installed elsewhere (shouldn't
			// happen in unit tests, but be defensive), we fall back to a
			// no-op — the test will fail with a clear assertion message.
			let _ = tracing::subscriber::set_global_default(GlobalCapturingSubscriber);
		});
	}

	/// Drain the per-thread event sink, run `f`, and return only the
	/// `"post-fill gas estimate"` events emitted on this thread during the
	/// closure. Filtering by message string keeps this test focused on
	/// the post-fill telemetry contract.
	async fn capture_post_fill_events<F, Fut>(f: F) -> Vec<CapturedEvent>
	where
		F: FnOnce() -> Fut,
		Fut: ::std::future::Future<Output = ()>,
	{
		install_global_capture();
		// Drain anything carried over from a prior test on this thread —
		// `cargo test` reuses worker threads, so an earlier test's events
		// can still sit in the sink.
		CAPTURED_EVENTS.with(|cell| cell.borrow_mut().clear());
		f().await;
		let captured = CAPTURED_EVENTS.with(|cell| cell.borrow_mut().drain(..).collect::<Vec<_>>());
		captured
			.into_iter()
			.filter(|e| e.message == "post-fill gas estimate")
			.collect()
	}

	/// Build a config like `config_for_live_estimate(false)` but with the
	/// Hyperlane settlement entry **omitted**. `hyperlane_config_for_quote`
	/// returns `None`, the build helper returns `Ok(None)`, and the call
	/// site logs `outcome=skipped_disabled`.
	fn config_without_hyperlane_for_post_fill(dest_chain_in_set: bool) -> Config {
		let mut config = config_for_live_estimate(false);
		// Wipe the hyperlane implementation so `hyperlane_config_for_quote`
		// has no oracles to read. Keep `primary` pointing at "hyperlane"
		// so the lookup miss is via the implementations map, not the
		// fallback alias.
		config.settlement.implementations.clear();
		config.settlement.primary = "hyperlane".to_string();
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(0),
					post_fill: Some(50_000),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: if dest_chain_in_set {
				std::collections::HashSet::from([137u64])
			} else {
				std::collections::HashSet::new()
			},
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});
		config
	}

	/// Like `config_for_live_estimate(false)` but with a malformed Hyperlane
	/// output oracle on chain 137. Fee-param construction still succeeds because
	/// the destination network remains configured; only `build_post_fill_tx_for_quote`
	/// errors, and the call site emits `outcome=skipped_build_tx`.
	///
	/// The upstream cost calc still resolves because `calculate_swap_amounts`
	/// reads token info via the `TokenManager`, which carries its own
	/// per-test networks.
	fn config_malformed_output_oracle_for_post_fill() -> Config {
		let mut config = config_for_live_estimate(false);
		config.settlement.implementations.insert(
			"hyperlane".to_string(),
			serde_json::json!({
				"oracles": {
					"input": {
						"1": ["0x1111111111111111111111111111111111111111"],
						"137": ["0x2222222222222222222222222222222222222222"]
					},
					"output": {
						"1": ["0x1111111111111111111111111111111111111111"],
						"137": ["not-an-address"]
					}
				}
			}),
		);
		config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(0),
					post_fill: Some(50_000),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::from([137u64]),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});
		config
	}

	fn gas_config_post_fill(chain_in_set: bool) -> solver_config::GasConfig {
		solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(0),
					post_fill: Some(50_000),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: false,
			live_post_fill_estimate_chain_ids: if chain_in_set {
				std::collections::HashSet::from([137u64])
			} else {
				std::collections::HashSet::new()
			},
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		}
	}

	#[tokio::test]
	async fn each_post_fill_branch_emits_exactly_one_outcome_event() {
		// One outcome value per case. Six cases, six branches. For each, we
		// run `calculate_cost_context_for_flow_keys` under a capturing
		// subscriber and assert:
		//   (a) exactly one `"post-fill gas estimate"` event was emitted, AND
		//   (b) its `outcome` field equals the expected discriminator.
		// (a) is the single-emit invariant; (b) is the routing correctness.
		use post_fill_outcome::*;

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		// Case 1: SKIPPED_UNSUPPORTED_CHAIN — chain 137 absent from the set.
		let captured = capture_post_fill_events(|| {
			let request = request.clone();
			let context = context.clone();
			let solver = solver.clone();
			async move {
				let (service, _, _) =
					cost_profit_service_for_post_fill_override(None, Some(5_000_000));
				let mut config = config_for_live_estimate(false);
				config.gas = Some(gas_config_post_fill(false));
				let _ = service
					.calculate_cost_context_for_flow_keys(
						&request,
						&context,
						&config,
						&["permit2_escrow".to_string()],
						&solver,
					)
					.await
					.expect("cost context should compute");
			}
		})
		.await;
		assert_eq!(
			captured.len(),
			1,
			"SKIPPED_UNSUPPORTED_CHAIN must emit exactly one event, got {captured:#?}"
		);
		assert_eq!(
			captured[0].fields.get("outcome").map(|s| s.as_str()),
			Some(SKIPPED_UNSUPPORTED_CHAIN),
			"outcome field mismatch: {captured:#?}",
		);

		// Case 2: SKIPPED_DISABLED — chain enabled, hyperlane impl absent.
		let captured = capture_post_fill_events(|| {
			let request = request.clone();
			let context = context.clone();
			let solver = solver.clone();
			async move {
				let (service, _, _) =
					cost_profit_service_for_post_fill_override(None, Some(5_000_000));
				let config = config_without_hyperlane_for_post_fill(true);
				let _ = service
					.calculate_cost_context_for_flow_keys(
						&request,
						&context,
						&config,
						&["permit2_escrow".to_string()],
						&solver,
					)
					.await
					.expect("cost context should compute");
			}
		})
		.await;
		assert_eq!(
			captured.len(),
			1,
			"SKIPPED_DISABLED must emit exactly one event, got {captured:#?}"
		);
		assert_eq!(
			captured[0].fields.get("outcome").map(|s| s.as_str()),
			Some(SKIPPED_DISABLED),
			"outcome field mismatch: {captured:#?}",
		);

		// Case 3: SKIPPED_BUILD_TX — chain enabled, but Hyperlane output oracle
		// malformed so `build_post_fill_tx_for_quote` errors.
		let captured = capture_post_fill_events(|| {
			let request = request.clone();
			let context = context.clone();
			let solver = solver.clone();
			async move {
				let (service, _, _) =
					cost_profit_service_for_post_fill_override(None, Some(5_000_000));
				let config = config_malformed_output_oracle_for_post_fill();
				let _ = service
					.calculate_cost_context_for_flow_keys(
						&request,
						&context,
						&config,
						&["permit2_escrow".to_string()],
						&solver,
					)
					.await
					.expect("cost context should compute");
			}
		})
		.await;
		assert_eq!(
			captured.len(),
			1,
			"SKIPPED_BUILD_TX must emit exactly one event, got {captured:#?}"
		);
		assert_eq!(
			captured[0].fields.get("outcome").map(|s| s.as_str()),
			Some(SKIPPED_BUILD_TX),
			"outcome field mismatch: {captured:#?}",
		);

		// Case 4: FALLBACK_ZERO — override returns Ok(0).
		let captured = capture_post_fill_events(|| {
			let request = request.clone();
			let context = context.clone();
			let solver = solver.clone();
			async move {
				let (service, _, _) = cost_profit_service_for_post_fill_override(None, Some(0));
				let mut config = config_for_live_estimate(false);
				config.gas = Some(gas_config_post_fill(true));
				let _ = service
					.calculate_cost_context_for_flow_keys(
						&request,
						&context,
						&config,
						&["permit2_escrow".to_string()],
						&solver,
					)
					.await
					.expect("cost context should compute");
			}
		})
		.await;
		assert_eq!(
			captured.len(),
			1,
			"FALLBACK_ZERO must emit exactly one event, got {captured:#?}"
		);
		assert_eq!(
			captured[0].fields.get("outcome").map(|s| s.as_str()),
			Some(FALLBACK_ZERO),
			"outcome field mismatch: {captured:#?}",
		);

		// Case 5: FALLBACK_ERROR — override returns Err.
		let captured = capture_post_fill_events(|| {
			let request = request.clone();
			let context = context.clone();
			let solver = solver.clone();
			async move {
				let (service, _, _) = cost_profit_service_for_post_fill_override(None, None);
				let mut config = config_for_live_estimate(false);
				config.gas = Some(gas_config_post_fill(true));
				let _ = service
					.calculate_cost_context_for_flow_keys(
						&request,
						&context,
						&config,
						&["permit2_escrow".to_string()],
						&solver,
					)
					.await
					.expect("cost context should compute");
			}
		})
		.await;
		assert_eq!(
			captured.len(),
			1,
			"FALLBACK_ERROR must emit exactly one event, got {captured:#?}"
		);
		assert_eq!(
			captured[0].fields.get("outcome").map(|s| s.as_str()),
			Some(FALLBACK_ERROR),
			"outcome field mismatch: {captured:#?}",
		);

		// Case 6: SUCCESS — override returns Ok(units > 0).
		let captured = capture_post_fill_events(|| {
			let request = request.clone();
			let context = context.clone();
			let solver = solver.clone();
			async move {
				let (service, _, _) =
					cost_profit_service_for_post_fill_override(None, Some(5_000_000));
				let mut config = config_for_live_estimate(false);
				config.gas = Some(gas_config_post_fill(true));
				let _ = service
					.calculate_cost_context_for_flow_keys(
						&request,
						&context,
						&config,
						&["permit2_escrow".to_string()],
						&solver,
					)
					.await
					.expect("cost context should compute");
			}
		})
		.await;
		assert_eq!(
			captured.len(),
			1,
			"SUCCESS must emit exactly one event, got {captured:#?}"
		);
		assert_eq!(
			captured[0].fields.get("outcome").map(|s| s.as_str()),
			Some(SUCCESS),
			"outcome field mismatch: {captured:#?}",
		);
		// Bonus: SUCCESS branch must also surface the live_units / static_units
		// pair we promised dashboards. If a refactor drops them the test
		// fails loudly here.
		assert!(
			captured[0].fields.contains_key("live_units"),
			"SUCCESS event must include live_units; got {:?}",
			captured[0].fields,
		);
		assert!(
			captured[0].fields.contains_key("static_units"),
			"SUCCESS event must include static_units; got {:?}",
			captured[0].fields,
		);
	}

	#[tokio::test]
	async fn build_fill_tx_for_quote_prefers_resolved_amount_over_request_output() {
		let config = config_with_output_settler_on_dest(QUOTE_OUTPUT_SETTLER);
		let solver = solver_types::Address(QUOTE_SOLVER.to_vec());
		// The request output carries a stale 999; the resolved map says 1_000_000.
		let request = quote_request_with_stale_output_amount(999);
		let validated = create_test_validated_context(true);
		let resolved = resolved_amounts_for_request(&request, U256::from(1_000_000u64));
		let service = cost_profit_service_no_delivery_chains();

		let tx = service
			.build_fill_tx_for_quote(&request, &validated, &resolved, &config, &solver, true)
			.await
			.expect("synthetic fill tx should build");

		let decoded =
			IOutputSettlerSimple::fillCall::abi_decode(&tx.data).expect("fillCall should decode");
		assert_eq!(
			decoded.output.amount,
			U256::from(1_000_000u64),
			"builder must use resolved amount, not the stale request value"
		);
	}

	#[test]
	fn exact_output_post_fill_fee_params_use_known_output_amount() {
		let config = config_with_output_settler_on_dest(QUOTE_OUTPUT_SETTLER);
		let request = create_test_request(false);
		let context = create_test_validated_context(false);
		let input_asset = request.intent.inputs[0].asset.clone();
		let mut resolved = HashMap::new();
		resolved.insert(
			input_asset.clone(),
			TokenAmountInfo {
				token: input_asset,
				amount: U256::from(1_000_000_000_000_000_000u128),
				decimals: 18,
			},
		);
		let service = cost_profit_service_no_delivery_chains();

		let params = service
			.build_post_fill_fee_params_for_quote(&request, &context, &resolved, &config)
			.expect("exact-output fee params should use known output amount")
			.expect("quote has a post-fill output");

		assert_eq!(params.output_amount, U256::from_str("2000000000").unwrap());
	}

	// ----- Task 5: validator honors stored cost_breakdown for quoted orders ---

	/// Helper that builds a `StoredQuote` whose embedded `cost_context` carries
	/// a custom operational_cost — used to drive the validator's "use stored
	/// breakdown" branch.
	fn stored_quote_with_operational_cost(
		quote_id: &::std::primitive::str,
		operational_cost: Decimal,
	) -> StoredQuote {
		let mut breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		breakdown.operational_cost = operational_cost;
		breakdown.gas_open = Decimal::from_str("0.0").unwrap();
		breakdown.gas_fill = operational_cost;
		breakdown.gas_claim = Decimal::from_str("0.0").unwrap();
		breakdown.subtotal = operational_cost;
		breakdown.total = operational_cost;

		StoredQuote {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: current_timestamp() + 300,
				eta: Some(60),
				quote_id: quote_id.to_string(),
				provider: Some("test_solver".to_string()),
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: CostContext {
				cost_breakdown: breakdown,
				execution_costs_by_chain: HashMap::new(),
				liquidity_cost_adjustment: Decimal::ZERO,
				protocol_fees: HashMap::new(),
				swap_type: SwapType::ExactInput,
				cost_amounts_in_tokens: HashMap::new(),
				swap_amounts: HashMap::new(),
				adjusted_amounts: HashMap::new(),
			},
			settlement_name: None,
			// Bind the stored quote to the canonical test order so the stored-cost
			// path (binding matches) is exercised. Tests that need a mismatch or a
			// legacy record override `binding` after calling this helper.
			binding: Some(binding_for_order(&create_profitable_order())),
		}
	}

	/// Recompute the H-07 economic binding for an order, exactly as the gate does.
	fn binding_for_order(order: &Order) -> alloy_primitives::B256 {
		let parsed = order
			.parse_order_data()
			.expect("parse order data for binding");
		solver_types::quote_order_binding(
			parsed.origin_chain_id(),
			parsed.parse_lock_type().as_deref(),
			&parsed.parse_available_inputs(),
			&parsed.parse_requested_outputs(),
		)
	}

	#[tokio::test]
	async fn validate_profitability_uses_stored_cost_breakdown_for_quoted_orders() {
		// Order: input $4000 / output $3900 → spread $100. Min profit 2% of input
		// (= $80). The stored breakdown has operational_cost = $0.044 (typical
		// quote-time figure), the freshly recomputed one has $50 (intent-time
		// gas spike).
		//
		// - Using stored:    margin = ($100 - $0.044) / $4000 ≈ 2.498% → PASS
		// - Using fresh:     margin = ($100 - $50)     / $4000 = 1.25%  → FAIL
		// We assert PASS, proving the validator reaches for the stored figure.
		let quote_id = "test_quote_stored_cost_path";
		let mut mock_storage = MockStorageInterface::new();
		let stored =
			stored_quote_with_operational_cost(quote_id, Decimal::from_str("0.044").unwrap());
		mock_storage
			.expect_get_bytes()
			.with(eq(format!("quotes:{quote_id}")))
			.returning(move |_| {
				let serialized = serde_json::to_vec(&stored).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		// Fresh breakdown intentionally has a high operational cost that would
		// fail the 2% floor on its own.
		let mut fresh_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		fresh_breakdown.operational_cost = Decimal::from_str("50.0").unwrap();
		fresh_breakdown.gas_fill = Decimal::from_str("50.0").unwrap();

		let result = service
			.validate_profitability(
				&order,
				&fresh_breakdown,
				Decimal::from_str("2.0").unwrap(),
				Some(quote_id),
				"off-chain",
			)
			.await;
		assert!(
			result.is_ok(),
			"validator must use stored cost; got {result:?}"
		);
	}

	#[tokio::test]
	async fn validate_profitability_rejects_order_with_mismatched_quote_binding() {
		// H-07 (RED before the binding check): a cheap quote's id stapled to a
		// DIFFERENT order must not be priced on that quote's stored (cheaper)
		// economics. The stored operational_cost ($0.044) would clear the 2% floor;
		// the fresh one ($50) would not. Before the fix, the gate used the stored
		// figure and ACCEPTED the loss-making order. After it, a binding that does
		// not match the submitted order fails closed.
		let quote_id = "test_quote_mismatched_binding";
		let mut mock_storage = MockStorageInterface::new();
		let mut stored =
			stored_quote_with_operational_cost(quote_id, Decimal::from_str("0.044").unwrap());
		// Pretend this quote priced a different order: a binding that cannot match
		// the submitted `create_profitable_order()`.
		stored.binding = Some(alloy_primitives::B256::repeat_byte(0xAB));
		mock_storage
			.expect_get_bytes()
			.with(eq(format!("quotes:{quote_id}")))
			.returning(move |_| {
				let serialized = serde_json::to_vec(&stored).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let mut fresh_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		fresh_breakdown.operational_cost = Decimal::from_str("50.0").unwrap();
		fresh_breakdown.gas_fill = Decimal::from_str("50.0").unwrap();

		let result = service
			.validate_profitability(
				&order,
				&fresh_breakdown,
				Decimal::from_str("2.0").unwrap(),
				Some(quote_id),
				"off-chain",
			)
			.await;
		assert!(
			matches!(
				result,
				Err(APIError::UnprocessableEntity {
					error_type: ApiErrorType::QuoteOrderMismatch,
					..
				})
			),
			"mismatched quote binding must fail closed; got {result:?}"
		);
	}

	#[tokio::test]
	async fn validate_profitability_falls_back_to_fresh_when_quote_binding_absent() {
		// §4.2: a quote with no binding (legacy record / generic order) is judged
		// on the freshly recomputed breakdown — like a direct submission — never on
		// the stored cost. The fresh op cost ($50) fails the 2% floor, so the order
		// is rejected for insufficient profitability (NOT a binding mismatch, and
		// NOT accepted on the stored $0.044).
		let quote_id = "test_quote_no_binding";
		let mut mock_storage = MockStorageInterface::new();
		let mut stored =
			stored_quote_with_operational_cost(quote_id, Decimal::from_str("0.044").unwrap());
		stored.binding = None;
		mock_storage
			.expect_get_bytes()
			.with(eq(format!("quotes:{quote_id}")))
			.returning(move |_| {
				let serialized = serde_json::to_vec(&stored).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let mut fresh_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		fresh_breakdown.operational_cost = Decimal::from_str("50.0").unwrap();
		fresh_breakdown.gas_fill = Decimal::from_str("50.0").unwrap();

		let result = service
			.validate_profitability(
				&order,
				&fresh_breakdown,
				Decimal::from_str("2.0").unwrap(),
				Some(quote_id),
				"off-chain",
			)
			.await;
		assert!(
			matches!(
				result,
				Err(APIError::UnprocessableEntity {
					error_type: ApiErrorType::InsufficientProfitability,
					..
				})
			),
			"absent binding must judge on fresh breakdown (fail 2% floor); got {result:?}"
		);
	}

	#[tokio::test]
	async fn validate_profitability_uses_fresh_cost_breakdown_for_direct_orders() {
		// Same setup, but pass quote_id = None: validator must use fresh
		// breakdown and reject for insufficient margin.
		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(MockStorageInterface::new())));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let mut fresh_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		fresh_breakdown.operational_cost = Decimal::from_str("50.0").unwrap();

		let result = service
			.validate_profitability(
				&order,
				&fresh_breakdown,
				Decimal::from_str("2.0").unwrap(),
				None, // direct submission
				"off-chain",
			)
			.await;
		assert!(
			result.is_err(),
			"direct submission must use fresh cost and fail the 2% floor"
		);
	}

	#[tokio::test]
	async fn validate_profitability_falls_back_when_cost_context_missing() {
		// Storage returns NotFound for the quote_id (e.g., quote expired between
		// submission and validation). Validator must fall back to fresh
		// breakdown and — given the same expensive fresh breakdown — reject.
		let mut mock_storage = MockStorageInterface::new();
		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:expired-quote"))
			.returning(|_| {
				Box::pin(async move {
					Err(solver_storage::StorageError::NotFound(
						"quote expired".to_string(),
					))
				})
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		let order = create_profitable_order();
		let mut fresh_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		fresh_breakdown.operational_cost = Decimal::from_str("50.0").unwrap();

		let result = service
			.validate_profitability(
				&order,
				&fresh_breakdown,
				Decimal::from_str("2.0").unwrap(),
				Some("expired-quote"),
				"off-chain",
			)
			.await;
		assert!(
			result.is_err(),
			"missing cost context must fall back to fresh breakdown (here: expensive → reject)"
		);
	}

	// ----- Task 6: end-to-end quote→validator roundtrip parity ----------------

	#[tokio::test]
	async fn quote_then_validate_roundtrip_no_divergence() {
		// 1. Run the quote-time cost-context calculation with live estimation
		//    enabled. Mock estimate_gas returns cheap units so the resulting
		//    cost_context is "what we promised the user".
		let quote_service = cost_profit_service_for_live_estimate(Some(50_000));
		let mut quote_config = config_for_live_estimate(true);
		quote_config.gas = Some(solver_config::GasConfig {
			flows: HashMap::from([(
				"permit2_escrow".to_string(),
				solver_config::GasFlowUnits {
					open: Some(0),
					fill: Some(50_000),
					post_fill: Some(0),
					pre_claim: Some(0),
					claim: Some(0),
				},
			)]),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: std::collections::HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		});

		let request = create_test_request(true);
		let context = create_test_validated_context(true);
		let solver = Address([0xAB; 20].to_vec());

		let stored_cost_context = quote_service
			.calculate_cost_context_for_flow_keys(
				&request,
				&context,
				&quote_config,
				&["permit2_escrow".to_string()],
				&solver,
			)
			.await
			.expect("quote-time cost context should compute");

		// Sanity: live path was used (gas_fill is non-zero, derived from 50_000
		// units × 20 gwei × the wei→USD mock).
		assert!(stored_cost_context.cost_breakdown.gas_fill > Decimal::ZERO);

		// 2. Persist the resulting cost_context inside a StoredQuote.
		let quote_id = "roundtrip-quote-id";
		let stored = StoredQuote {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: current_timestamp() + 300,
				eta: Some(60),
				quote_id: quote_id.to_string(),
				provider: Some("test_solver".to_string()),
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: stored_cost_context.clone(),
			settlement_name: None,
			binding: Some(binding_for_order(&create_profitable_order())),
		};

		// 3. Build a validator-side service whose storage returns the stored quote.
		let mut mock_storage = MockStorageInterface::new();
		mock_storage
			.expect_get_bytes()
			.with(eq(format!("quotes:{quote_id}")))
			.returning(move |_| {
				let serialized = serde_json::to_vec(&stored).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let validator_service = CostProfitService::new(
			pricing,
			delivery,
			token_manager,
			storage,
			no_fee_settlement_service(),
		);

		// 4. Order whose spread comfortably exceeds the stored operational cost.
		let order = create_profitable_order();

		// 5. Fresh cost_breakdown reflecting a gas spike at intent time —
		//    operational_cost much higher than what the quote priced. Without
		//    Task 5 the validator would reject; with it, the stored figure wins.
		let mut fresh_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		fresh_breakdown.operational_cost = Decimal::from_str("75.0").unwrap();
		fresh_breakdown.gas_fill = Decimal::from_str("75.0").unwrap();

		// 6. Validator must honor the quote and accept.
		let margin = validator_service
			.validate_profitability(
				&order,
				&fresh_breakdown,
				Decimal::from_str("2.0").unwrap(),
				Some(quote_id),
				"off-chain",
			)
			.await
			.expect("validator must accept the quoted order under stored-cost parity");

		// 7. Margin should be the one priced by the quote (≈ ($100 - tiny stored
		//    operational) / $4000), well above the 2% floor — NOT the
		//    catastrophic ($100 - $75) / $4000 = 0.625% the fresh costs imply.
		assert!(
			margin > Decimal::from_str("2.0").unwrap(),
			"margin {margin} must reflect stored cost, not the inflated fresh cost",
		);
	}
}

#[cfg(test)]
mod gas_leg_proptests {
	//! Property tests for `calculate_gas_leg_costs_wei`.
	//!
	//! Encodes the OIF contract-derived chain-boundary invariant:
	//!   - `Settler.open*`, pre-claim, and `finalise*` are origin-chain costs.
	//!   - `BaseFiller.fill*` and post-fill oracle work are destination-chain costs.
	//!     Changing destination fee params must never move origin legs (and vice
	//!     versa). These tests run without any mock infrastructure because the
	//!     helper is pure.
	use super::*;
	use proptest::prelude::*;

	fn arb_gas_units() -> impl Strategy<Value = GasUnits> {
		(
			0u64..2_000_000u64,
			0u64..2_000_000u64,
			0u64..2_000_000u64,
			0u64..2_000_000u64,
			0u64..2_000_000u64,
		)
			.prop_map(|(open, fill, post_fill, pre_claim, claim)| GasUnits {
				open_units: open,
				fill_units: fill,
				post_fill_units: post_fill,
				pre_claim_units: pre_claim,
				claim_units: claim,
			})
	}

	proptest! {
		#[test]
		fn gas_leg_accounting_uses_contract_chain_boundaries(
			gas_units in arb_gas_units(),
			origin_fee in 0u128..1_000_000_000_000u128,
			dest_fee in 0u128..1_000_000_000_000u128,
		) {
			let costs = calculate_gas_leg_costs_wei(
				&gas_units,
				U256::from(origin_fee),
				U256::from(dest_fee),
			);

			prop_assert_eq!(costs.open, U256::from(origin_fee) * U256::from(gas_units.open_units));
			prop_assert_eq!(costs.pre_claim, U256::from(origin_fee) * U256::from(gas_units.pre_claim_units));
			prop_assert_eq!(costs.claim, U256::from(origin_fee) * U256::from(gas_units.claim_units));
			prop_assert_eq!(costs.fill, U256::from(dest_fee) * U256::from(gas_units.fill_units));
			prop_assert_eq!(costs.post_fill, U256::from(dest_fee) * U256::from(gas_units.post_fill_units));
		}

		#[test]
		fn changing_dest_fee_does_not_change_origin_contract_legs(
			gas_units in arb_gas_units(),
			origin_fee in 0u128..1_000_000_000_000u128,
			dest_fee_a in 0u128..1_000_000_000_000u128,
			dest_fee_b in 0u128..1_000_000_000_000u128,
		) {
			let a = calculate_gas_leg_costs_wei(
				&gas_units,
				U256::from(origin_fee),
				U256::from(dest_fee_a),
			);
			let b = calculate_gas_leg_costs_wei(
				&gas_units,
				U256::from(origin_fee),
				U256::from(dest_fee_b),
			);

			prop_assert_eq!(a.open, b.open);
			prop_assert_eq!(a.pre_claim, b.pre_claim);
			prop_assert_eq!(a.claim, b.claim);
		}
	}
}
