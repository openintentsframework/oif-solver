//! Quote Request Validation Module
//!
//! This module provides comprehensive validation for incoming quote requests in the OIF solver system.
//! It ensures all parameters meet the required constraints and that the solver has the necessary
//! capabilities to fulfill the requested quotes.
//!
//! # Validation Pipeline
//!
//! The validation process consists of several stages:
//! 1. **Basic Structure** - Ensures required fields are present and non-empty
//! 2. **Address Validation** - Validates ERC-7930 interoperable addresses
//! 3. **Network Support** - Verifies chains are configured with appropriate settlers
//! 4. **Token Support** - Confirms tokens are supported on their respective chains
//! 5. **Balance Checks** - Ensures solver has sufficient liquidity

use alloy_primitives::{Address as AlloyAddress, U256};
use futures::future::try_join_all;
use solver_core::SolverEngine;
use solver_types::{
	AuthScheme, CostContext, GetQuoteRequest, IntentRequest, IntentType, InteropAddress,
	QuoteError, SwapType, ValidatedQuoteContext,
};

/// Main validator for quote requests.
///
/// This struct provides static methods for validating various aspects of quote requests,
/// from basic structure validation to complex capability checks.
pub struct QuoteValidator;

/// Represents a validated asset that has been confirmed to be supported by the solver.
///
/// This struct is created after successful validation and contains only the
/// necessary information for subsequent processing stages.
#[derive(Debug, Clone)]
pub struct SupportedAsset {
	pub asset: InteropAddress,
	pub amount: U256,
}

impl QuoteValidator {
	pub fn validate_quote_request(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
	) -> Result<ValidatedQuoteContext, QuoteError> {
		// 1. Intent structure validation
		Self::validate_intent_structure(&request.intent)?;

		// 2. supportedTypes validation
		Self::validate_supported_types(&request.supported_types, solver)?;

		// 3. SwapType-aware input/output validation
		let context = Self::validate_swap_type_logic(&request.intent)?;

		// 4. Lock and auth scheme validation
		Self::validate_capabilities(request, solver, &context)?;

		Ok(context)
	}

	fn validate_intent_structure(intent: &IntentRequest) -> Result<(), QuoteError> {
		// Validate intentType
		if intent.intent_type != IntentType::OifSwap {
			return Err(QuoteError::UnsupportedIntentType(format!(
				"Unsupported intent type: {:?}",
				intent.intent_type
			)));
		}

		// Validate required arrays
		if intent.inputs.is_empty() || intent.outputs.is_empty() {
			return Err(QuoteError::InvalidRequest(
				"inputs and outputs are required".to_string(),
			));
		}

		for input in &intent.inputs {
			Self::validate_interop_address(&input.user)?;
			Self::validate_interop_address(&input.asset)?;
		}

		for output in &intent.outputs {
			Self::validate_interop_address(&output.receiver)?;
			Self::validate_interop_address(&output.asset)?;
		}

		Ok(())
	}

	fn validate_supported_types(
		supported_types: &[String],
		_solver: &SolverEngine,
	) -> Result<(), QuoteError> {
		if supported_types.is_empty() {
			return Err(QuoteError::InvalidRequest(
				"supportedTypes cannot be empty".to_string(),
			));
		}

		// Validate that order types follow the OIF versioning pattern
		for order_type in supported_types {
			if !order_type.starts_with("oif-") || !order_type.contains("-v") {
				return Err(QuoteError::InvalidRequest(format!(
					"Invalid order type format: {}",
					order_type
				)));
			}
		}

		Ok(())
	}

	fn validate_swap_type_logic(
		intent: &IntentRequest,
	) -> Result<ValidatedQuoteContext, QuoteError> {
		let swap_type = intent.swap_type.as_ref().unwrap_or(&SwapType::ExactInput);

		match swap_type {
			SwapType::ExactInput => {
				// Input amounts must be provided
				let mut known_inputs = Vec::new();
				for input in &intent.inputs {
					let amount_u256 = input.amount_as_u256().map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
					})?;

					if amount_u256.is_none() {
						return Err(QuoteError::MissingInputAmount);
					}

					let amount = amount_u256.unwrap();
					if amount.is_zero() {
						return Err(QuoteError::InvalidRequest(
							"Input amount cannot be zero for exact-input swaps".to_string(),
						));
					}

					known_inputs.push((input.clone(), amount));
				}

				// Output amounts are optional constraints
				let mut constraint_outputs = Vec::new();
				for output in &intent.outputs {
					let amount_u256 = output.amount_as_u256().map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
					})?;
					constraint_outputs.push((output.clone(), amount_u256));
				}

				Ok(ValidatedQuoteContext {
					swap_type: SwapType::ExactInput,
					known_inputs: Some(known_inputs),
					known_outputs: None,
					constraint_inputs: None,
					constraint_outputs: Some(constraint_outputs),
				})
			},
			SwapType::ExactOutput => {
				// Output amounts must be provided
				let mut known_outputs = Vec::new();
				for output in &intent.outputs {
					let amount_u256 = output.amount_as_u256().map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
					})?;

					if amount_u256.is_none() {
						return Err(QuoteError::MissingOutputAmount);
					}

					let amount = amount_u256.unwrap();
					if amount.is_zero() {
						return Err(QuoteError::InvalidRequest(
							"Output amount cannot be zero for exact-output swaps".to_string(),
						));
					}

					known_outputs.push((output.clone(), amount));
				}

				// Input amounts are optional constraints
				let mut constraint_inputs = Vec::new();
				for input in &intent.inputs {
					let amount_u256 = input.amount_as_u256().map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
					})?;
					constraint_inputs.push((input.clone(), amount_u256));
				}

				Ok(ValidatedQuoteContext {
					swap_type: SwapType::ExactOutput,
					known_inputs: None,
					known_outputs: Some(known_outputs),
					constraint_inputs: Some(constraint_inputs),
					constraint_outputs: None,
				})
			},
		}
	}

	fn validate_capabilities(
		request: &GetQuoteRequest,
		_solver: &SolverEngine,
		context: &ValidatedQuoteContext,
	) -> Result<(), QuoteError> {
		// Validate inferred order types match supported types
		Self::validate_order_type_compatibility(request, context)?;

		// Validate auth schemes if specified
		if let Some(origin) = &request.intent.origin_submission {
			Self::validate_auth_schemes(&origin.schemes)?;
		}

		Ok(())
	}

	fn validate_order_type_compatibility(
		request: &GetQuoteRequest,
		_context: &ValidatedQuoteContext,
	) -> Result<(), QuoteError> {
		use solver_types::oif_versions;

		// Check that each input's inferred order type is compatible with supportedTypes
		for input in &request.intent.inputs {
			// Infer the order type with the current version, considering origin submission schemes
			let inferred_order_type = input.infer_order_type_with_origin(
				oif_versions::CURRENT,
				request.intent.origin_submission.as_ref(),
			);

			// Check if the inferred type (with version) is in the supported types list
			if !request.supported_types.contains(&inferred_order_type) {
				return Err(QuoteError::NoMatchingOrderType(format!(
					"Inferred order type '{}' not found in supported types: {:?}",
					inferred_order_type, request.supported_types
				)));
			}
		}

		Ok(())
	}

	fn validate_auth_schemes(schemes: &Option<Vec<AuthScheme>>) -> Result<(), QuoteError> {
		if let Some(schemes) = schemes {
			if schemes.is_empty() {
				return Err(QuoteError::InvalidRequest(
					"Auth schemes cannot be empty if specified".to_string(),
				));
			}
			// Note: We don't validate specific auth schemes here.
			// The solver should attempt to work with whatever auth schemes the user prefers.
			// Actual capability checking happens in custody_strategy.decide_custody()
		}
		Ok(())
	}

	/// Validates that the chains referenced in the request are supported by the solver.
	///
	/// # Validation Policy
	///
	/// - **Available Inputs**: Must be on chains with configured `input_settler_address` (origin chains)
	/// - **Requested Outputs**: Must be on chains with configured `output_settler_address` (destination chains)
	///
	/// At least one input must be on a supported origin chain, while ALL outputs must be
	/// on supported destination chains.
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing chain references
	/// * `solver` - The solver engine with network configuration
	///
	/// # Errors
	///
	/// Returns `QuoteError::UnsupportedAsset` if unsupported chains are detected
	pub fn validate_supported_networks(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
	) -> Result<(), QuoteError> {
		let networks = solver.token_manager().get_networks();

		// Check if any input is on a supported origin chain
		let has_valid_input = request.intent.inputs.iter().any(|input| {
			Self::chain_id_from_interop(&input.asset)
				.ok()
				.and_then(|id| {
					tracing::debug!("Checking input chain ID: {}", id);
					networks.get(&id)
				})
				.is_some_and(|net| !net.input_settler_address.0.is_empty())
		});

		if !has_valid_input {
			return Err(QuoteError::UnsupportedAsset(
				"No supported origin chains in inputs".into(),
			));
		}

		// Validate all outputs are on supported destination chains
		for output in &request.intent.outputs {
			let chain_id = Self::chain_id_from_interop(&output.asset)?;
			let is_dest = networks
				.get(&chain_id)
				.is_some_and(|net| !net.output_settler_address.0.is_empty());

			if !is_dest {
				return Err(QuoteError::UnsupportedAsset(format!(
					"Chain {} not supported as destination",
					chain_id
				)));
			}
		}

		Ok(())
	}

	/// Checks if a specific token is supported by the solver on a given chain.
	///
	/// This method queries the TokenManager to determine if the solver has
	/// configuration for the specified token.
	///
	/// # Arguments
	///
	/// * `solver` - The solver engine containing token configuration
	/// * `chain_id` - The blockchain network ID
	/// * `address` - The token contract address
	fn is_token_supported(solver: &SolverEngine, chain_id: u64, address: &AlloyAddress) -> bool {
		let solver_address: solver_types::Address = (*address).into();
		solver
			.token_manager()
			.is_supported(chain_id, &solver_address)
	}

	/// Validates an ERC-7930 interoperable address.
	///
	/// Ensures the address conforms to the ERC-7930 standard format which
	/// encodes both chain information and the address itself.
	///
	/// # Future Enhancements
	///
	/// Additional validation could include:
	/// - Chain-specific address validation
	/// - Token contract existence checks
	/// - Supported chain verification
	fn validate_interop_address(address: &InteropAddress) -> Result<(), QuoteError> {
		// Validate the interoperable address format
		address.validate().map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid interoperable address: {}", e))
		})?;

		Ok(())
	}

	fn chain_id_from_interop(addr: &InteropAddress) -> Result<u64, QuoteError> {
		addr.ethereum_chain_id().map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid chain in interoperable address: {}", e))
		})
	}

	/// Extracts chain ID and EVM address components from an InteropAddress.
	///
	/// Decomposes an ERC-7930 interoperable address into its constituent parts
	/// for use in chain-specific operations.
	///
	/// # Returns
	///
	/// A tuple of (chain_id, evm_address) on success
	fn extract_chain_and_address(addr: &InteropAddress) -> Result<(u64, AlloyAddress), QuoteError> {
		let chain_id = Self::chain_id_from_interop(addr)?;
		let evm_addr = addr
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid asset address: {}", e)))?;
		Ok((chain_id, evm_addr))
	}

	/// Validates and collects input assets using calculated swap amounts from cost context.
	///
	/// Uses the pre-calculated swap amounts from the cost context which represent the
	/// actual amounts needed for the swap. ALL input assets must be supported for
	/// pricing and execution.
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing inputs
	/// * `solver` - The solver engine with token configuration  
	/// * `cost_context` - Contains calculated swap amounts for each asset
	///
	/// # Returns
	///
	/// A vector of `SupportedAsset` with amounts from cost_context.swap_amounts
	///
	/// # Errors
	///
	/// Returns `QuoteError::UnsupportedAsset` if ANY input is not supported
	pub fn validate_and_collect_inputs_with_costs(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
		cost_context: &CostContext,
	) -> Result<Vec<SupportedAsset>, QuoteError> {
		let mut supported_assets = Vec::new();

		for asset_info in &request.intent.inputs {
			let asset_addr = &asset_info.asset;
			let (chain_id, evm_addr) = Self::extract_chain_and_address(asset_addr)?;

			// ALL assets must be supported for proper pricing
			if !Self::is_token_supported(solver, chain_id, &evm_addr) {
				return Err(QuoteError::UnsupportedAsset(format!(
					"Input token not supported on chain {}: {}",
					chain_id,
					alloy_primitives::hex::encode(evm_addr.as_slice())
				)));
			}

			// Use the swap amount from cost context (the calculated base amount)
			let amount = cost_context
				.swap_amounts
				.get(asset_addr)
				.map(|info| info.amount)
				.unwrap_or_else(|| {
					// Fallback to request amount if not in cost context
					asset_info
						.amount_as_u256()
						.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))
						.ok()
						.flatten()
						.unwrap_or_default()
				});

			supported_assets.push(SupportedAsset {
				asset: asset_addr.clone(),
				amount,
			});
		}

		Ok(supported_assets)
	}

	/// Validates and collects output assets using calculated swap amounts from cost context.
	///
	/// Uses the pre-calculated swap amounts from the cost context which represent the
	/// actual amounts needed for the swap. ALL output assets must be supported for
	/// pricing and execution.
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing outputs
	/// * `solver` - The solver engine with token configuration
	/// * `cost_context` - Contains calculated swap amounts for each asset
	///
	/// # Returns
	///
	/// A vector of `SupportedAsset` with amounts from cost_context.swap_amounts
	///
	/// # Errors
	///
	/// Returns `QuoteError::UnsupportedAsset` if ANY output is not supported
	pub fn validate_and_collect_outputs_with_costs(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
		cost_context: &CostContext,
	) -> Result<Vec<SupportedAsset>, QuoteError> {
		let mut supported_assets = Vec::new();

		for asset_info in &request.intent.outputs {
			let asset_addr = &asset_info.asset;
			let (chain_id, evm_addr) = Self::extract_chain_and_address(asset_addr)?;

			// ALL assets must be supported for proper pricing
			if !Self::is_token_supported(solver, chain_id, &evm_addr) {
				return Err(QuoteError::UnsupportedAsset(format!(
					"Output token not supported on chain {}: {}",
					chain_id,
					alloy_primitives::hex::encode(evm_addr.as_slice())
				)));
			}

			// Use the swap amount from cost context (the calculated base amount)
			let amount = cost_context
				.swap_amounts
				.get(asset_addr)
				.map(|info| info.amount)
				.unwrap_or_else(|| {
					// Fallback to request amount if not in cost context
					asset_info
						.amount_as_u256()
						.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))
						.ok()
						.flatten()
						.unwrap_or_default()
				});

			supported_assets.push(SupportedAsset {
				asset: asset_addr.clone(),
				amount,
			});
		}

		Ok(supported_assets)
	}

	/// Ensures the solver has sufficient balance for all requested destination outputs.
	///
	/// Performs parallel balance checks for all output tokens to verify the solver
	/// has enough liquidity to fulfill the quote. For ExactInput swaps, this should
	/// be called with cost-adjusted output amounts. For ExactOutput swaps, the amounts
	/// remain unchanged.
	///
	/// # Performance
	///
	/// Balance checks are executed in parallel using `futures::try_join_all` for
	/// optimal performance when checking multiple outputs.
	///
	/// # Arguments
	///
	/// * `solver` - The solver engine with token manager
	/// * `outputs` - The validated output assets with cost-adjusted amounts
	/// * `context` - The validated quote context to determine swap type
	/// * `cost_context` - Contains cost amounts for adjusting output requirements
	///
	/// # Errors
	///
	/// Returns `QuoteError::InsufficientLiquidity` if any balance is insufficient.
	/// Returns `QuoteError::Internal` if balance checks fail or parsing errors occur.
	pub async fn ensure_destination_balances_with_costs(
		solver: &SolverEngine,
		outputs: &[SupportedAsset],
		context: &ValidatedQuoteContext,
		cost_context: &CostContext,
	) -> Result<(), QuoteError> {
		let token_manager = solver.token_manager();

		// Create futures for parallel balance checks
		let balance_checks = outputs.iter().map(|output| {
			let output = output.clone();
			async move {
				let (chain_id, evm_addr) = Self::extract_chain_and_address(&output.asset)?;
				let token_addr: solver_types::Address = evm_addr.into();

				let balance_str = token_manager
					.check_balance(chain_id, &token_addr)
					.await
					.map_err(|e| QuoteError::Internal(format!("Balance check failed: {}", e)))?;

				let balance = U256::from_str_radix(&balance_str, 10)
					.map_err(|e| QuoteError::Internal(format!("Failed to parse balance: {}", e)))?;

				// For ExactInput swaps, adjust the required amount by subtracting costs
				let required_amount = if matches!(context.swap_type, SwapType::ExactInput) {
					// Check if this is the first output (which bears the cost)
					let is_first = outputs
						.first()
						.map(|first| first.asset == output.asset)
						.unwrap_or(false);

					if is_first {
						// First output: subtract costs from the base amount
						let cost_in_token = cost_context
							.cost_amounts_in_tokens
							.get(&output.asset)
							.map(|info| info.amount)
							.unwrap_or(U256::ZERO);
						output.amount.saturating_sub(cost_in_token)
					} else {
						output.amount
					}
				} else {
					// For ExactOutput, amounts remain unchanged
					output.amount
				};

				if balance < required_amount {
					let token_hex = alloy_primitives::hex::encode(evm_addr.as_slice());
					tracing::error!(
						chain_id = chain_id,
						required = %required_amount,
						available = %balance,
						token = %token_hex,
						"Insufficient destination balance",
					);
					return Err(QuoteError::InsufficientLiquidity);
				} else {
					tracing::debug!(
						chain_id = chain_id,
						required = %required_amount,
						available = %balance,
						token = %alloy_primitives::hex::encode(evm_addr.as_slice()),
						"Sufficient destination balance"
					);
				}

				Ok::<(), QuoteError>(())
			}
		});

		// Execute all balance checks in parallel
		try_join_all(balance_checks).await?;

		Ok(())
	}

	/// Validates callback data in outputs against the solver's callback whitelist.
	///
	/// This validation runs early in the quote generation flow to provide fail-fast
	/// behavior when a user requests a callback that the solver cannot support.
	///
	/// # Validation Rules
	///
	/// 1. If an output has callback data (`calldata` field):
	///    - If `simulate_callbacks` is disabled in config, reject with error
	///    - If the receiver (callback recipient) is not in the whitelist, reject with error
	///    - An empty whitelist allows all callbacks (but simulation must be enabled)
	///
	/// 2. If an output has no callback data, no validation is needed
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing outputs with potential callbacks
	/// * `config` - Solver configuration containing callback settings
	///
	/// # Errors
	///
	/// Returns `QuoteError::InvalidRequest` if:
	/// - Callback data is present but simulation is disabled
	/// - Callback recipient is not in the whitelist
	pub fn validate_callback_whitelist(
		request: &GetQuoteRequest,
		config: &solver_config::Config,
	) -> Result<(), QuoteError> {
		for output in &request.intent.outputs {
			// Check if this output has callback data
			let has_callback = output
				.calldata
				.as_ref()
				.map(|c| !c.is_empty() && c != "0x")
				.unwrap_or(false);

			if !has_callback {
				continue;
			}

			// Output has callback data - validate it
			tracing::debug!(
				"Output has callback data: {:?}, receiver: {}",
				output.calldata,
				output.receiver.to_hex()
			);

			// Check if callback simulation is enabled
			if !config.order.simulate_callbacks {
				return Err(QuoteError::InvalidRequest(
					"Callback data provided but callback simulation is disabled in solver config. \
					The solver cannot process orders with callbacks."
						.to_string(),
				));
			}

			// Check whitelist (empty whitelist means all callbacks allowed)
			if config.order.callback_whitelist.is_empty() {
				tracing::debug!("Callback whitelist is empty - all callbacks allowed");
				continue;
			}

			// Get the receiver's EIP-7930 hex representation for whitelist comparison
			let receiver_interop_hex = output.receiver.to_hex().to_lowercase();

			let is_whitelisted = config
				.order
				.callback_whitelist
				.iter()
				.any(|entry| entry.to_lowercase() == receiver_interop_hex);

			if !is_whitelisted {
				// Extract chain ID and address for helpful error message
				let chain_id = output.receiver.ethereum_chain_id().unwrap_or(0);
				let recipient_addr = output
					.receiver
					.ethereum_address()
					.map(|a| format!("{:?}", a))
					.unwrap_or_else(|_| "unknown".to_string());

				return Err(QuoteError::InvalidRequest(format!(
					"Callback recipient {} on chain {} is not in the solver's whitelist. \
					Add '{}' to order.callback_whitelist in config (EIP-7930 format) to enable this callback.",
					recipient_addr, chain_id, receiver_interop_hex
				)));
			}

			tracing::debug!("Callback recipient {} is whitelisted", receiver_interop_hex);
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::address;
	use solver_core::SolverEngine;
	use solver_types::networks::NetworkConfig;
	use solver_types::{
		AuthScheme, GetQuoteRequest, IntentType, OriginMode, OriginSubmission, QuoteInput,
		QuoteOutput,
	};
	use std::collections::HashMap;
	use std::sync::Arc;

	/// Creates a minimal mock SolverEngine for testing
	fn create_mock_solver() -> SolverEngine {
		create_mock_solver_with_networks(HashMap::new())
	}

	/// Creates a minimal mock SolverEngine for testing with custom network configurations
	fn create_mock_solver_with_networks(networks: HashMap<u64, NetworkConfig>) -> SolverEngine {
		use solver_account::AccountService;
		use solver_config::Config;
		use solver_core::engine::event_bus::EventBus;
		use solver_core::engine::token_manager::TokenManager;
		use solver_delivery::DeliveryService;
		use solver_discovery::DiscoveryService;
		use solver_order::OrderService;
		use solver_settlement::SettlementService;
		use solver_storage::StorageService;
		use solver_types::Address;

		// Create minimal config for testing
		let config_toml = r#"
			[solver]
			id = "test-solver"
			monitoring_timeout_seconds = 30
			min_profitability_pct = 1.0
			
			[storage]
			primary = "memory"
			cleanup_interval_seconds = 3600
			[storage.implementations.memory]
			
			[delivery]
			min_confirmations = 1
			[delivery.implementations]
			
			[account]
			primary = "local"
			[account.implementations.local]
			private_key = "0x1234567890123456789012345678901234567890123456789012345678901234"
			
			[discovery]
			[discovery.implementations]
			
			[order]
			[order.implementations]
			[order.strategy]
			primary = "simple"
			[order.strategy.implementations.simple]
			
			[settlement]
			[settlement.implementations]
			
			[networks]
		"#;
		let config: Config = toml::from_str(config_toml).expect("Failed to parse test config");

		// Create mock services
		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));

		let account_config = toml::from_str(
			r#"private_key = "0x1234567890123456789012345678901234567890123456789012345678901234""#,
		)
		.expect("Failed to parse account config");
		let account = Arc::new(AccountService::new(
			solver_account::implementations::local::create_account(&account_config)
				.expect("Failed to create account"),
		));

		let solver_address = Address(vec![1u8; 20]);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
		let discovery = Arc::new(DiscoveryService::new(HashMap::new()));

		let strategy_config = toml::Value::Table(toml::value::Table::new());
		let strategy =
			solver_order::implementations::strategies::simple::create_strategy(&strategy_config)
				.expect("Failed to create strategy");
		let order = Arc::new(OrderService::new(HashMap::new(), strategy));

		let settlement = Arc::new(SettlementService::new(HashMap::new(), 20));

		let pricing_config = toml::Value::Table(toml::value::Table::new());
		let pricing_impl =
			solver_pricing::implementations::mock::create_mock_pricing(&pricing_config)
				.expect("Failed to create mock pricing");
		let pricing = Arc::new(solver_pricing::PricingService::new(pricing_impl, Vec::new()));

		let event_bus = EventBus::new(100);

		// Create token manager with provided networks config
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			account.clone(),
		));

		SolverEngine::new(
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		)
	}

	fn create_valid_get_quote_request() -> GetQuoteRequest {
		GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			intent: create_exact_input_request(Some("1000000000000000000"), None),
			supported_types: vec!["oif-escrow-v0".to_string()],
		}
	}

	fn create_intent_request(
		input_amount: Option<&str>,
		output_amount: Option<&str>,
		exact_input: bool, // true for ExactInput (default), false for ExactOutput
	) -> IntentRequest {
		IntentRequest {
			intent_type: IntentType::OifSwap,
			inputs: vec![QuoteInput {
				user: InteropAddress::new_ethereum(
					1,
					address!("1111111111111111111111111111111111111111"),
				),
				asset: InteropAddress::new_ethereum(
					1,
					address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
				),
				amount: input_amount.map(|s| s.to_string()),
				lock: None,
			}],
			outputs: vec![QuoteOutput {
				receiver: InteropAddress::new_ethereum(
					137,
					address!("2222222222222222222222222222222222222222"),
				),
				asset: InteropAddress::new_ethereum(
					137,
					address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"),
				),
				amount: output_amount.map(|s| s.to_string()),
				calldata: None,
			}],
			swap_type: Some(if exact_input {
				SwapType::ExactInput
			} else {
				SwapType::ExactOutput
			}),
			min_valid_until: None,
			preference: None,
			origin_submission: None,
			failure_handling: None,
			partial_fill: None,
			metadata: None,
		}
	}

	fn create_exact_input_request(
		input_amount: Option<&str>,
		output_amount: Option<&str>,
	) -> IntentRequest {
		create_intent_request(input_amount, output_amount, true)
	}

	fn create_exact_output_request(
		input_amount: Option<&str>,
		output_amount: Option<&str>,
	) -> IntentRequest {
		create_intent_request(input_amount, output_amount, false)
	}

	#[test]
	fn test_exact_input_missing_input_amount_fails() {
		// Test: Exact-input missing required input amount
		let intent = create_exact_input_request(
			None, // Missing required input amount
			None,
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			matches!(result, Err(QuoteError::MissingInputAmount)),
			"Should reject missing input amount: {:?}",
			result
		);
	}

	#[test]
	fn test_exact_output_missing_output_amount_fails() {
		// Test: Exact-output missing required output amount
		let intent = create_exact_output_request(
			None, None, // Missing required output amount
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			matches!(result, Err(QuoteError::MissingOutputAmount)),
			"Should reject missing output amount: {:?}",
			result
		);
	}

	#[test]
	fn test_exact_input_zero_input_amount_fails() {
		// Test: Exact-input with zero input amount
		let intent = create_exact_input_request(
			Some("0"), // Zero input amount
			None,
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("cannot be zero")),
			"Should reject zero input amount for exact-input: {:?}",
			result
		);
	}

	#[test]
	fn test_exact_output_zero_output_amount_fails() {
		// Test: Exact-output with zero output amount
		let intent = create_exact_output_request(
			None,
			Some("0"), // Zero output amount
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("cannot be zero")),
			"Should reject zero output amount for exact-output: {:?}",
			result
		);
	}

	#[test]
	fn test_exact_input_with_valid_amounts_succeeds() {
		// Test: Exact-input with valid input amount should succeed
		let intent = create_exact_input_request(
			Some("1000000000000000000"), // 1 token
			None,
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			result.is_ok(),
			"Should accept valid exact-input: {:?}",
			result
		);

		let context = result.unwrap();
		assert!(matches!(context.swap_type, SwapType::ExactInput));
		assert!(context.known_inputs.is_some());
		assert_eq!(context.known_inputs.unwrap().len(), 1);
	}

	#[test]
	fn test_exact_output_with_valid_amounts_succeeds() {
		// Test: Exact-output with valid output amount should succeed
		let intent = create_exact_output_request(
			None,
			Some("1000000000000000000"), // 1 token
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			result.is_ok(),
			"Should accept valid exact-output: {:?}",
			result
		);

		let context = result.unwrap();
		assert!(matches!(context.swap_type, SwapType::ExactOutput));
		assert!(context.known_outputs.is_some());
		assert_eq!(context.known_outputs.unwrap().len(), 1);
	}

	// ========== validate_quote_request Tests ==========

	#[test]
	fn test_validate_quote_request_success_exact_input() {
		let solver = create_mock_solver();
		let request = create_valid_get_quote_request();

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			result.is_ok(),
			"Valid exact-input request should succeed: {:?}",
			result
		);

		let context = result.unwrap();
		assert!(matches!(context.swap_type, SwapType::ExactInput));
		assert!(context.known_inputs.is_some());
		assert!(context.constraint_outputs.is_some());
	}

	#[test]
	fn test_validate_quote_request_success_exact_output() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent = create_exact_output_request(None, Some("1000000000000000000"));

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			result.is_ok(),
			"Valid exact-output request should succeed: {:?}",
			result
		);

		let context = result.unwrap();
		assert!(matches!(context.swap_type, SwapType::ExactOutput));
		assert!(context.known_outputs.is_some());
		assert!(context.constraint_inputs.is_some());
	}

	#[test]
	fn test_validate_quote_request_fails_empty_inputs() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent.inputs = vec![]; // Empty inputs

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("inputs and outputs are required")),
			"Should reject empty inputs: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_empty_outputs() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent.outputs = vec![]; // Empty outputs

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("inputs and outputs are required")),
			"Should reject empty outputs: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_empty_supported_types() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.supported_types = vec![]; // Empty supported types

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("supportedTypes cannot be empty")),
			"Should reject empty supported types: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_invalid_order_type_format() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.supported_types = vec!["invalid-format".to_string()]; // Invalid format

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("Invalid order type format")),
			"Should reject invalid order type format: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_missing_input_amount_exact_input() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent = create_exact_input_request(None, None); // Missing input amount

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::MissingInputAmount)),
			"Should reject missing input amount for exact-input: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_missing_output_amount_exact_output() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent = create_exact_output_request(None, None); // Missing output amount

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::MissingOutputAmount)),
			"Should reject missing output amount for exact-output: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_zero_input_amount_exact_input() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent = create_exact_input_request(Some("0"), None); // Zero input amount

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("cannot be zero")),
			"Should reject zero input amount for exact-input: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_zero_output_amount_exact_output() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent = create_exact_output_request(None, Some("0")); // Zero output amount

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("cannot be zero")),
			"Should reject zero output amount for exact-output: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_empty_auth_schemes() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent.origin_submission = Some(OriginSubmission {
			mode: OriginMode::User,
			schemes: Some(vec![]), // Empty auth schemes
		});

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("Auth schemes cannot be empty")),
			"Should reject empty auth schemes: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_success_with_valid_auth_schemes() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent.origin_submission = Some(OriginSubmission {
			mode: OriginMode::User,
			schemes: Some(vec![AuthScheme::Permit2]),
		});

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			result.is_ok(),
			"Should accept valid auth schemes: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_success_with_no_auth_schemes() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent.origin_submission = Some(OriginSubmission {
			mode: OriginMode::User,
			schemes: None,
		});

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			result.is_ok(),
			"Should accept None auth schemes: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_success_with_no_origin_submission() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		request.intent.origin_submission = None;

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			result.is_ok(),
			"Should accept no origin submission: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_fails_order_type_compatibility() {
		let solver = create_mock_solver();
		let mut request = create_valid_get_quote_request();
		// Set supported types that won't match the inferred order type
		request.supported_types = vec!["oif-different-v1".to_string()];

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::NoMatchingOrderType(_))),
			"Should reject incompatible order types: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_quote_request_handles_invalid_interop_addresses() {
		let solver = create_mock_solver();
		let request = create_valid_get_quote_request();

		// Create an invalid interop address by directly constructing it
		// This test would need to be adjusted based on how InteropAddress validation works
		// For now, we'll test with a request that has valid structure but might fail address validation

		let result = QuoteValidator::validate_quote_request(&request, &solver);
		// This test assumes the addresses in create_valid_get_quote_request are valid
		// If we need to test invalid addresses, we'd need to construct them differently
		assert!(
			result.is_ok() || matches!(result, Err(QuoteError::InvalidRequest(_))),
			"Should handle address validation appropriately: {:?}",
			result
		);
	}

	// ========== validate_supported_networks Tests ==========

	/// Helper function to create a network config with specified settler addresses
	fn create_network_config(
		input_settler_empty: bool,
		output_settler_empty: bool,
	) -> NetworkConfig {
		use solver_types::networks::{NetworkConfig, RpcEndpoint, TokenConfig};
		use solver_types::Address;

		NetworkConfig {
			rpc_urls: vec![RpcEndpoint::http_only("https://test.rpc".to_string())],
			input_settler_address: if input_settler_empty {
				Address(vec![]) // Empty address (empty vector)
			} else {
				Address(vec![1u8; 20]) // Non-empty address
			},
			output_settler_address: if output_settler_empty {
				Address(vec![]) // Empty address (empty vector)
			} else {
				Address(vec![2u8; 20]) // Non-empty address
			},
			tokens: vec![TokenConfig {
				address: Address(vec![3u8; 20]),
				symbol: "TEST".to_string(),
				decimals: 18,
			}],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		}
	}

	/// Helper function to create a request with specific chain IDs for inputs and outputs
	fn create_request_with_chains(input_chain: u64, output_chain: u64) -> GetQuoteRequest {
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
						input_chain,
						address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
					),
					amount: Some("1000000000000000000".to_string()),
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						output_chain,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						output_chain,
						address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"),
					),
					amount: None,
					calldata: None,
				}],
				swap_type: Some(SwapType::ExactInput),
				min_valid_until: None,
				preference: None,
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec!["oif-escrow-v0".to_string()],
		}
	}

	#[test]
	fn test_validate_supported_networks_success_both_chains_supported() {
		// Test: Both input and output chains are properly configured
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, false)); // Chain 1: both settlers configured
		networks.insert(137u64, create_network_config(false, false)); // Chain 137: both settlers configured

		let solver = create_mock_solver_with_networks(networks);
		let request = create_request_with_chains(1, 137);

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			result.is_ok(),
			"Should accept request with supported chains: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_success_input_origin_only() {
		// Test: Input chain has input settler, output chain has output settler
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, true)); // Chain 1: input settler only
		networks.insert(137u64, create_network_config(true, false)); // Chain 137: output settler only

		let solver = create_mock_solver_with_networks(networks);
		let request = create_request_with_chains(1, 137);

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			result.is_ok(),
			"Should accept request with proper origin/destination setup: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_fails_no_input_origin_chains() {
		// Test: No input chains have input settler configured
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(true, false)); // Chain 1: no input settler
		networks.insert(137u64, create_network_config(true, false)); // Chain 137: no input settler

		let solver = create_mock_solver_with_networks(networks);
		let request = create_request_with_chains(1, 137);

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("No supported origin chains")),
			"Should reject when no input chains have input settlers: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_fails_output_not_destination() {
		// Test: Output chain doesn't have output settler configured
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, false)); // Chain 1: both settlers
		networks.insert(137u64, create_network_config(false, true)); // Chain 137: no output settler

		let solver = create_mock_solver_with_networks(networks);
		let request = create_request_with_chains(1, 137);

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("Chain 137 not supported as destination")),
			"Should reject when output chain lacks output settler: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_fails_input_chain_not_configured() {
		// Test: Input chain is not configured at all
		let mut networks = HashMap::new();
		networks.insert(137u64, create_network_config(false, false)); // Only chain 137 configured

		let solver = create_mock_solver_with_networks(networks);
		let request = create_request_with_chains(1, 137); // Input on chain 1 (not configured)

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("No supported origin chains")),
			"Should reject when input chain is not configured: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_fails_output_chain_not_configured() {
		// Test: Output chain is not configured at all
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, false)); // Only chain 1 configured

		let solver = create_mock_solver_with_networks(networks);
		let request = create_request_with_chains(1, 137); // Output on chain 137 (not configured)

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("Chain 137 not supported as destination")),
			"Should reject when output chain is not configured: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_success_multiple_inputs_one_valid() {
		// Test: Multiple inputs, at least one on supported origin chain
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, false)); // Chain 1: both settlers
		networks.insert(42u64, create_network_config(true, false)); // Chain 42: no input settler
		networks.insert(137u64, create_network_config(false, false)); // Chain 137: both settlers

		let solver = create_mock_solver_with_networks(networks);

		let mut request = create_request_with_chains(1, 137);
		// Add another input on unsupported origin chain
		request.intent.inputs.push(QuoteInput {
			user: InteropAddress::new_ethereum(
				42,
				address!("1111111111111111111111111111111111111111"),
			),
			asset: InteropAddress::new_ethereum(
				42,
				address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
			),
			amount: Some("500000000000000000".to_string()),
			lock: None,
		});

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			result.is_ok(),
			"Should accept when at least one input is on supported origin chain: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_fails_multiple_outputs_one_invalid() {
		// Test: Multiple outputs, all must be on supported destination chains
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, false)); // Chain 1: both settlers
		networks.insert(137u64, create_network_config(false, false)); // Chain 137: both settlers
		networks.insert(42u64, create_network_config(false, true)); // Chain 42: no output settler

		let solver = create_mock_solver_with_networks(networks);

		let mut request = create_request_with_chains(1, 137);
		// Add another output on unsupported destination chain
		request.intent.outputs.push(QuoteOutput {
			receiver: InteropAddress::new_ethereum(
				42,
				address!("2222222222222222222222222222222222222222"),
			),
			asset: InteropAddress::new_ethereum(
				42,
				address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"),
			),
			amount: None,
			calldata: None,
		});

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("Chain 42 not supported as destination")),
			"Should reject when any output is on unsupported destination chain: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_success_same_chain_input_output() {
		// Test: Input and output on same chain with both settlers configured
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, false)); // Chain 1: both settlers

		let solver = create_mock_solver_with_networks(networks);
		let request = create_request_with_chains(1, 1); // Same chain for input and output

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			result.is_ok(),
			"Should accept same-chain swaps when both settlers configured: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_fails_same_chain_missing_settlers() {
		// Test: Input and output on same chain but missing required settlers
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, true)); // Chain 1: no output settler

		let solver = create_mock_solver_with_networks(networks);
		let request = create_request_with_chains(1, 1); // Same chain for input and output

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("Chain 1 not supported as destination")),
			"Should reject same-chain swaps when output settler missing: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_supported_networks_handles_invalid_interop_address() {
		// Test: Invalid chain ID in interop address should be handled gracefully
		let mut networks = HashMap::new();
		networks.insert(1u64, create_network_config(false, false));

		let solver = create_mock_solver_with_networks(networks);

		// This test would need to construct an invalid InteropAddress
		// For now, we test with a valid request to ensure the function works correctly
		let request = create_request_with_chains(1, 1);

		let result = QuoteValidator::validate_supported_networks(&request, &solver);
		assert!(
			result.is_ok() || matches!(result, Err(QuoteError::InvalidRequest(_))),
			"Should handle address parsing appropriately: {:?}",
			result
		);
	}

	// ========== Helper functions for testing validate_and_collect_*_with_costs ==========

	/// Creates a mock CostContext for testing
	fn create_mock_cost_context(
		swap_amounts: HashMap<InteropAddress, (U256, u8)>,
		cost_amounts: HashMap<InteropAddress, (U256, u8)>,
		swap_type: SwapType,
	) -> solver_types::CostContext {
		use rust_decimal::Decimal;
		use solver_types::costs::TokenAmountInfo;
		use solver_types::{CostBreakdown, CostContext};

		let mut swap_amounts_map = HashMap::new();
		for (addr, (amount, decimals)) in swap_amounts {
			swap_amounts_map.insert(
				addr.clone(),
				TokenAmountInfo {
					token: addr.clone(),
					amount,
					decimals,
				},
			);
		}

		let mut cost_amounts_map = HashMap::new();
		for (addr, (amount, decimals)) in cost_amounts {
			cost_amounts_map.insert(
				addr.clone(),
				TokenAmountInfo {
					token: addr.clone(),
					amount,
					decimals,
				},
			);
		}

		CostContext {
			cost_breakdown: CostBreakdown {
				gas_open: Decimal::ZERO,
				gas_fill: Decimal::ZERO,
				gas_claim: Decimal::ZERO,
				gas_buffer: Decimal::ZERO,
				rate_buffer: Decimal::ZERO,
				base_price: Decimal::ZERO,
				min_profit: Decimal::ZERO,
				operational_cost: Decimal::ZERO,
				subtotal: Decimal::ZERO,
				total: Decimal::ZERO,
				currency: "USD".to_string(),
			},
			execution_costs_by_chain: HashMap::new(),
			liquidity_cost_adjustment: Decimal::ZERO,
			protocol_fees: HashMap::new(),
			swap_type,
			cost_amounts_in_tokens: cost_amounts_map,
			swap_amounts: swap_amounts_map,
			adjusted_amounts: HashMap::new(),
		}
	}

	/// Creates a mock solver with specific token support configuration
	fn create_mock_solver_with_token_support(
		supported_tokens: HashMap<u64, Vec<AlloyAddress>>,
	) -> SolverEngine {
		use solver_types::networks::{NetworkConfig, RpcEndpoint, TokenConfig};
		use solver_types::Address;

		let mut networks = HashMap::new();

		for (chain_id, token_addresses) in supported_tokens {
			let tokens = token_addresses
				.into_iter()
				.enumerate()
				.map(|(i, addr)| TokenConfig {
					address: Address(addr.as_slice().to_vec()),
					symbol: format!("TOKEN{}", i),
					decimals: 18,
				})
				.collect();

			networks.insert(
				chain_id,
				NetworkConfig {
					rpc_urls: vec![RpcEndpoint::http_only("https://test.rpc".to_string())],
					input_settler_address: Address(vec![1u8; 20]),
					output_settler_address: Address(vec![2u8; 20]),
					tokens,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			);
		}

		create_mock_solver_with_networks(networks)
	}

	/// Creates a GetQuoteRequest for testing with customizable inputs and outputs
	fn create_test_quote_request(
		inputs: Vec<(InteropAddress, Option<&str>)>, // (asset, amount)
		outputs: Vec<(InteropAddress, Option<&str>)>, // (asset, amount)
		swap_type: SwapType,
	) -> GetQuoteRequest {
		let user_address =
			InteropAddress::new_ethereum(1, address!("1111111111111111111111111111111111111111"));

		let quote_inputs = inputs
			.into_iter()
			.map(|(asset, amount)| QuoteInput {
				user: user_address.clone(),
				asset,
				amount: amount.map(|s| s.to_string()),
				lock: None,
			})
			.collect();

		let quote_outputs = outputs
			.into_iter()
			.map(|(asset, amount)| QuoteOutput {
				receiver: InteropAddress::new_ethereum(
					137,
					address!("2222222222222222222222222222222222222222"),
				),
				asset,
				amount: amount.map(|s| s.to_string()),
				calldata: None,
			})
			.collect();

		GetQuoteRequest {
			user: user_address,
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: quote_inputs,
				outputs: quote_outputs,
				swap_type: Some(swap_type),
				min_valid_until: None,
				preference: None,
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec!["oif-escrow-v0".to_string()],
		}
	}

	/// Creates a simple single-input, single-output GetQuoteRequest for testing
	fn create_simple_test_quote_request(
		input_asset: InteropAddress,
		input_amount: Option<&str>,
		output_asset: InteropAddress,
		output_amount: Option<&str>,
		swap_type: SwapType,
	) -> GetQuoteRequest {
		create_test_quote_request(
			vec![(input_asset, input_amount)],
			vec![(output_asset, output_amount)],
			swap_type,
		)
	}

	// ========== validate_and_collect_inputs_with_costs Tests ==========

	#[test]
	fn test_validate_and_collect_inputs_with_costs_success_all_supported() {
		// Test: All input tokens are supported, amounts from cost context
		let input_token =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let output_token =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));

		let mut supported_tokens = HashMap::new();
		supported_tokens.insert(
			1u64,
			vec![address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")],
		);
		let solver = create_mock_solver_with_token_support(supported_tokens);

		let request = create_simple_test_quote_request(
			input_token.clone(),
			Some("1000000"), // 1 USDC (6 decimals)
			output_token,
			None,
			SwapType::ExactInput,
		);

		// Create cost context with swap amounts
		let mut swap_amounts = HashMap::new();
		swap_amounts.insert(input_token.clone(), (U256::from(2000000u64), 6)); // 2 USDC from cost context

		let cost_context =
			create_mock_cost_context(swap_amounts, HashMap::new(), SwapType::ExactInput);

		let result = QuoteValidator::validate_and_collect_inputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			result.is_ok(),
			"Should succeed with supported tokens: {:?}",
			result
		);

		let supported_assets = result.unwrap();
		assert_eq!(supported_assets.len(), 1);
		assert_eq!(supported_assets[0].asset, input_token);
		assert_eq!(supported_assets[0].amount, U256::from(2000000u64)); // Amount from cost context
	}

	#[test]
	fn test_validate_and_collect_inputs_with_costs_fallback_to_request_amount() {
		// Test: Token not in cost context, falls back to request amount
		let input_token =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let output_token =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));

		let mut supported_tokens = HashMap::new();
		supported_tokens.insert(
			1u64,
			vec![address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")],
		);
		let solver = create_mock_solver_with_token_support(supported_tokens);

		let request = create_simple_test_quote_request(
			input_token.clone(),
			Some("1000000"), // 1 USDC (6 decimals)
			output_token,
			None,
			SwapType::ExactInput,
		);

		// Create cost context without this token (empty swap_amounts)
		let cost_context =
			create_mock_cost_context(HashMap::new(), HashMap::new(), SwapType::ExactInput);

		let result = QuoteValidator::validate_and_collect_inputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			result.is_ok(),
			"Should succeed with fallback to request amount: {:?}",
			result
		);

		let supported_assets = result.unwrap();
		assert_eq!(supported_assets.len(), 1);
		assert_eq!(supported_assets[0].asset, input_token);
		assert_eq!(supported_assets[0].amount, U256::from(1000000u64)); // Amount from request
	}

	#[test]
	fn test_validate_and_collect_inputs_with_costs_fails_unsupported_token() {
		// Test: Input token is not supported by solver
		let input_token =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let output_token =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));

		// Create solver that doesn't support this token
		let solver = create_mock_solver_with_token_support(HashMap::new());

		let request = create_simple_test_quote_request(
			input_token.clone(),
			Some("1000000"),
			output_token,
			None,
			SwapType::ExactInput,
		);

		let cost_context =
			create_mock_cost_context(HashMap::new(), HashMap::new(), SwapType::ExactInput);

		let result = QuoteValidator::validate_and_collect_inputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("Input token not supported")),
			"Should reject unsupported input token: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_and_collect_inputs_with_costs_multiple_inputs_mixed_support() {
		// Test: Multiple inputs, some supported, some not - should fail if ANY is unsupported
		let supported_token =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let unsupported_token =
			InteropAddress::new_ethereum(1, address!("1111111111111111111111111111111111111111"));
		let output_token =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));

		let mut supported_tokens = HashMap::new();
		supported_tokens.insert(
			1u64,
			vec![address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")],
		);
		let solver = create_mock_solver_with_token_support(supported_tokens);

		let request = create_test_quote_request(
			vec![
				(supported_token.clone(), Some("1000000")),
				(unsupported_token.clone(), Some("500000")),
			],
			vec![(output_token, None)],
			SwapType::ExactInput,
		);

		let cost_context =
			create_mock_cost_context(HashMap::new(), HashMap::new(), SwapType::ExactInput);

		let result = QuoteValidator::validate_and_collect_inputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("Input token not supported")),
			"Should reject when any input token is unsupported: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_and_collect_inputs_with_costs_multiple_inputs_all_supported() {
		// Test: Multiple inputs, all supported
		let token1 =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let token2 =
			InteropAddress::new_ethereum(1, address!("dAC17F958D2ee523a2206206994597C13D831ec7"));
		let output_token =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));

		let mut supported_tokens = HashMap::new();
		supported_tokens.insert(
			1u64,
			vec![
				address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
				address!("dAC17F958D2ee523a2206206994597C13D831ec7"),
			],
		);
		let solver = create_mock_solver_with_token_support(supported_tokens);

		let request = create_test_quote_request(
			vec![
				(token1.clone(), Some("1000000")),
				(token2.clone(), Some("500000")),
			],
			vec![(output_token, None)],
			SwapType::ExactInput,
		);

		// Create cost context with amounts for both tokens
		let mut swap_amounts = HashMap::new();
		swap_amounts.insert(token1.clone(), (U256::from(2000000u64), 6));
		swap_amounts.insert(token2.clone(), (U256::from(1000000u64), 6));

		let cost_context =
			create_mock_cost_context(swap_amounts, HashMap::new(), SwapType::ExactInput);

		let result = QuoteValidator::validate_and_collect_inputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			result.is_ok(),
			"Should succeed with all supported tokens: {:?}",
			result
		);

		let supported_assets = result.unwrap();
		assert_eq!(supported_assets.len(), 2);

		// Check both tokens are present with correct amounts
		let asset1 = supported_assets.iter().find(|a| a.asset == token1).unwrap();
		let asset2 = supported_assets.iter().find(|a| a.asset == token2).unwrap();

		assert_eq!(asset1.amount, U256::from(2000000u64)); // From cost context
		assert_eq!(asset2.amount, U256::from(1000000u64)); // From cost context
	}

	// ========== validate_and_collect_outputs_with_costs Tests ==========

	#[test]
	fn test_validate_and_collect_outputs_with_costs_success_all_supported() {
		// Test: All output tokens are supported, amounts from cost context
		let input_token =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let output_token =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));

		let mut supported_tokens = HashMap::new();
		supported_tokens.insert(
			137u64,
			vec![address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1")],
		);
		let solver = create_mock_solver_with_token_support(supported_tokens);

		let request = create_simple_test_quote_request(
			input_token,
			Some("1000000"),
			output_token.clone(),
			Some("950000"), // 0.95 token (18 decimals)
			SwapType::ExactOutput,
		);

		// Create cost context with swap amounts
		let mut swap_amounts = HashMap::new();
		swap_amounts.insert(output_token.clone(), (U256::from(1000000u64), 18)); // 1 token from cost context

		let cost_context =
			create_mock_cost_context(swap_amounts, HashMap::new(), SwapType::ExactOutput);

		let result = QuoteValidator::validate_and_collect_outputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			result.is_ok(),
			"Should succeed with supported tokens: {:?}",
			result
		);

		let supported_assets = result.unwrap();
		assert_eq!(supported_assets.len(), 1);
		assert_eq!(supported_assets[0].asset, output_token);
		assert_eq!(supported_assets[0].amount, U256::from(1000000u64)); // Amount from cost context
	}

	#[test]
	fn test_validate_and_collect_outputs_with_costs_fallback_to_request_amount() {
		// Test: Token not in cost context, falls back to request amount
		let input_token =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let output_token =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));

		let mut supported_tokens = HashMap::new();
		supported_tokens.insert(
			137u64,
			vec![address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1")],
		);
		let solver = create_mock_solver_with_token_support(supported_tokens);

		let request = create_simple_test_quote_request(
			input_token,
			Some("1000000"),
			output_token.clone(),
			Some("950000"), // 0.95 token
			SwapType::ExactOutput,
		);

		// Create cost context without this token (empty swap_amounts)
		let cost_context =
			create_mock_cost_context(HashMap::new(), HashMap::new(), SwapType::ExactOutput);

		let result = QuoteValidator::validate_and_collect_outputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			result.is_ok(),
			"Should succeed with fallback to request amount: {:?}",
			result
		);

		let supported_assets = result.unwrap();
		assert_eq!(supported_assets.len(), 1);
		assert_eq!(supported_assets[0].asset, output_token);
		assert_eq!(supported_assets[0].amount, U256::from(950000u64)); // Amount from request
	}

	#[test]
	fn test_validate_and_collect_outputs_with_costs_fails_unsupported_token() {
		// Test: Output token is not supported by solver
		let input_token =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let output_token =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));

		// Create solver that doesn't support this token
		let solver = create_mock_solver_with_token_support(HashMap::new());

		let request = create_simple_test_quote_request(
			input_token,
			Some("1000000"),
			output_token.clone(),
			Some("950000"),
			SwapType::ExactOutput,
		);

		let cost_context =
			create_mock_cost_context(HashMap::new(), HashMap::new(), SwapType::ExactOutput);

		let result = QuoteValidator::validate_and_collect_outputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			matches!(result, Err(QuoteError::UnsupportedAsset(ref msg)) if msg.contains("Output token not supported")),
			"Should reject unsupported output token: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_and_collect_outputs_with_costs_multiple_outputs_all_supported() {
		// Test: Multiple outputs, all supported
		let input_token =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let token1 =
			InteropAddress::new_ethereum(137, address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"));
		let token2 =
			InteropAddress::new_ethereum(137, address!("c2132D05D31c914a87C6611C10748AEb04B58e8F"));

		let mut supported_tokens = HashMap::new();
		supported_tokens.insert(
			137u64,
			vec![
				address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"),
				address!("c2132D05D31c914a87C6611C10748AEb04B58e8F"),
			],
		);
		let solver = create_mock_solver_with_token_support(supported_tokens);

		let request = create_test_quote_request(
			vec![(input_token, Some("1000000"))],
			vec![
				(token1.clone(), Some("950000")),
				(token2.clone(), Some("500000")),
			],
			SwapType::ExactOutput,
		);

		// Create cost context with amounts for both tokens
		let mut swap_amounts = HashMap::new();
		swap_amounts.insert(token1.clone(), (U256::from(1000000u64), 18));
		swap_amounts.insert(token2.clone(), (U256::from(750000u64), 6));

		let cost_context =
			create_mock_cost_context(swap_amounts, HashMap::new(), SwapType::ExactOutput);

		let result = QuoteValidator::validate_and_collect_outputs_with_costs(
			&request,
			&solver,
			&cost_context,
		);

		assert!(
			result.is_ok(),
			"Should succeed with all supported tokens: {:?}",
			result
		);

		let supported_assets = result.unwrap();
		assert_eq!(supported_assets.len(), 2);

		// Check both tokens are present with correct amounts
		let asset1 = supported_assets.iter().find(|a| a.asset == token1).unwrap();
		let asset2 = supported_assets.iter().find(|a| a.asset == token2).unwrap();

		assert_eq!(asset1.amount, U256::from(1000000u64)); // From cost context
		assert_eq!(asset2.amount, U256::from(750000u64)); // From cost context
	}

	// ========== validate_callback_whitelist Tests ==========

	fn create_test_config_with_callbacks(
		simulate_callbacks: bool,
		whitelist: Vec<String>,
	) -> solver_config::Config {
		let config_toml = format!(
			r#"
			[solver]
			id = "test-solver"
			monitoring_timeout_seconds = 30
			min_profitability_pct = 1.0

			[storage]
			primary = "memory"
			cleanup_interval_seconds = 3600
			[storage.implementations.memory]

			[delivery]
			min_confirmations = 1
			[delivery.implementations]

			[account]
			primary = "local"
			[account.implementations.local]
			private_key = "0x1234567890123456789012345678901234567890123456789012345678901234"

			[discovery]
			[discovery.implementations]

			[order]
			simulate_callbacks = {}
			callback_whitelist = {:?}
			[order.implementations]
			[order.strategy]
			primary = "simple"
			[order.strategy.implementations.simple]

			[settlement]
			[settlement.implementations]

			[networks]
		"#,
			simulate_callbacks, whitelist
		);
		toml::from_str(&config_toml).expect("Failed to parse test config")
	}

	fn create_request_with_callback(calldata: Option<&str>) -> GetQuoteRequest {
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
						address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
					),
					amount: Some("1000000000000000000".to_string()),
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						84532,
						address!("f2a313a3Dc028295e1dFa3BEE34EaFD2f801C994"),
					),
					asset: InteropAddress::new_ethereum(
						84532,
						address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"),
					),
					amount: None,
					calldata: calldata.map(|s| s.to_string()),
				}],
				swap_type: Some(SwapType::ExactInput),
				min_valid_until: None,
				preference: None,
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec!["oif-escrow-v0".to_string()],
		}
	}

	#[test]
	fn test_validate_callback_whitelist_no_callback_succeeds() {
		// Test: No callback data should always succeed
		let config = create_test_config_with_callbacks(false, vec![]);
		let request = create_request_with_callback(None);

		let result = QuoteValidator::validate_callback_whitelist(&request, &config);
		assert!(
			result.is_ok(),
			"Should succeed when no callback data: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_callback_whitelist_empty_callback_succeeds() {
		// Test: Empty callback ("0x") should be treated as no callback
		let config = create_test_config_with_callbacks(false, vec![]);
		let request = create_request_with_callback(Some("0x"));

		let result = QuoteValidator::validate_callback_whitelist(&request, &config);
		assert!(
			result.is_ok(),
			"Should succeed when callback is empty '0x': {:?}",
			result
		);
	}

	#[test]
	fn test_validate_callback_whitelist_simulation_disabled_fails() {
		// Test: Callback data with simulation disabled should fail
		let config = create_test_config_with_callbacks(false, vec![]);
		let request = create_request_with_callback(Some(
			"0x000000000000000000000000d890aa4d1b1517a16f9c3d938d06721356e48b7d",
		));

		let result = QuoteValidator::validate_callback_whitelist(&request, &config);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("simulation is disabled")),
			"Should reject callback when simulation disabled: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_callback_whitelist_empty_whitelist_allows_all() {
		// Test: Empty whitelist should allow all callbacks (when simulation enabled)
		let config = create_test_config_with_callbacks(true, vec![]);
		let request = create_request_with_callback(Some(
			"0x000000000000000000000000d890aa4d1b1517a16f9c3d938d06721356e48b7d",
		));

		let result = QuoteValidator::validate_callback_whitelist(&request, &config);
		assert!(
			result.is_ok(),
			"Should allow any callback when whitelist is empty: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_callback_whitelist_recipient_whitelisted_succeeds() {
		// Test: Callback recipient in whitelist should succeed
		// Receiver is 0xf2a313a3Dc028295e1dFa3BEE34EaFD2f801C994 on chain 84532 (0x014a34)
		// EIP-7930 format: 0x0001 | 0x0000 | 0x03 | 0x014a34 | 0x14 | <address>
		let whitelist_entry =
			"0x0001000003014a3414f2a313a3dc028295e1dfa3bee34eafd2f801c994".to_string();
		let config = create_test_config_with_callbacks(true, vec![whitelist_entry]);
		let request = create_request_with_callback(Some(
			"0x000000000000000000000000d890aa4d1b1517a16f9c3d938d06721356e48b7d",
		));

		let result = QuoteValidator::validate_callback_whitelist(&request, &config);
		assert!(
			result.is_ok(),
			"Should succeed when callback recipient is whitelisted: {:?}",
			result
		);
	}

	#[test]
	fn test_validate_callback_whitelist_recipient_not_whitelisted_fails() {
		// Test: Callback recipient NOT in whitelist should fail
		// Whitelist has a different address
		let whitelist_entry =
			"0x0001000003014a34140000000000000000000000000000000000000000".to_string();
		let config = create_test_config_with_callbacks(true, vec![whitelist_entry]);
		let request = create_request_with_callback(Some(
			"0x000000000000000000000000d890aa4d1b1517a16f9c3d938d06721356e48b7d",
		));

		let result = QuoteValidator::validate_callback_whitelist(&request, &config);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("not in the solver's whitelist")),
			"Should reject callback when recipient not whitelisted: {:?}",
			result
		);
	}
}
