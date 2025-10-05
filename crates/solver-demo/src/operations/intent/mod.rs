//! Intent operations module
//!
//! Provides functionality for building, submitting, and managing cross-chain intents.
//! Handles intent request construction, settlement type validation, authentication
//! schemes, and order submission workflows with comprehensive parameter validation.

use crate::{
	core::logging,
	types::{chain::ChainId, error::Result},
	Context, GetQuoteRequest, PostOrderRequest,
};
use alloy_primitives::{Address, U256};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use solver_types::api::{
	AuthScheme, FailureHandlingMode, IntentRequest, IntentType, OriginMode, OriginSubmission,
	QuoteInput, QuoteOutput, QuotePreference, SwapType,
};
use solver_types::standards::eip7930::InteropAddress;
use std::str::FromStr;
use std::sync::Arc;
use tracing::instrument;

/// Intent operations handler
///
/// Provides methods for building intent requests, validating settlement configurations,
/// and managing the complete intent lifecycle from construction to submission.
/// Supports multiple settlement types and authentication schemes.
pub struct IntentOps {
	ctx: Arc<Context>,
}

impl IntentOps {
	/// Creates a new intent operations handler
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New intent operations instance
	pub fn new(ctx: Arc<Context>) -> Self {
		Self { ctx }
	}

	/// Builds a cross-chain intent and creates a quote request
	///
	/// # Arguments
	/// * `params` - Intent parameters including chains, tokens, amounts, and settlement type
	/// * `output_path` - Optional path to save the generated request
	///
	/// # Returns
	/// Quote request ready for API submission
	///
	/// # Errors
	/// Returns error if token resolution fails, settlement validation fails, or
	/// authentication scheme configuration is invalid
	#[instrument(skip(self))]
	pub async fn build(
		&self,
		params: IntentParams,
		output_path: Option<std::path::PathBuf>,
	) -> Result<GetQuoteRequest> {
		use crate::types::hex::Hex;
		let user_addr = params.sender.unwrap_or_else(|| {
			Hex::to_address(&self.ctx.config.accounts().user.address)
				.unwrap_or_else(|_| Address::from([0x01; 20]))
		});
		let recipient_addr = params.recipient.unwrap_or(user_addr);

		let user = self.create_interop_address(user_addr, params.from_chain)?;

		let from_token_addr = self.get_token_address(params.from_chain, &params.from_token)?;
		let asset_input = self.create_interop_address(from_token_addr, params.from_chain)?;

		let to_token_addr = self.get_token_address(params.to_chain, &params.to_token)?;
		let asset_output = self.create_interop_address(to_token_addr, params.to_chain)?;

		let receiver = self.create_interop_address(recipient_addr, params.to_chain)?;

		let (origin_submission, lock) = match params.settlement {
			SettlementType::Escrow => {
				let auth_scheme = match params.auth {
					Some(AuthType::Permit2) => AuthScheme::Permit2,
					Some(AuthType::Eip3009) => AuthScheme::Eip3009,
					None => return Err(crate::types::error::Error::InvalidConfig(
						"Auth scheme is required for escrow settlement. Use --auth permit2 or --auth eip3009".to_string()
					)),
				};

				let origin_submission = OriginSubmission {
					mode: OriginMode::User,
					schemes: Some(vec![auth_scheme]),
				};

				(Some(origin_submission), None)
			},
			SettlementType::Compact => {
				if params.auth.is_some() {
					return Err(crate::types::error::Error::InvalidConfig(
						"Auth scheme should not be specified for compact settlement. Compact uses its own signature mechanism".to_string()
					));
				}

				let lock = Some(solver_types::api::AssetLockReference {
					kind: solver_types::api::LockKind::TheCompact,
					params: None,
				});
				(None, lock)
			},
		};

		let (input, output) = if params.exact_output {
			let input = QuoteInput {
				user,
				asset: asset_input,
				amount: None, // No amount for exact output
				lock: lock.clone(),
			};

			let output = QuoteOutput {
				receiver,
				asset: asset_output,
				amount: Some(params.amount.to_string()), // Use the specified amount as output
				calldata: None,
			};

			(input, output)
		} else {
			// For exact input swaps: only set input amount, leave output amount as None
			let input = QuoteInput {
				user,
				asset: asset_input,
				amount: Some(params.amount.to_string()), // Use the specified amount as input
				lock: lock.clone(),
			};

			let output = QuoteOutput {
				receiver,
				asset: asset_output,
				amount: params.min_amount.map(|a| a.to_string()), // Optional minimum output amount
				calldata: None,
			};

			(input, output)
		};

		// Determine swap type
		let swap_type = if params.exact_output {
			SwapType::ExactOutput
		} else {
			SwapType::ExactInput
		};

		// Build complete intent request following old demo pattern
		let intent = IntentRequest {
			intent_type: IntentType::OifSwap,
			inputs: vec![input],
			outputs: vec![output],
			swap_type: Some(swap_type),
			min_valid_until: Some((Utc::now().timestamp() as u64) + 300), // 5 minutes
			preference: Some(QuotePreference::Speed),
			origin_submission,
			failure_handling: Some(vec![FailureHandlingMode::RefundAutomatic]),
			partial_fill: Some(false),
			metadata: None,
		};

		// Determine supported types based on settlement and auth
		let supported_types = match params.settlement {
			SettlementType::Escrow => match params.auth {
				Some(AuthType::Permit2) => vec!["oif-escrow-v0".to_string()],
				Some(AuthType::Eip3009) => vec!["oif-3009-v0".to_string()],
				None => unreachable!("Auth is validated to be present for escrow"),
			},
			SettlementType::Compact => vec!["oif-resource-lock-v0".to_string()],
		};

		// Create GetQuoteRequest following old demo pattern
		let quote_request = GetQuoteRequest {
			user: self.create_interop_address(user_addr, params.from_chain)?,
			intent,
			supported_types,
		};

		// Save to storage following old demo pattern
		if let Some(custom_path) = output_path {
			// Save to custom path
			let content = serde_json::to_string_pretty(&quote_request)?;
			std::fs::write(&custom_path, content)?;
		} else {
			// Save to requests subdirectory like old demo
			let requests_storage = self.ctx.storage.subdir("requests")?;
			requests_storage.save("get_quote.req", &quote_request)?;
		}

		Ok(quote_request)
	}

	/// Build batch of intents from file
	pub async fn build_batch(&self, input_file: &std::path::Path) -> Result<Vec<GetQuoteRequest>> {
		let content = std::fs::read_to_string(input_file)?;
		let batch: crate::types::BatchIntentSpec = serde_json::from_str(&content)?;

		let mut quote_requests = Vec::new();
		for spec in batch.intents {
			// Convert IntentSpec to IntentParams
			let params = self.convert_intent_spec_to_params(spec).await?;
			let quote_request = self.build(params, None).await?;
			quote_requests.push(quote_request);
		}

		Ok(quote_requests)
	}

	/// Converts intent specification from JSON format to internal parameters
	///
	/// # Arguments
	/// * `spec` - Intent specification containing all configuration details
	///
	/// # Returns
	/// Intent parameters ready for quote request building
	///
	/// # Errors
	/// Returns error if intent disabled, amount validation fails, or address resolution fails
	async fn convert_intent_spec_to_params(
		&self,
		spec: crate::types::IntentSpec,
	) -> Result<IntentParams> {
		// Skip disabled intents
		if !spec.enabled {
			return Err(crate::types::error::Error::InvalidConfig(
				"Intent is disabled".to_string(),
			));
		}

		// Determine swap type and amount
		let (exact_output, amount_str) =
			if spec.amounts.input.is_some() && spec.amounts.output.is_some() {
				return Err(crate::types::error::Error::InvalidConfig(
					"Intent specifies both input and output amounts. Please specify only one."
						.to_string(),
				));
			} else if let Some(input_amount) = spec.amounts.input {
				(false, input_amount)
			} else if let Some(output_amount) = spec.amounts.output {
				(true, output_amount)
			} else {
				return Err(crate::types::error::Error::InvalidConfig(
					"Intent must specify either input or output amount".to_string(),
				));
			};

		// Parse amount according to token decimals
		let amount = if exact_output {
			// For exact output, use destination token decimals
			crate::types::extensions::TokenExtensions::to_wei_from_decimals(
				&amount_str,
				spec.dest_token.decimals,
			)?
		} else {
			// For exact input, use source token decimals
			crate::types::extensions::TokenExtensions::to_wei_from_decimals(
				&amount_str,
				spec.origin_token.decimals,
			)?
		};

		// Parse settlement and auth
		let settlement_type = spec
			.settlement
			.as_deref()
			.unwrap_or("escrow")
			.parse::<SettlementType>()?;

		let auth_type = match spec.auth.as_deref() {
			Some(auth_str) => Some(auth_str.parse::<AuthType>()?),
			None => {
				// Default to permit2 for escrow, none for compact
				match settlement_type {
					SettlementType::Escrow => Some(AuthType::Permit2),
					SettlementType::Compact => None,
				}
			},
		};

		// Resolve recipient if provided
		let recipient = if let Some(recipient_str) = spec.recipient {
			Some(self.ctx.resolve_address(&recipient_str)?)
		} else {
			None
		};

		Ok(IntentParams {
			from_chain: crate::types::chain::ChainId::from_u64(spec.origin_chain_id),
			to_chain: crate::types::chain::ChainId::from_u64(spec.dest_chain_id),
			from_token: spec.origin_token.symbol,
			to_token: spec.dest_token.symbol,
			amount,
			min_amount: None,
			sender: None,
			recipient,
			exact_output,
			settlement: settlement_type,
			auth: auth_type,
		})
	}

	/// Submit an intent (creates an order)
	#[instrument(skip(self, order))]
	pub async fn submit(&self, order: PostOrderRequest) -> Result<String> {
		// Check if this is a Compact order that needs deposit
		let order_type = order.order.order_type();
		if order_type == "oif-resource-lock-v0" {
			use crate::core::logging;
			logging::verbose_operation("Detected Compact order", "performing deposit");
			self.deposit_compact_tokens(&order).await?;
		}

		// Get API client
		let api = self.ctx.api_client().await?;

		// Submit order
		let response = api.submit_order(order).await?;

		Ok(response.order_id.unwrap_or_else(|| "pending".to_string()))
	}

	/// Deposits tokens to TheCompact contract for resource lock orders
	///
	/// # Arguments
	/// * `order` - Post order request containing resource lock order details
	///
	/// # Errors
	/// Returns error if order extraction fails, contract interaction fails, or transaction fails
	async fn deposit_compact_tokens(&self, order: &PostOrderRequest) -> Result<()> {
		use solver_types::api::OifOrder;

		match &order.order {
			OifOrder::OifResourceLockV0 { payload } => {
				// Extract chain ID from domain
				let chain_id = self.extract_chain_id_from_payload(payload)?;
				let chain = ChainId::from_u64(chain_id);

				// Extract commitment details
				let (token_address, amount) = self.extract_commitment_details(payload)?;

				// Get user address (sponsor)
				let user_address = self.extract_user_address(payload)?;

				use crate::core::logging;
				logging::verbose_operation(
					"Preparing compact deposit",
					&format!("chain {}, amount {}", chain_id, amount),
				);

				// Generate allocator lock tag from allocator address
				let allocator_lock_tag = self.generate_allocator_lock_tag(chain).await?;

				// Execute deposit
				self.execute_compact_deposit(
					chain,
					token_address,
					amount,
					allocator_lock_tag,
					user_address,
				)
				.await?;

				logging::verbose_success("Compact deposit", "operation completed successfully");
			},
			_ => {
				// Not a resource lock order, no deposit needed
			},
		}

		Ok(())
	}

	/// Extracts chain ID from order payload domain structure
	///
	/// # Arguments
	/// * `payload` - Order payload containing domain information
	///
	/// # Returns
	/// Chain ID as u64 value
	///
	/// # Errors
	/// Returns error if domain format invalid or chain ID missing/malformed
	fn extract_chain_id_from_payload(
		&self,
		payload: &solver_types::api::OrderPayload,
	) -> Result<u64> {
		let domain = payload.domain.as_object().ok_or_else(|| {
			crate::types::error::Error::InvalidConfig("Invalid domain format".to_string())
		})?;

		let chain_id_value = domain.get("chainId").ok_or_else(|| {
			crate::types::error::Error::InvalidConfig("Missing chainId in domain".to_string())
		})?;

		// Handle both string and number formats
		let chain_id = if let Some(s) = chain_id_value.as_str() {
			s.parse::<u64>().map_err(|_| {
				crate::types::error::Error::InvalidConfig("Invalid chainId format".to_string())
			})?
		} else if let Some(n) = chain_id_value.as_u64() {
			n
		} else {
			return Err(crate::types::error::Error::InvalidConfig(
				"chainId must be string or number".to_string(),
			));
		};

		Ok(chain_id)
	}

	/// Extract commitment details (token and amount) from payload
	fn extract_commitment_details(
		&self,
		payload: &solver_types::api::OrderPayload,
	) -> Result<(Address, U256)> {
		let message = payload.message.as_object().ok_or_else(|| {
			crate::types::error::Error::InvalidConfig("Invalid message format".to_string())
		})?;

		let commitments = message
			.get("commitments")
			.and_then(|c| c.as_array())
			.ok_or_else(|| {
				crate::types::error::Error::InvalidConfig("Missing commitments".to_string())
			})?;

		// Get first commitment (single token deposit)
		let commitment = commitments.first().ok_or_else(|| {
			crate::types::error::Error::InvalidConfig("No commitments found".to_string())
		})?;

		let token_str = commitment
			.get("token")
			.and_then(|t| t.as_str())
			.ok_or_else(|| {
				crate::types::error::Error::InvalidConfig("Missing token in commitment".to_string())
			})?;

		let amount_str = commitment
			.get("amount")
			.and_then(|a| a.as_str())
			.ok_or_else(|| {
				crate::types::error::Error::InvalidConfig(
					"Missing amount in commitment".to_string(),
				)
			})?;

		use crate::types::hex::Hex;
		let token_address = Hex::to_address(token_str)?;
		let amount = U256::from_str(amount_str).map_err(|e| {
			crate::types::error::Error::InvalidAmount(format!("Failed to parse amount: {}", e))
		})?;

		Ok((token_address, amount))
	}

	/// Extract user address (sponsor) from payload
	fn extract_user_address(&self, payload: &solver_types::api::OrderPayload) -> Result<Address> {
		let message = payload.message.as_object().ok_or_else(|| {
			crate::types::error::Error::InvalidConfig("Invalid message format".to_string())
		})?;

		let sponsor_str = message
			.get("sponsor")
			.and_then(|s| s.as_str())
			.ok_or_else(|| {
				crate::types::error::Error::InvalidConfig("Missing sponsor in message".to_string())
			})?;

		use crate::types::hex::Hex;
		Hex::to_address(sponsor_str)
	}

	/// Generate allocator lock tag from allocator address
	async fn generate_allocator_lock_tag(&self, chain: ChainId) -> Result<[u8; 12]> {
		// Get allocator address for this chain
		let contracts = self.ctx.contracts.read().map_err(|e| {
			crate::types::error::Error::StorageError(format!(
				"Failed to acquire contracts lock: {}",
				e
			))
		})?;

		// Debug: Look for contracts on chain
		use crate::core::logging;
		logging::verbose_operation("Looking for contracts", &format!("chain {}", chain.id()));
		let addresses = contracts.addresses(chain);
		if let Some(_addresses) = addresses {
			logging::verbose_success("Found contract addresses", &format!("chain {}", chain.id()));
		} else {
			logging::verbose_operation("No addresses found", &format!("chain {}", chain.id()));
		}
		let addresses = contracts.addresses(chain).ok_or_else(|| {
			crate::types::error::Error::InvalidConfig(format!(
				"No contract addresses found for chain {}",
				chain.id()
			))
		})?;
		let allocator_address = addresses.allocator.ok_or_else(|| {
			crate::types::error::Error::InvalidConfig(format!(
				"Allocator contract not found for chain {}",
				chain.id()
			))
		})?;

		// Generate lock tag: 0x00 + last 11 bytes of allocator address
		let mut allocator_lock_tag = [0u8; 12];
		allocator_lock_tag[0] = 0x00; // First byte is 0x00
		allocator_lock_tag[1..].copy_from_slice(&allocator_address.as_slice()[9..]);

		logging::verbose_tech(
			"Generated allocator lock tag",
			&hex::encode(allocator_lock_tag),
		);

		Ok(allocator_lock_tag)
	}

	/// Execute the actual deposit transaction to TheCompact
	async fn execute_compact_deposit(
		&self,
		chain: ChainId,
		token: Address,
		amount: U256,
		allocator_lock_tag: [u8; 12],
		user: Address,
	) -> Result<()> {
		use alloy_rpc_types::TransactionRequest;

		// Get provider using context
		let provider = self.ctx.provider(chain).await?;

		// Get TheCompact contract address and prepare contract call data
		let (compact_address, approve_data, deposit_data) = {
			let contracts = self.ctx.contracts.read().map_err(|e| {
				crate::types::error::Error::StorageError(format!(
					"Failed to acquire contracts lock: {}",
					e
				))
			})?;
			let addresses = contracts.addresses(chain).ok_or_else(|| {
				crate::types::error::Error::InvalidConfig(format!(
					"No contract addresses found for chain {}",
					chain.id()
				))
			})?;
			let compact_address = addresses.compact.ok_or_else(|| {
				crate::types::error::Error::InvalidConfig(format!(
					"TheCompact contract not found for chain {}",
					chain.id()
				))
			})?;

			// Prepare all contract call data while holding the lock
			let approve_data = contracts.erc20_approve(compact_address, amount)?;
			let deposit_data =
				contracts.thecompact_deposit(token, allocator_lock_tag, amount, user)?;

			(compact_address, approve_data, deposit_data)
		}; // Lock is dropped here

		logging::verbose_tech("Using TheCompact contract", &compact_address.to_string());

		// Get user's private key and create signer for transactions
		let private_key_str = self
			.ctx
			.config
			.accounts()
			.user
			.private_key
			.as_ref()
			.ok_or_else(|| {
				crate::types::error::Error::InvalidConfig("No private key configured".to_string())
			})?
			.expose_secret();
		let signer = private_key_str
			.parse::<alloy_signer_local::PrivateKeySigner>()
			.map_err(|e| {
				crate::types::error::Error::InvalidConfig(format!("Invalid private key: {}", e))
			})?;

		// Use TxBuilder for transactions
		use crate::core::blockchain::TxBuilder;
		let tx_builder = TxBuilder::new(provider).with_signer(signer);

		// Step 1: Approve TheCompact to spend tokens
		logging::verbose_operation(
			"Sending approval transaction",
			&format!("amount: {}", amount),
		);
		let approve_request = TransactionRequest::default()
			.to(token)
			.input(approve_data.into());

		let approve_hash = tx_builder.send(approve_request).await?;
		logging::verbose_tech("Approval transaction sent", &format!("{:?}", approve_hash));

		// Wait for approval to be mined before sending deposit
		logging::verbose_operation("Waiting for confirmation", "approval transaction");
		let _approve_receipt = tx_builder.wait(approve_hash).await?;
		logging::verbose_success("Approval transaction confirmed", "");

		// Step 2: Send deposit transaction (using pre-computed deposit_data)
		let deposit_request = TransactionRequest::default()
			.to(compact_address)
			.input(deposit_data.into());

		logging::verbose_operation("Sending deposit transaction", "to TheCompact");
		let deposit_hash = tx_builder.send(deposit_request).await?;

		logging::verbose_tech("Deposit transaction sent", &format!("{:?}", deposit_hash));

		// Wait for confirmation
		let receipt = tx_builder.wait(deposit_hash).await?;

		if !receipt.status() {
			return Err(crate::types::error::Error::ContractCallFailed(
				"Deposit transaction failed".to_string(),
			));
		}

		logging::verbose_success(
			"Deposit transaction confirmed",
			&format!(
				"hash: {:?}, block: {}",
				deposit_hash,
				receipt.block_number.unwrap_or_default()
			),
		);

		Ok(())
	}

	/// Query intent/order status
	#[instrument(skip(self))]
	pub async fn status(&self, order_id: &str) -> Result<OrderStatusInfo> {
		// Get API client
		let api = self.ctx.api_client().await?;

		// Query order
		let response = api.get_order(order_id).await?;

		// Extract fill transaction hash if available
		let fill_tx_hash = response
			.order
			.fill_transaction
			.as_ref()
			.and_then(|tx| tx.get("hash"))
			.and_then(|h| h.as_str())
			.map(|s| s.to_string());

		Ok(OrderStatusInfo {
			order_id: order_id.to_string(),
			status: response.order.status.to_string(),
			timestamp: chrono::Utc::now().to_rfc3339(),
			fill_tx_hash,
		})
	}

	/// Test intents with performance metrics
	#[instrument(skip(self))]
	pub async fn test(
		&self,
		input_file: &std::path::Path,
		output_file: Option<&std::path::Path>,
	) -> Result<TestResults> {
		let quote_requests = self.build_batch(input_file).await?;
		let mut results = TestResults::default();

		for quote_request in quote_requests {
			let start = std::time::Instant::now();

			// Try to get quote
			match self.ctx.api_client().await?.get_quote(quote_request).await {
				Ok(_) => {
					results.successful += 1;
					results.total_time += start.elapsed();
				},
				Err(e) => {
					results.failed += 1;
					results.errors.push(e.to_string());
				},
			}
		}

		// Save results if output file specified
		if let Some(output) = output_file {
			std::fs::write(output, serde_json::to_string_pretty(&results)?)?;
		}

		Ok(results)
	}

	fn create_interop_address(&self, address: Address, chain: ChainId) -> Result<InteropAddress> {
		// Use the standard new_ethereum method instead of manual EIP-7930 encoding
		Ok(InteropAddress::new_ethereum(chain.id(), address))
	}

	/// Get token address from registry
	fn get_token_address(&self, chain: ChainId, symbol: &str) -> Result<Address> {
		let token = self.ctx.tokens.get_or_error(chain, symbol)?;
		Ok(token.address)
	}
}

/// Settlement type for intents
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettlementType {
	Escrow,
	Compact,
}

impl FromStr for SettlementType {
	type Err = crate::types::error::Error;

	fn from_str(s: &str) -> Result<Self> {
		match s.to_lowercase().as_str() {
			"escrow" => Ok(Self::Escrow),
			"compact" => Ok(Self::Compact),
			_ => Err(crate::types::error::Error::InvalidConfig(format!(
				"Invalid settlement type: {}. Use 'escrow' or 'compact'",
				s
			))),
		}
	}
}

/// Authentication type for escrow settlements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
	Permit2,
	Eip3009,
}

impl FromStr for AuthType {
	type Err = crate::types::error::Error;

	fn from_str(s: &str) -> Result<Self> {
		match s.to_lowercase().as_str() {
			"permit2" => Ok(Self::Permit2),
			"eip3009" => Ok(Self::Eip3009),
			_ => Err(crate::types::error::Error::InvalidConfig(format!(
				"Invalid auth type: {}. Use 'permit2' or 'eip3009'",
				s
			))),
		}
	}
}

/// Parameters for building an intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentParams {
	pub from_chain: ChainId,
	pub to_chain: ChainId,
	pub from_token: String,
	pub to_token: String,
	pub amount: U256,
	pub min_amount: Option<U256>,
	pub sender: Option<Address>,
	pub recipient: Option<Address>,
	pub exact_output: bool,
	pub settlement: SettlementType,
	pub auth: Option<AuthType>,
}

/// Order status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderStatusInfo {
	pub order_id: String,
	pub status: String,
	pub timestamp: String,
	pub fill_tx_hash: Option<String>,
}

/// Test results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestResults {
	pub successful: usize,
	pub failed: usize,
	pub total_time: std::time::Duration,
	pub errors: Vec<String>,
}
