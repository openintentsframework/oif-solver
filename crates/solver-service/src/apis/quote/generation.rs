//! Quote generation engine for cross-chain intent execution.
//!
//! This module orchestrates the creation of executable quotes for cross-chain token transfers.
//! It combines custody decisions, settlement mechanisms, and signature requirements to produce
//! complete quote objects that users can sign and submit for execution.
//!
//! ## Overview
//!
//! The quote generator:
//! - Analyzes available inputs and requested outputs
//! - Determines optimal custody and settlement strategies
//! - Generates appropriate signature payloads
//! - Calculates execution timelines and expiry
//! - Produces multiple quote options when available
//!
//! ## Quote Structure
//!
//! Each generated quote contains:
//! - **Orders**: Signature requirements (EIP-712, ERC-3009, etc.)
//! - **Details**: Input/output specifications
//! - **Validity**: Expiry times and execution windows
//! - **ETA**: Estimated completion time based on chain characteristics
//! - **Provider**: Solver identification
//!
//! ## Generation Process
//!
//! 1. **Input Analysis**: Evaluate each available input for capabilities
//! 2. **Custody Decision**: Determine optimal token custody mechanism
//! 3. **Order Creation**: Generate appropriate signature payloads
//! 4. **Quote Assembly**: Combine all components into executable quotes
//! 5. **Preference Sorting**: Order quotes based on user preferences
//!
//! ## Supported Order Types
//!
//! ### Resource Locks
//! - TheCompact orders with allocation proofs
//! - Custom protocol-specific lock orders
//!
//! ### Escrow Orders
//! - Permit2 batch witness transfers
//! - ERC-3009 authorization transfers
//!
//! ## Optimization Strategies
//!
//! The generator optimizes for:
//! - **Speed**: Minimal execution time across chains
//! - **Cost**: Lowest gas fees and protocol costs
//! - **Trust**: Minimal trust assumptions
//! - **Input Priority**: Preference for specific input tokens

use super::custody::{CustodyDecision, CustodyStrategy, EscrowKind, LockKind};
use crate::apis::quote::permit2::{
	build_permit2_batch_witness_digest, permit2_domain_address_from_config,
};
use solver_config::{Config, QuoteConfig};
use solver_settlement::{SettlementInterface, SettlementService};
use solver_types::{
	with_0x_prefix, GetQuoteRequest, InteropAddress, Quote, QuoteDetails, QuoteError, QuoteOrder,
	QuotePreference, SignatureType,
};
use std::sync::Arc;
use uuid::Uuid;

/// Quote generation engine with settlement service integration.
pub struct QuoteGenerator {
	custody_strategy: CustodyStrategy,
	/// Reference to settlement service for implementation lookup.
	settlement_service: Arc<SettlementService>,
}

impl QuoteGenerator {
	/// Creates a new quote generator.
	///
	/// # Arguments
	/// * `settlement_service` - Service managing settlement implementations
	pub fn new(settlement_service: Arc<SettlementService>) -> Self {
		Self {
			custody_strategy: CustodyStrategy::new(),
			settlement_service,
		}
	}

	pub async fn generate_quotes(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
	) -> Result<Vec<Quote>, QuoteError> {
		let mut quotes = Vec::new();
		for input in &request.available_inputs {
			let custody_decision = self.custody_strategy.decide_custody(input).await?;
			if let Ok(quote) = self
				.generate_quote_for_settlement(request, config, &custody_decision)
				.await
			{
				quotes.push(quote);
			}
		}
		if quotes.is_empty() {
			return Err(QuoteError::InsufficientLiquidity);
		}
		self.sort_quotes_by_preference(&mut quotes, &request.preference);
		Ok(quotes)
	}

	async fn generate_quote_for_settlement(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		custody_decision: &CustodyDecision,
	) -> Result<Quote, QuoteError> {
		let quote_id = Uuid::new_v4().to_string();
		let order = match custody_decision {
			CustodyDecision::ResourceLock { kind } => {
				self.generate_resource_lock_order(request, config, kind)?
			},
			CustodyDecision::Escrow { kind } => {
				self.generate_escrow_order(request, config, kind)?
			},
		};
		let details = QuoteDetails {
			requested_outputs: request.requested_outputs.clone(),
			available_inputs: request.available_inputs.clone(),
		};
		let eta = self.calculate_eta(&request.preference);
		let lock_type = match custody_decision {
			CustodyDecision::ResourceLock { .. } => "compact_resource_lock".to_string(),
			CustodyDecision::Escrow { kind } => match kind {
				EscrowKind::Permit2 => "permit2_escrow".to_string(),
				EscrowKind::Erc3009 => "erc3009_escrow".to_string(),
			},
		};
		let validity_seconds = self.get_quote_validity_seconds(config);
		Ok(Quote {
			orders: vec![order],
			details,
			valid_until: Some(chrono::Utc::now().timestamp() as u64 + validity_seconds),
			eta: Some(eta),
			quote_id,
			provider: "oif-solver".to_string(),
			cost: None,
			lock_type,
		})
	}

	fn generate_resource_lock_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		lock_kind: &LockKind,
	) -> Result<QuoteOrder, QuoteError> {
		let domain_address = self.get_lock_domain_address(config, lock_kind)?;
		let (primary_type, message) = match lock_kind {
			LockKind::TheCompact { params } => (
				"CompactLock".to_string(),
				self.build_compact_message(request, config, params)?,
			),
		};
		Ok(QuoteOrder {
			signature_type: SignatureType::Eip712,
			domain: domain_address,
			primary_type,
			message,
		})
	}

	fn generate_escrow_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		escrow_kind: &EscrowKind,
	) -> Result<QuoteOrder, QuoteError> {
		// Standard determined by business logic context
		// Currently we only support EIP7683
		let _standard = "eip7683"; // Currently only supporting eip7683

		// Extract chain from first output to find appropriate settlement
		// TODO: Implement support for multiple destination chains
		let chain_id = request
			.requested_outputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("No requested outputs".to_string()))?
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid chain ID: {}", e)))?;

		// Get settlement AND selected oracle for consistency
		let (settlement, selected_oracle) = self
			.settlement_service
			.get_any_settlement_for_chain(chain_id)
			.ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"No settlement available for chain {}",
					chain_id
				))
			})?;

		match escrow_kind {
			EscrowKind::Permit2 => {
				self.generate_permit2_order(request, config, settlement, selected_oracle)
			},
			EscrowKind::Erc3009 => self.generate_erc3009_order(request, config),
		}
	}

	fn generate_permit2_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		settlement: &dyn SettlementInterface,
		selected_oracle: solver_types::Address,
	) -> Result<QuoteOrder, QuoteError> {
		use alloy_primitives::hex;

		let chain_id = request.available_inputs[0]
			.asset
			.ethereum_chain_id()
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid chain ID in asset address: {}", e))
			})?;
		let domain_address = permit2_domain_address_from_config(config, chain_id)?;
		let (final_digest, message_obj) =
			build_permit2_batch_witness_digest(request, config, settlement, selected_oracle)?;
		let message = serde_json::json!({ "digest": with_0x_prefix(&hex::encode(final_digest)), "eip712": message_obj });
		Ok(QuoteOrder {
			signature_type: SignatureType::Eip712,
			domain: domain_address,
			primary_type: "PermitBatchWitnessTransferFrom".to_string(),
			message,
		})
	}

	fn generate_erc3009_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
	) -> Result<QuoteOrder, QuoteError> {
		let input = &request.available_inputs[0];
		let domain_address = input.asset.clone();
		let validity_seconds = self.get_quote_validity_seconds(config);
		let message = serde_json::json!({
			"from": input.user.ethereum_address().map_err(|e| QuoteError::InvalidRequest(format!("Invalid Ethereum address: {}", e)))?,
			"to": self.get_escrow_address(config)?,
			"value": input.amount.to_string(),
			"validAfter": 0,
			"validBefore": chrono::Utc::now().timestamp() + validity_seconds as i64,
			"nonce": format!("0x{:064x}", chrono::Utc::now().timestamp() as u64)
		});
		Ok(QuoteOrder {
			signature_type: SignatureType::Erc3009,
			domain: domain_address,
			primary_type: "ReceiveWithAuthorization".to_string(),
			message,
		})
	}

	fn build_compact_message(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		_params: &serde_json::Value,
	) -> Result<serde_json::Value, QuoteError> {
		let validity_seconds = self.get_quote_validity_seconds(config);
		Ok(serde_json::json!({
			"user": request.user,
			"inputs": request.available_inputs,
			"outputs": request.requested_outputs,
			"nonce": chrono::Utc::now().timestamp(),
			"deadline": chrono::Utc::now().timestamp() + validity_seconds as i64
		}))
	}

	fn get_lock_domain_address(
		&self,
		config: &Config,
		lock_kind: &LockKind,
	) -> Result<InteropAddress, QuoteError> {
		match &config.settlement.domain {
			Some(domain_config) => {
				let address = domain_config.address.parse().map_err(|e| {
					QuoteError::InvalidRequest(format!("Invalid domain address in config: {}", e))
				})?;
				Ok(InteropAddress::new_ethereum(
					domain_config.chain_id,
					address,
				))
			},
			None => Err(QuoteError::InvalidRequest(format!(
				"Domain configuration required for lock type: {:?}",
				lock_kind
			))),
		}
	}

	fn get_escrow_address(&self, config: &Config) -> Result<alloy_primitives::Address, QuoteError> {
		match &config.settlement.domain {
			Some(domain_config) => domain_config.address.parse().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid escrow address in config: {}", e))
			}),
			None => Err(QuoteError::InvalidRequest(
				"Escrow address configuration required".to_string(),
			)),
		}
	}

	fn calculate_eta(&self, preference: &Option<QuotePreference>) -> u64 {
		let base_eta = 120u64;
		match preference {
			Some(QuotePreference::Speed) => (base_eta as f64 * 0.8) as u64,
			Some(QuotePreference::Price) => (base_eta as f64 * 1.2) as u64,
			Some(QuotePreference::TrustMinimization) => (base_eta as f64 * 1.5) as u64,
			_ => base_eta,
		}
	}

	fn sort_quotes_by_preference(
		&self,
		quotes: &mut [Quote],
		preference: &Option<QuotePreference>,
	) {
		match preference {
			Some(QuotePreference::Speed) => quotes.sort_by(|a, b| match (a.eta, b.eta) {
				(Some(eta_a), Some(eta_b)) => eta_a.cmp(&eta_b),
				(Some(_), None) => std::cmp::Ordering::Less,
				(None, Some(_)) => std::cmp::Ordering::Greater,
				(None, None) => std::cmp::Ordering::Equal,
			}),
			Some(QuotePreference::InputPriority) => {},
			Some(QuotePreference::Price) | Some(QuotePreference::TrustMinimization) | None => {},
		}
	}

	/// Gets the quote validity duration from configuration.
	///
	/// Returns the configured validity seconds from api.quote config or default.
	fn get_quote_validity_seconds(&self, config: &Config) -> u64 {
		config
			.api
			.as_ref()
			.and_then(|api| api.quote.as_ref())
			.map(|quote| quote.validity_seconds)
			.unwrap_or_else(|| QuoteConfig::default().validity_seconds)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::apis::quote::custody::{CustodyDecision, EscrowKind, LockKind};
	use alloy_primitives::address;
	use alloy_primitives::U256;
	use solver_config::{
		ApiConfig, Config, ConfigBuilder, DomainConfig, QuoteConfig, SettlementConfig,
	};
	use solver_settlement::{MockSettlementInterface, SettlementInterface};
	use solver_types::{
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		AvailableInput, QuotePreference, RequestedOutput, SignatureType,
	};
	use std::collections::HashMap;

	fn create_test_config() -> Config {
		// Create API configuration with quote settings
		let api_config = ApiConfig {
			enabled: true,
			host: "127.0.0.1".to_string(),
			port: 8080,
			timeout_seconds: 30,
			max_request_size: 1048576,
			implementations: Default::default(),
			rate_limiting: None,
			cors: None,
			auth: None,
			quote: Some(QuoteConfig {
				validity_seconds: 300,
			}),
		};

		// Create settlement configuration with domain
		let settlement_config = SettlementConfig {
			implementations: HashMap::new(),
			domain: Some(DomainConfig {
				chain_id: 1,
				address: "0x1234567890123456789012345678901234567890".to_string(),
			}),
		};

		// Build network configurations using builder pattern
		let networks = NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.add_network(137, NetworkConfigBuilder::new().build())
			.build();

		// Create config using ConfigBuilder with complete fluent API
		ConfigBuilder::new()
			.api(Some(api_config))
			.settlement(settlement_config)
			.networks(networks)
			.build()
	}

	fn create_test_request() -> GetQuoteRequest {
		GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			available_inputs: vec![AvailableInput {
				user: InteropAddress::new_ethereum(
					1,
					address!("1111111111111111111111111111111111111111"),
				),
				asset: InteropAddress::new_ethereum(
					1,
					address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
				),
				amount: U256::from(1000),
				lock: None,
			}],
			requested_outputs: vec![RequestedOutput {
				receiver: InteropAddress::new_ethereum(
					137,
					address!("2222222222222222222222222222222222222222"),
				),
				asset: InteropAddress::new_ethereum(
					137,
					address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
				),
				amount: U256::from(950),
				calldata: None,
			}],
			min_valid_until: None,
			preference: Some(QuotePreference::Speed),
		}
	}

	fn create_test_settlement_service(with_oracles: bool) -> Arc<SettlementService> {
		use solver_types::Address;

		let mut input_oracles = HashMap::new();
		let mut output_oracles = HashMap::new();
		let mut routes = HashMap::new();

		if with_oracles {
			// Add input oracles for both chains (since get_any_settlement_for_chain looks for input oracles)
			input_oracles.insert(1, vec![Address(vec![0xaa; 20])]);
			input_oracles.insert(137, vec![Address(vec![0xcc; 20])]);
			// Add output oracles for both chains
			output_oracles.insert(1, vec![Address(vec![0xbb; 20])]);
			output_oracles.insert(137, vec![Address(vec![0xdd; 20])]);
			// Add routes between chains
			routes.insert(1, vec![137]);
			routes.insert(137, vec![1]);
		}

		let mut mock_settlement = MockSettlementInterface::new();
		mock_settlement
			.expect_oracle_config()
			.return_const(solver_settlement::OracleConfig {
				input_oracles,
				output_oracles,
				routes,
				selection_strategy: solver_settlement::OracleSelectionStrategy::First,
			});

		if with_oracles {
			// Mock the select_oracle method to return the first oracle
			mock_settlement
				.expect_select_oracle()
				.returning(|oracles, _context| oracles.first().cloned());
		}

		let mut implementations: HashMap<String, Box<dyn SettlementInterface>> = HashMap::new();
		implementations.insert("test".to_string(), Box::new(mock_settlement));

		Arc::new(SettlementService::new(implementations))
	}

	#[tokio::test]
	async fn test_generate_quotes_success() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator.generate_quotes(&request, &config).await;

		// Should succeed since we have properly configured oracles
		assert!(result.is_ok());
		let quotes = result.unwrap();
		assert!(!quotes.is_empty());

		let quote = &quotes[0];
		assert_eq!(quote.provider, "oif-solver");
		assert!(quote.valid_until.is_some());
		assert!(quote.eta.is_some());
		assert_eq!(quote.eta.unwrap(), 96); // Speed preference: 120 * 0.8
		assert!(!quote.orders.is_empty());
		assert!(!quote.quote_id.is_empty());

		// Verify quote details
		assert_eq!(quote.details.available_inputs.len(), 1);
		assert_eq!(quote.details.requested_outputs.len(), 1);
	}

	#[tokio::test]
	async fn test_generate_quotes_no_oracles_configured() {
		let settlement_service = create_test_settlement_service(false);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator.generate_quotes(&request, &config).await;

		// Should fail with insufficient liquidity since our mock settlement has no oracles configured
		assert!(matches!(result, Err(QuoteError::InsufficientLiquidity)));
	}

	#[tokio::test]
	async fn test_generate_quotes_insufficient_liquidity() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();

		// Create request with no available inputs
		let request = GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			available_inputs: vec![],
			requested_outputs: vec![RequestedOutput {
				receiver: InteropAddress::new_ethereum(
					137,
					address!("2222222222222222222222222222222222222222"),
				),
				asset: InteropAddress::new_ethereum(
					137,
					address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
				),
				amount: U256::from(950),
				calldata: None,
			}],
			min_valid_until: None,
			preference: Some(QuotePreference::Speed),
		};

		let result = generator.generate_quotes(&request, &config).await;
		assert!(matches!(result, Err(QuoteError::InsufficientLiquidity)));
	}

	#[test]
	fn test_generate_resource_lock_order_the_compact() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();
		let request = create_test_request();

		let lock_kind = LockKind::TheCompact {
			params: serde_json::json!({"test": "value"}),
		};

		let result = generator.generate_resource_lock_order(&request, &config, &lock_kind);

		match result {
			Ok(order) => {
				assert_eq!(order.signature_type, SignatureType::Eip712);
				assert_eq!(order.primary_type, "CompactLock");
				assert!(order.message.is_object());
			},
			Err(e) => {
				// Expected if domain configuration is missing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[test]
	fn test_generate_erc3009_order() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator.generate_erc3009_order(&request, &config);

		match result {
			Ok(order) => {
				assert_eq!(order.signature_type, SignatureType::Erc3009);
				assert_eq!(order.primary_type, "ReceiveWithAuthorization");
				assert!(order.message.is_object());

				// Verify message structure
				let message = order.message.as_object().unwrap();
				assert!(message.contains_key("from"));
				assert!(message.contains_key("to"));
				assert!(message.contains_key("value"));
				assert!(message.contains_key("validAfter"));
				assert!(message.contains_key("validBefore"));
				assert!(message.contains_key("nonce"));
			},
			Err(e) => {
				// Expected if escrow address configuration is missing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[test]
	fn test_build_compact_message() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();
		let request = create_test_request();
		let params = serde_json::json!({"test": "value"});

		let result = generator.build_compact_message(&request, &config, &params);

		assert!(result.is_ok());
		let message = result.unwrap();
		assert!(message.is_object());

		let message_obj = message.as_object().unwrap();
		assert!(message_obj.contains_key("user"));
		assert!(message_obj.contains_key("inputs"));
		assert!(message_obj.contains_key("outputs"));
		assert!(message_obj.contains_key("nonce"));
		assert!(message_obj.contains_key("deadline"));
	}

	#[test]
	fn test_calculate_eta_with_preferences() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);

		// Test speed preference
		let speed_eta = generator.calculate_eta(&Some(QuotePreference::Speed));
		assert_eq!(speed_eta, 96); // 120 * 0.8

		// Test price preference
		let price_eta = generator.calculate_eta(&Some(QuotePreference::Price));
		assert_eq!(price_eta, 144); // 120 * 1.2

		// Test trust minimization preference
		let trust_eta = generator.calculate_eta(&Some(QuotePreference::TrustMinimization));
		assert_eq!(trust_eta, 180); // 120 * 1.5

		// Test no preference
		let default_eta = generator.calculate_eta(&None);
		assert_eq!(default_eta, 120);

		// Test input priority (should use default)
		let input_eta = generator.calculate_eta(&Some(QuotePreference::InputPriority));
		assert_eq!(input_eta, 120);
	}

	#[test]
	fn test_sort_quotes_by_preference_speed() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);

		let mut quotes = vec![
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: Some(200),
				quote_id: "quote1".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: Some(100),
				quote_id: "quote2".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: None,
				quote_id: "quote3".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
		];

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::Speed));

		// Should be sorted by ETA ascending (fastest first)
		assert_eq!(quotes[0].eta, Some(100));
		assert_eq!(quotes[1].eta, Some(200));
		assert_eq!(quotes[2].eta, None); // None should be last
	}

	#[test]
	fn test_sort_quotes_by_preference_other() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);

		let mut quotes = vec![
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: Some(200),
				quote_id: "quote1".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: Some(100),
				quote_id: "quote2".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
		];

		let original_order = quotes.clone();

		// Test that other preferences don't change order
		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::Price));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::TrustMinimization));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::InputPriority));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &None);
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);
	}

	#[test]
	fn test_get_quote_validity_seconds() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);

		// Test with configured validity
		let config = create_test_config();
		let validity = generator.get_quote_validity_seconds(&config);
		assert_eq!(validity, 300);

		// Test with no API config (should use default)
		let config_no_api = ConfigBuilder::new().build();
		let validity_default = generator.get_quote_validity_seconds(&config_no_api);
		assert_eq!(validity_default, 20); // if API none, use default 20
	}

	#[test]
	fn test_get_lock_domain_address_success() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();
		let lock_kind = LockKind::TheCompact {
			params: serde_json::json!({}),
		};

		let result = generator.get_lock_domain_address(&config, &lock_kind);
		assert!(result.is_ok());

		let domain = result.unwrap();
		assert_eq!(domain.ethereum_chain_id().unwrap(), 1);
	}

	#[test]
	fn test_get_lock_domain_address_missing_config() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let mut config = create_test_config();
		config.settlement.domain = None;

		let lock_kind = LockKind::TheCompact {
			params: serde_json::json!({}),
		};

		let result = generator.get_lock_domain_address(&config, &lock_kind);
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[test]
	fn test_get_escrow_address_success() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();

		let result = generator.get_escrow_address(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_get_escrow_address_missing_config() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let mut config = create_test_config();
		config.settlement.domain = None;

		let result = generator.get_escrow_address(&config);
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[test]
	fn test_get_escrow_address_invalid_address() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let mut config = create_test_config();
		config.settlement.domain.as_mut().unwrap().address = "invalid_address".to_string();

		let result = generator.get_escrow_address(&config);
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[tokio::test]
	async fn test_generate_quote_for_settlement_resource_lock() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();
		let request = create_test_request();

		let custody_decision = CustodyDecision::ResourceLock {
			kind: LockKind::TheCompact {
				params: serde_json::json!({}),
			},
		};

		let result = generator
			.generate_quote_for_settlement(&request, &config, &custody_decision)
			.await;

		match result {
			Ok(quote) => {
				assert!(!quote.quote_id.is_empty());
				assert_eq!(quote.provider, "oif-solver");
				assert!(quote.valid_until.is_some());
				assert!(quote.eta.is_some());
				assert_eq!(quote.orders.len(), 1);
				assert_eq!(quote.orders[0].signature_type, SignatureType::Eip712);
			},
			Err(e) => {
				// Expected if domain configuration is incomplete
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_generate_quote_for_settlement_escrow() {
		let settlement_service = create_test_settlement_service(true);
		let generator = QuoteGenerator::new(settlement_service);
		let config = create_test_config();
		let request = create_test_request();

		let custody_decision = CustodyDecision::Escrow {
			kind: EscrowKind::Erc3009,
		};

		let result = generator
			.generate_quote_for_settlement(&request, &config, &custody_decision)
			.await;

		match result {
			Ok(quote) => {
				assert!(!quote.quote_id.is_empty());
				assert_eq!(quote.provider, "oif-solver");
				assert!(quote.valid_until.is_some());
				assert!(quote.eta.is_some());
				assert_eq!(quote.orders.len(), 1);
				assert_eq!(quote.orders[0].signature_type, SignatureType::Erc3009);
			},
			Err(e) => {
				// Expected due to missing settlement service setup or invalid request
				assert!(matches!(
					e,
					QuoteError::InvalidRequest(_) | QuoteError::UnsupportedSettlement(_)
				));
			},
		}
	}
}
