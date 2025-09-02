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
use solver_config::Config;
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
		let validity_seconds = self.get_quote_validity_seconds(config);
		Ok(Quote {
			orders: vec![order],
			details,
			valid_until: Some(chrono::Utc::now().timestamp() as u64 + validity_seconds),
			eta: Some(eta),
			quote_id,
			provider: "oif-solver".to_string(),
			cost: None,
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
	/// Returns the configured validity seconds from the quote config.
	fn get_quote_validity_seconds(&self, config: &Config) -> u64 {
		config
			.quote
			.as_ref()
			.unwrap_or(&Default::default())
			.validity_seconds
	}
}
