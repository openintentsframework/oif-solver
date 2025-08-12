//! Quote Generation Logic
//!
//! This module handles the generation of quote options based on validated requests
//! and settlement strategy decisions.

use solver_config::Config;
use solver_types::{
    GetQuoteRequest, InteropAddress, Quote, QuoteDetails, QuoteError, QuoteOrder, QuotePreference,
    SignatureType,
};

use uuid::Uuid;

use super::custody::{CustodyDecision, CustodyStrategy, EscrowKind, LockKind};

/// Quote generation engine
pub struct QuoteGenerator {
    custody_strategy: CustodyStrategy,
}

impl QuoteGenerator {
    /// Create new quote generator
    pub fn new() -> Self {
        Self {
            custody_strategy: CustodyStrategy::new(),
        }
    }

    /// Generate quotes for the given request
    pub async fn generate_quotes(
        &self,
        request: &GetQuoteRequest,
        config: &Config,
    ) -> Result<Vec<Quote>, QuoteError> {
        let mut quotes = Vec::new();

        // For each available input, determine settlement strategy and generate quotes
        for input in &request.available_inputs {
            let settlement_decision = self.custody_strategy.decide_custody(input).await?;
            
            tracing::info!("Settlement decision: {:?}", settlement_decision);

            if let Ok(quote) = self.generate_quote_for_settlement(
                request, 
                config, 
                &settlement_decision
            ).await {
                quotes.push(quote);
            }
        }

        if quotes.is_empty() {
            return Err(QuoteError::InsufficientLiquidity);
        }

        // Sort quotes based on user preference
        self.sort_quotes_by_preference(&mut quotes, &request.preference);

        Ok(quotes)
    }

    /// Generate a quote for a specific settlement strategy
    async fn generate_quote_for_settlement(
        &self,
        request: &GetQuoteRequest,
        config: &Config,
        settlement_decision: &CustodyDecision,
    ) -> Result<Quote, QuoteError> {
        let quote_id = Uuid::new_v4().to_string();

        // Generate the appropriate order based on settlement type
        let order = match settlement_decision {
            CustodyDecision::ResourceLock { kind } => {
                self.generate_resource_lock_order(request, config, kind)?
            }
            CustodyDecision::Escrow { kind } => {
                self.generate_escrow_order(request, config, kind)?
            }
        };

        // Create quote details
        let details = QuoteDetails {
            requested_outputs: request.requested_outputs.clone(),
            available_inputs: request.available_inputs.clone(),
        };

        // Calculate estimated timing
        let eta = self.calculate_eta(&request.preference);

        Ok(Quote {
            orders: vec![order],
            details,
            valid_until: Some(chrono::Utc::now().timestamp() as u64 + 300), // 5 minutes validity
            eta: Some(eta),
            quote_id,
            provider: "oif-solver".to_string(),
        })
    }

    /// Generate order for resource lock settlement
    fn generate_resource_lock_order(
        &self,
        request: &GetQuoteRequest,
        config: &Config,
        lock_kind: &LockKind,
    ) -> Result<QuoteOrder, QuoteError> {
        let domain_address = self.get_lock_domain_address(config, lock_kind)?;

        let (primary_type, message) = match lock_kind {
            LockKind::TheCompact { params } => {
                ("CompactLock".to_string(), self.build_compact_message(request, params)?)
            }
        };

        Ok(QuoteOrder {
            signature_type: SignatureType::Eip712,
            domain: domain_address,
            primary_type,
            message,
        })
    }

    /// Generate order for escrow settlement
    fn generate_escrow_order(
        &self,
        request: &GetQuoteRequest,
        config: &Config,
        escrow_kind: &EscrowKind,
    ) -> Result<QuoteOrder, QuoteError> {
        match escrow_kind {
            EscrowKind::Permit2 => self.generate_permit2_order(request, config),
            EscrowKind::Erc3009 => self.generate_erc3009_order(request, config),
        }
    }

    /// Generate Permit2 SignatureTransfer order
    fn generate_permit2_order(
        &self,
        request: &GetQuoteRequest,
        config: &Config,
    ) -> Result<QuoteOrder, QuoteError> {
        // Get Permit2 domain address for the chain
        let chain_id = request.available_inputs[0].asset.ethereum_chain_id().map_err(|e| {
            QuoteError::InvalidRequest(format!("Invalid chain ID in asset address: {}", e))
        })?;
        let permit2_address = self.get_permit2_address(chain_id)?;
        let domain_address = InteropAddress::new_ethereum(chain_id, permit2_address);

        // Build Permit2 SignatureTransfer message
        let message = serde_json::json!({
            "permitted": {
                "token": request.available_inputs[0].asset.ethereum_address().map_err(|e| {
                    QuoteError::InvalidRequest(format!("Invalid Ethereum address: {}", e))
                })?,
                "amount": request.available_inputs[0].amount.to_string()
            },
            "spender": self.get_escrow_address(config)?,
            "nonce": chrono::Utc::now().timestamp(),
            "deadline": chrono::Utc::now().timestamp() + 300
        });

        Ok(QuoteOrder {
            signature_type: SignatureType::Eip712,
            domain: domain_address,
            primary_type: "PermitTransferFrom".to_string(),
            message,
        })
    }

    /// Generate ERC-3009 order
    fn generate_erc3009_order(
        &self,
        request: &GetQuoteRequest,
        config: &Config,
    ) -> Result<QuoteOrder, QuoteError> {
        let input = &request.available_inputs[0];
        let domain_address = input.asset.clone(); // Token itself is the domain

        // Build ERC-3009 ReceiveWithAuthorization message
        let message = serde_json::json!({
            "from": input.user.ethereum_address().map_err(|e| {
                QuoteError::InvalidRequest(format!("Invalid Ethereum address: {}", e))
            })?,
            "to": self.get_escrow_address(config)?,
            "value": input.amount.to_string(),
            "validAfter": 0,
            "validBefore": chrono::Utc::now().timestamp() + 300,
            "nonce": format!("0x{:064x}", chrono::Utc::now().timestamp() as u64) // Use timestamp as nonce
        });

        Ok(QuoteOrder {
            signature_type: SignatureType::Erc3009,
            domain: domain_address,
            primary_type: "ReceiveWithAuthorization".to_string(),
            message,
        })
    }

    /// Build message for The Compact lock
    fn build_compact_message(
        &self,
        request: &GetQuoteRequest,
        _params: &serde_json::Value,
    ) -> Result<serde_json::Value, QuoteError> {
        Ok(serde_json::json!({
            "user": request.user,
            "inputs": request.available_inputs,
            "outputs": request.requested_outputs,
            "nonce": chrono::Utc::now().timestamp(),
            "deadline": chrono::Utc::now().timestamp() + 300
        }))
    }



    /// Get domain address for lock-based settlements
    fn get_lock_domain_address(
        &self,
        config: &Config,
        lock_kind: &LockKind,
    ) -> Result<InteropAddress, QuoteError> {
        // For now, use the settlement domain from config
        // In a real implementation, this would be specific to the lock protocol
        match &config.settlement.domain {
            Some(domain_config) => {
                let address = domain_config.address.parse().map_err(|e| {
                    QuoteError::InvalidRequest(format!("Invalid domain address in config: {}", e))
                })?;
                Ok(InteropAddress::new_ethereum(domain_config.chain_id, address))
            }
            None => Err(QuoteError::InvalidRequest(
                format!("Domain configuration required for lock type: {:?}", lock_kind)
            ))
        }
    }

    /// Get Permit2 contract address for chain
    fn get_permit2_address(&self, chain_id: u64) -> Result<alloy_primitives::Address, QuoteError> {
        // Permit2 is deployed at the same address across all major chains
        "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            .parse()
            .map_err(|_| QuoteError::InvalidRequest(
                format!("Permit2 not available on chain {}", chain_id)
            ))
    }

    /// Get escrow contract address from config
    fn get_escrow_address(&self, config: &Config) -> Result<alloy_primitives::Address, QuoteError> {
        match &config.settlement.domain {
            Some(domain_config) => {
                domain_config.address.parse().map_err(|e| {
                    QuoteError::InvalidRequest(format!("Invalid escrow address in config: {}", e))
                })
            }
            None => Err(QuoteError::InvalidRequest(
                "Escrow address configuration required".to_string()
            ))
        }
    }

    /// Calculate estimated time to completion based on preference
    fn calculate_eta(&self, preference: &Option<QuotePreference>) -> u64 {
        // Base ETA of 2 minutes
        let base_eta = 120;

        // Adjust based on preference
        match preference {
            Some(QuotePreference::Speed) => (base_eta as f64 * 0.8) as u64, // Faster
            Some(QuotePreference::Price) => (base_eta as f64 * 1.2) as u64, // Slower but cheaper
            Some(QuotePreference::TrustMinimization) => (base_eta as f64 * 1.5) as u64, // Slower for security
            _ => base_eta, // Default
        }
    }

    /// Sort quotes based on user preference
    fn sort_quotes_by_preference(&self, quotes: &mut [Quote], preference: &Option<QuotePreference>) {
        match preference {
            Some(QuotePreference::Speed) => {
                // Sort by fastest ETA first
                quotes.sort_by(|a, b| match (a.eta, b.eta) {
                    (Some(eta_a), Some(eta_b)) => eta_a.cmp(&eta_b),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                });
            }
            Some(QuotePreference::InputPriority) => {
                // Maintain original order based on input sequence
                // This respects the significance of input order mentioned in UII spec
            }
            Some(QuotePreference::Price) | Some(QuotePreference::TrustMinimization) | None => {
                // For now, maintain original order
                // In real implementation, would sort by calculated cost/trust metrics
            }
        }
    }
}

impl Default for QuoteGenerator {
    fn default() -> Self {
        Self::new()
    }
}