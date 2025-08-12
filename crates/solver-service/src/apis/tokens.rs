//! Token information API for the OIF Solver.
//!
//! This module provides endpoints to query supported tokens and networks
//! configured in the solver.

use alloy_primitives::hex;
use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use serde::Serialize;
use solver_core::SolverEngine;
use solver_types::with_0x_prefix;
use std::collections::HashMap;
use std::sync::Arc;

/// Response structure for all supported tokens across all networks.
#[derive(Debug, Serialize)]
pub struct TokensResponse {
	/// Map of chain ID (as string) to network token information.
	pub networks: HashMap<String, NetworkTokens>,
}

/// Token information for a specific network.
#[derive(Debug, Serialize)]
pub struct NetworkTokens {
	/// The blockchain network ID.
	pub chain_id: u64,
	/// Input settler contract address.
	pub input_settler: String,
	/// Output settler contract address.
	pub output_settler: String,
	/// List of supported tokens on this network.
	pub tokens: Vec<TokenInfo>,
}

/// Information about a specific token.
#[derive(Debug, Serialize)]
pub struct TokenInfo {
	/// Token contract address.
	pub address: String,
	/// Token symbol (e.g., "USDC", "USDT").
	pub symbol: String,
	/// Number of decimal places for the token.
	pub decimals: u8,
}

/// Handles GET /api/tokens requests.
///
/// Returns all supported tokens across all configured networks.
pub async fn get_tokens(State(solver): State<Arc<SolverEngine>>) -> Json<TokensResponse> {
	let networks = solver.token_manager().get_networks();

	let mut response = TokensResponse {
		networks: HashMap::new(),
	};

	for (chain_id, network) in networks {
		response.networks.insert(
			chain_id.to_string(),
			NetworkTokens {
				chain_id: *chain_id,
				input_settler: with_0x_prefix(&hex::encode(&network.input_settler_address.0)),
				output_settler: with_0x_prefix(&hex::encode(&network.output_settler_address.0)),
				tokens: network
					.tokens
					.iter()
					.map(|t| TokenInfo {
						address: with_0x_prefix(&hex::encode(&t.address.0)),
						symbol: t.symbol.clone(),
						decimals: t.decimals,
					})
					.collect(),
			},
		);
	}

	Json(response)
}

/// Handles GET /api/tokens/{chain_id} requests.
///
/// Returns supported tokens for a specific chain.
pub async fn get_tokens_for_chain(
	Path(chain_id): Path<u64>,
	State(solver): State<Arc<SolverEngine>>,
) -> Result<Json<NetworkTokens>, StatusCode> {
	let networks = solver.token_manager().get_networks();

	match networks.get(&chain_id) {
		Some(network) => Ok(Json(NetworkTokens {
			chain_id,
			input_settler: with_0x_prefix(&hex::encode(&network.input_settler_address.0)),
			output_settler: with_0x_prefix(&hex::encode(&network.output_settler_address.0)),
			tokens: network
				.tokens
				.iter()
				.map(|t| TokenInfo {
					address: with_0x_prefix(&hex::encode(&t.address.0)),
					symbol: t.symbol.clone(),
					decimals: t.decimals,
				})
				.collect(),
		})),
		None => Err(StatusCode::NOT_FOUND),
	}
}
