use alloy_primitives::{hex, Address as AlloyAddress, U256};
use alloy_sol_types::SolCall;
use solver_config::Config;
use solver_core::SolverEngine;
use solver_types::{
	standards::eip7683::{interfaces::StandardOrder, LockType},
	APIError, ApiErrorType,
};
use std::convert::TryFrom;

mod interfaces {
	use alloy_sol_types::sol;

	sol! {
		function balanceOf(address owner, uint256 id) external view returns (uint256);
	}
}

pub async fn ensure_user_capacity_for_order(
	solver: &SolverEngine,
	config: &Config,
	lock_type: LockType,
	standard_order: &StandardOrder,
) -> Result<(), APIError> {
	let origin_chain_id: u64 =
		u64::try_from(standard_order.originChainId).map_err(|_| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: "Origin chain ID missing or invalid in order".to_string(),
			details: None,
		})?;

	let user = &standard_order.user;

	match lock_type {
		LockType::ResourceLock => {
			for input in &standard_order.inputs {
				let token_id = input[0];
				let amount = input[1];
				if amount.is_zero() {
					continue;
				}
				validate_compact_deposit_for_order(
					solver,
					config,
					origin_chain_id,
					user,
					token_id,
					amount,
				)
				.await?;
			}
		},
		_ => {
			for input in &standard_order.inputs {
				let token_field = input[0];
				let amount = input[1];
				if amount.is_zero() {
					continue;
				}

				let token_bytes = token_field.to_be_bytes::<32>();
				let token_address = AlloyAddress::from_slice(&token_bytes[12..]);

				validate_wallet_balance_for_order(
					solver,
					origin_chain_id,
					user,
					&token_address,
					amount,
				)
				.await?;
			}
		},
	}

	Ok(())
}

async fn validate_wallet_balance_for_order(
	solver: &SolverEngine,
	chain_id: u64,
	user: &AlloyAddress,
	token: &AlloyAddress,
	required_amount: U256,
) -> Result<(), APIError> {
	let user_hex = hex::encode(user.as_slice());
	let token_hex = hex::encode(token.as_slice());

	let balance_str = solver
		.delivery()
		.get_balance(chain_id, &user_hex, Some(&token_hex))
		.await
		.map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to fetch user balance: {}", e),
			details: None,
		})?;

	let balance = U256::from_str_radix(&balance_str, 10).map_err(|e| APIError::BadRequest {
		error_type: ApiErrorType::OrderValidationFailed,
		message: format!("Failed to parse user balance '{}': {}", balance_str, e),
		details: None,
	})?;

	if balance < required_amount {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!(
				"User {:#x} has insufficient balance for token {:#x} on chain {} (required {}, available {})",
				user,
				token,
				chain_id,
				required_amount,
				balance,
			),
			details: None,
		});
	}

	Ok(())
}

async fn validate_compact_deposit_for_order(
	solver: &SolverEngine,
	config: &Config,
	chain_id: u64,
	user: &AlloyAddress,
	token_id: U256,
	required_amount: U256,
) -> Result<(), APIError> {
	let network = config
		.networks
		.get(&chain_id)
		.ok_or_else(|| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Network {} not configured for solver", chain_id),
			details: None,
		})?;

	let compact_address =
		network
			.the_compact_address
			.as_ref()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("TheCompact address not configured for chain {}", chain_id),
				details: None,
			})?;

	let call_data = interfaces::balanceOfCall {
		owner: *user,
		id: token_id,
	}
	.abi_encode();

	let tx = solver_types::Transaction {
		to: Some(compact_address.clone()),
		data: call_data,
		value: U256::ZERO,
		chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	};

	let response = solver
		.delivery()
		.contract_call(chain_id, tx)
		.await
		.map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to query TheCompact deposit: {}", e),
			details: None,
		})?;

	if response.len() != 32 {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!(
				"Unexpected TheCompact balanceOf response length: expected 32 bytes, got {}",
				response.len()
			),
			details: None,
		});
	}

	let mut balance_buf = [0u8; 32];
	balance_buf.copy_from_slice(response.as_ref());
	let balance = U256::from_be_bytes(balance_buf);

	if balance < required_amount {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!(
				"Compact deposit for user {:#x} is insufficient on chain {} (required {}, available {})",
				user,
				chain_id,
				required_amount,
				balance,
			),
			details: None,
		});
	}

	Ok(())
}
