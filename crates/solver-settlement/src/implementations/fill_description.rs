use crate::SettlementError;
use alloy_primitives::U256;
use alloy_sol_types::SolEvent;
use sha3::{Digest, Keccak256};
use solver_types::{
	standards::eip7683::{interfaces::OutputFilled, MandateOutput},
	Address, Log, Order,
};

#[derive(Debug, Clone)]
pub(crate) struct VerifiedFill {
	pub solver_identifier: [u8; 32],
	pub timestamp: u32,
	pub output: MandateOutput,
}

/// Extract a verified fill from OutputFilled logs.
///
/// The accepted log must be emitted by the order's destination settler, reference
/// the target order id, and carry the exact MandateOutput signed in the order.
pub(crate) fn extract_verified_fill_from_logs(
	logs: &[Log],
	order: &Order,
	order_id: [u8; 32],
	dest_chain: u64,
) -> Result<VerifiedFill, SettlementError> {
	let order_data: solver_types::standards::eip7683::Eip7683OrderData =
		serde_json::from_value(order.data.clone()).map_err(|e| {
			SettlementError::ValidationFailed(format!("Failed to parse order_data: {e}"))
		})?;

	let matched: Vec<&MandateOutput> = order_data
		.outputs
		.iter()
		.filter(|o| o.chain_id == U256::from(dest_chain))
		.collect();
	if matched.is_empty() {
		return Err(SettlementError::ValidationFailed(format!(
			"Order has no output on destination chain {dest_chain}"
		)));
	}
	if matched.len() > 1 {
		return Err(SettlementError::ValidationFailed(format!(
			"Order has multiple outputs on destination chain {dest_chain}; unsupported"
		)));
	}
	let expected_output = matched[0];

	if expected_output.settler[0..12].iter().any(|b| *b != 0) {
		return Err(SettlementError::ValidationFailed(
			"Order output settler is not a left-padded EVM address".to_string(),
		));
	}
	let mut expected_addr = [0u8; 20];
	expected_addr.copy_from_slice(&expected_output.settler[12..32]);
	let expected_emitter = Address(expected_addr.to_vec());

	for log in logs {
		if log.address != expected_emitter {
			continue;
		}
		if log.topics.len() < 2 {
			continue;
		}
		if log.topics[0].0 != OutputFilled::SIGNATURE_HASH.0 {
			continue;
		}
		if log.topics[1].0 != order_id {
			continue;
		}

		match <OutputFilled as SolEvent>::abi_decode_data_validate(&log.data) {
			Ok((solver_b32, timestamp, sol_output, final_amount)) => {
				let oracle_match = sol_output.oracle.0 == expected_output.oracle;
				let settler_match = sol_output.settler.0 == expected_output.settler;
				let chain_match = sol_output.chainId == expected_output.chain_id;
				let token_match = sol_output.token.0 == expected_output.token;
				let amount_match = sol_output.amount == expected_output.amount;
				let recipient_match = sol_output.recipient.0 == expected_output.recipient;
				let call_match =
					sol_output.callbackData.as_ref() == expected_output.call.as_slice();
				let context_match =
					sol_output.context.as_ref() == expected_output.context.as_slice();

				if oracle_match
					&& settler_match
					&& chain_match && token_match
					&& amount_match && recipient_match
					&& call_match && context_match
				{
					if final_amount != sol_output.amount {
						tracing::warn!(
							order_id = %order.id,
							log_emitter = %log.address,
							expected = %sol_output.amount,
							actual = %final_amount,
							"OutputFilled finalAmount diverged from MandateOutput.amount; skipping log",
						);
						continue;
					}

					return Ok(VerifiedFill {
						solver_identifier: solver_b32.0,
						timestamp,
						output: sol_output.into(),
					});
				}
			},
			Err(e) => {
				tracing::warn!(
					error = %e,
					log_emitter = %log.address,
					"OutputFilled ABI decode failed; skipping log",
				);
			},
		}
	}

	Err(SettlementError::ValidationFailed(
		"no matching OutputFilled log emitted by expected settler".to_string(),
	))
}

/// Encode FillDescription according to MandateOutputEncodingLib.
///
/// Layout:
/// - solver (32 bytes)
/// - orderId (32 bytes)
/// - timestamp (4 bytes)
/// - token (32 bytes)
/// - amount (32 bytes)
/// - recipient (32 bytes)
/// - call length (2 bytes) + call data
/// - context length (2 bytes) + context data
pub(crate) fn encode_fill_description(
	fill: &VerifiedFill,
	order_id: [u8; 32],
) -> Result<Vec<u8>, SettlementError> {
	if fill.output.call.len() > u16::MAX as usize {
		return Err(SettlementError::ValidationFailed(
			"Call data too large".into(),
		));
	}
	if fill.output.context.len() > u16::MAX as usize {
		return Err(SettlementError::ValidationFailed(
			"Context data too large".into(),
		));
	}

	let mut payload = Vec::with_capacity(
		32 + 32 + 4 + 32 + 32 + 32 + 2 + fill.output.call.len() + 2 + fill.output.context.len(),
	);
	payload.extend_from_slice(&fill.solver_identifier);
	payload.extend_from_slice(&order_id);
	payload.extend_from_slice(&fill.timestamp.to_be_bytes());
	payload.extend_from_slice(&fill.output.token);
	payload.extend_from_slice(&fill.output.amount.to_be_bytes::<32>());
	payload.extend_from_slice(&fill.output.recipient);
	payload.extend_from_slice(&(fill.output.call.len() as u16).to_be_bytes());
	payload.extend_from_slice(&fill.output.call);
	payload.extend_from_slice(&(fill.output.context.len() as u16).to_be_bytes());
	payload.extend_from_slice(&fill.output.context);
	Ok(payload)
}

pub(crate) fn payload_hash(
	fill: &VerifiedFill,
	order_id: [u8; 32],
) -> Result<[u8; 32], SettlementError> {
	let payload = encode_fill_description(fill, order_id)?;
	let mut hasher = Keccak256::new();
	hasher.update(&payload);
	Ok(hasher.finalize().into())
}
