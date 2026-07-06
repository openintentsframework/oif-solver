use alloy_primitives::{Bytes, U256};
use alloy_sol_types::{sol, SolCall};
use solver_types::Transaction as SolverTransaction;

const SYNTHETIC_SIGNATURE_BYTES: usize = 65;

sol! {
	interface IGasPriceOracle {
		function getL1Fee(bytes memory _data) external view returns (uint256);
	}
}

#[derive(Debug, thiserror::Error)]
pub enum OpStackFeeError {
	#[error("OP Stack L1 data fee estimation requires gas_limit")]
	MissingGasLimit,
	#[error("OP Stack L1 data fee estimation requires gas_price or max_fee_per_gas")]
	MissingFeePerGas,
	#[error("OP Stack GasPriceOracle returned invalid getL1Fee data: {0}")]
	InvalidOracleReturn(String),
}

pub fn encode_get_l1_fee_call(tx_bytes: Bytes) -> Bytes {
	IGasPriceOracle::getL1FeeCall { _data: tx_bytes }
		.abi_encode()
		.into()
}

pub fn decode_get_l1_fee_return(output: &Bytes) -> Result<U256, OpStackFeeError> {
	IGasPriceOracle::getL1FeeCall::abi_decode_returns(output)
		.map_err(|err| OpStackFeeError::InvalidOracleReturn(err.to_string()))
}

pub fn synthetic_signed_transaction_bytes(
	tx: &SolverTransaction,
) -> Result<Bytes, OpStackFeeError> {
	let gas_limit = tx.gas_limit.ok_or(OpStackFeeError::MissingGasLimit)?;
	let fee_per_gas = tx
		.max_fee_per_gas
		.or(tx.gas_price)
		.ok_or(OpStackFeeError::MissingFeePerGas)?;
	let nonce = tx.nonce.unwrap_or(0);
	let tx_type = if tx.max_fee_per_gas.is_some() {
		0x02
	} else {
		0x01
	};

	let mut out = Vec::with_capacity(1 + 8 + 8 + 16 + 8 + 20 + 32 + tx.data.len() + 65);
	out.push(tx_type);
	out.extend_from_slice(&tx.chain_id.to_be_bytes());
	out.extend_from_slice(&nonce.to_be_bytes());
	out.extend_from_slice(&fee_per_gas.to_be_bytes());
	out.extend_from_slice(&gas_limit.to_be_bytes());
	if let Some(to) = &tx.to {
		out.extend_from_slice(&to.0);
	} else {
		out.extend_from_slice(&[0_u8; 20]);
	}
	out.extend_from_slice(&tx.value.to_be_bytes::<32>());
	out.extend_from_slice(&tx.data);
	out.extend(std::iter::repeat_n(0xff, SYNTHETIC_SIGNATURE_BYTES));

	Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_types::Address;

	fn tx_with_data(data: Vec<u8>) -> SolverTransaction {
		SolverTransaction {
			to: Some(Address(vec![0x11; 20])),
			data,
			value: U256::from(7_u64),
			chain_id: 8453,
			nonce: Some(3),
			gas_limit: Some(120_000),
			gas_price: None,
			max_fee_per_gas: Some(1_000_000_000),
			max_priority_fee_per_gas: Some(10_000_000),
		}
	}

	#[test]
	fn synthetic_signed_transaction_bytes_are_non_empty() {
		let encoded = synthetic_signed_transaction_bytes(&tx_with_data(vec![0xab, 0xcd]))
			.expect("synthetic bytes");

		assert!(!encoded.is_empty());
		assert!(encoded.len() > SYNTHETIC_SIGNATURE_BYTES);
	}

	#[test]
	fn synthetic_signed_transaction_bytes_change_with_calldata() {
		let first = synthetic_signed_transaction_bytes(&tx_with_data(vec![0xab, 0xcd]))
			.expect("first synthetic bytes");
		let second = synthetic_signed_transaction_bytes(&tx_with_data(vec![0xab, 0xce]))
			.expect("second synthetic bytes");

		assert_ne!(first, second);
	}

	#[test]
	fn synthetic_signed_transaction_bytes_marks_legacy_transactions() {
		let mut tx = tx_with_data(vec![0xab]);
		tx.max_fee_per_gas = None;
		tx.max_priority_fee_per_gas = None;
		tx.gas_price = Some(1_000_000_000);

		let encoded = synthetic_signed_transaction_bytes(&tx).expect("synthetic bytes");

		assert_eq!(encoded[0], 0x01);
	}

	#[test]
	fn synthetic_signed_transaction_bytes_uses_zero_to_for_contract_creation() {
		let mut tx = tx_with_data(vec![0xab]);
		tx.to = None;

		let encoded = synthetic_signed_transaction_bytes(&tx).expect("synthetic bytes");
		let to_offset = 1 + 8 + 8 + 16 + 8;

		assert_eq!(&encoded[to_offset..to_offset + 20], &[0_u8; 20]);
	}

	#[test]
	fn get_l1_fee_call_data_is_non_empty() {
		let call = encode_get_l1_fee_call(Bytes::from(vec![0x02, 0xff]));

		assert!(!call.is_empty());
	}
}
