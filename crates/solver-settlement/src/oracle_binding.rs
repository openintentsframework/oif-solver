//! Shared helpers for decoding order-bound oracle addresses from the canonical
//! EIP-7683 order data. Moved from broadcaster.rs to be shared across all
//! settlement implementations (broadcaster, direct, hyperlane).

use crate::SettlementError;
use solver_types::{bytes32_to_address, parse_address, Address, Eip7683OrderData, Order};

fn parse_eip7683_order_data(order: &Order) -> Result<Eip7683OrderData, SettlementError> {
	if order.standard != "eip7683" {
		return Err(SettlementError::ValidationFailed(format!(
			"Settlement only supports eip7683 orders, got '{}'",
			order.standard
		)));
	}
	serde_json::from_value(order.data.clone()).map_err(|e| {
		SettlementError::ValidationFailed(format!("Failed to parse eip7683 order data: {e}"))
	})
}

/// Parse the order-bound input oracle from canonical `Order.data`.
pub(crate) fn parse_bound_input_oracle(order: &Order) -> Result<Address, SettlementError> {
	let order_data = parse_eip7683_order_data(order)?;
	parse_address(&order_data.input_oracle).map_err(|e| {
		SettlementError::ValidationFailed(format!("Invalid order-bound input oracle: {e}"))
	})
}

/// Parse the order-bound output oracle for the given destination chain.
pub(crate) fn parse_bound_output_oracle(
	order: &Order,
	destination_chain: u64,
) -> Result<Address, SettlementError> {
	let order_data = parse_eip7683_order_data(order)?;
	let output = order_data
		.outputs
		.iter()
		.find(|output| output.chain_id.to::<u64>() == destination_chain)
		.ok_or_else(|| {
			SettlementError::ValidationFailed(format!(
				"No order output found for destination chain {destination_chain}"
			))
		})?;

	if output.oracle == [0u8; 32] {
		return Err(SettlementError::ValidationFailed(format!(
			"Order output oracle is zero for destination chain {destination_chain}; \
			 order-bound output oracle is required"
		)));
	}

	let oracle_hex = bytes32_to_address(&output.oracle);
	parse_address(&oracle_hex).map_err(|e| {
		SettlementError::ValidationFailed(format!("Invalid order-bound output oracle: {e}"))
	})
}
