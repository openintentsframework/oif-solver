//! Rebuild transient intent data from persisted orders.
//!
//! Deferred orders and startup recovery persist the accepted `Order`, not the
//! original discovery event. Retrying the strategy or off-chain prepare path
//! needs the subset of `Intent` fields that can be reconstructed from the
//! persisted EIP-7683 order data.

use alloy_primitives::hex;
use solver_types::{
	standards::eip7683::Eip7683OrderData, without_0x_prefix, Intent, IntentMetadata, Order,
};

pub(crate) fn intent_from_order(order: &Order) -> Option<Intent> {
	let order_data: Eip7683OrderData = serde_json::from_value(order.data.clone()).ok()?;
	let raw_order_data = order_data.raw_order_data.as_ref()?;
	let lock_type = order_data.lock_type?;
	let order_bytes =
		alloy_primitives::Bytes::from(hex::decode(without_0x_prefix(raw_order_data)).ok()?);

	Some(Intent {
		id: order.id.clone(),
		source: "off-chain".to_string(),
		standard: order.standard.clone(),
		metadata: IntentMetadata {
			requires_auction: false,
			exclusive_until: None,
			discovered_at: solver_types::current_timestamp(),
		},
		data: order.data.clone(),
		order_bytes,
		quote_id: order.quote_id.clone(),
		lock_type: lock_type.to_string(),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_types::{
		standards::eip7683::LockType,
		utils::tests::builders::{Eip7683OrderDataBuilder, OrderBuilder},
	};

	fn order_with_data(order_data: Eip7683OrderData) -> Order {
		OrderBuilder::new()
			.with_id("0x1111111111111111111111111111111111111111111111111111111111111111")
			.with_data(serde_json::to_value(order_data).unwrap())
			.build()
	}

	#[test]
	fn intent_from_order_rehydrates_offchain_intent_fields() {
		let order_data = Eip7683OrderDataBuilder::new()
			.lock_type(LockType::Permit2Escrow)
			.raw_order_data("0x1234")
			.build();
		let order = order_with_data(order_data);

		let intent = intent_from_order(&order).expect("intent should be rehydrated");

		assert_eq!(intent.id, order.id);
		assert_eq!(intent.source, "off-chain");
		assert_eq!(intent.standard, order.standard);
		assert_eq!(intent.order_bytes.as_ref(), &[0x12, 0x34]);
		assert_eq!(intent.lock_type, LockType::Permit2Escrow.to_string());
	}

	#[test]
	fn intent_from_order_requires_raw_order_data() {
		let order_data = Eip7683OrderDataBuilder::new()
			.lock_type(LockType::Permit2Escrow)
			.build();
		let order = order_with_data(order_data);

		assert!(intent_from_order(&order).is_none());
	}

	#[test]
	fn intent_from_order_requires_lock_type() {
		let order_data = Eip7683OrderDataBuilder::new()
			.raw_order_data("0x1234")
			.build();
		let order = order_with_data(order_data);

		assert!(intent_from_order(&order).is_none());
	}
}
