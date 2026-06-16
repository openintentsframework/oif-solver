use solver_types::{
	standards::eip7683::{Eip7683OrderData, LockType},
	Order,
};

pub(crate) fn order_requires_preparation(order: &Order) -> bool {
	if order.standard != "eip7683" {
		return false;
	}

	let Ok(order_data) = serde_json::from_value::<Eip7683OrderData>(order.data.clone()) else {
		return false;
	};

	let escrow_lock = matches!(
		order_data.lock_type,
		Some(LockType::Permit2Escrow | LockType::Eip3009Escrow)
	);

	escrow_lock
		&& order_data.raw_order_data.is_some()
		&& order_data.sponsor.is_some()
		&& order_data.signature.is_some()
}

#[cfg(test)]
mod tests {
	use super::order_requires_preparation;
	use solver_types::{
		standards::eip7683::LockType,
		utils::tests::builders::{Eip7683OrderDataBuilder, OrderBuilder},
	};

	fn order_with_data(data: serde_json::Value) -> solver_types::Order {
		OrderBuilder::new().with_data(data).build()
	}

	fn eip7683_data(
		lock_type: LockType,
		raw: bool,
		sponsor: bool,
		signature: bool,
	) -> serde_json::Value {
		let mut builder = Eip7683OrderDataBuilder::new().lock_type(lock_type);
		if raw {
			builder = builder.raw_order_data("0x1234");
		}
		if sponsor {
			builder = builder.sponsor("0x1111111111111111111111111111111111111111");
		}
		if signature {
			builder = builder.signature("0xabcdef");
		}
		serde_json::to_value(builder.build()).expect("serialize order data")
	}

	#[test]
	fn offchain_escrow_shape_requires_prepare() {
		let order = order_with_data(eip7683_data(LockType::Permit2Escrow, true, true, true));

		assert!(order_requires_preparation(&order));
	}

	#[test]
	fn offchain_eip3009_shape_requires_prepare() {
		let order = order_with_data(eip7683_data(LockType::Eip3009Escrow, true, true, true));

		assert!(order_requires_preparation(&order));
	}

	#[test]
	fn resource_lock_shape_does_not_require_prepare() {
		let order = order_with_data(eip7683_data(LockType::ResourceLock, true, true, true));

		assert!(!order_requires_preparation(&order));
	}

	#[test]
	fn onchain_escrow_shape_without_sponsor_or_signature_does_not_require_prepare() {
		let order = order_with_data(eip7683_data(LockType::Permit2Escrow, true, false, false));

		assert!(!order_requires_preparation(&order));
	}

	#[test]
	fn non_eip7683_order_does_not_require_prepare() {
		let order = OrderBuilder::new()
			.with_standard("other-standard")
			.with_data(serde_json::json!({ "not": "eip7683" }))
			.build();

		assert!(!order_requires_preparation(&order));
	}

	#[test]
	fn unparseable_eip7683_data_does_not_require_prepare() {
		let order = order_with_data(serde_json::json!({ "not": "eip7683" }));

		assert!(!order_requires_preparation(&order));
	}
}
