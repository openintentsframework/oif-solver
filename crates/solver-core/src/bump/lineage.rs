//! Lineage graph traversal for same-nonce replacement chains.

use solver_types::{TransactionAttempt, TransactionAttemptStatus};

/// Group attempts (already filtered to a single `(order_id, tx_type)`)
/// into connected lineage components by walking `replacement_of` links.
/// Each returned `Vec` is one same-nonce lineage.
pub fn lineage_components(attempts: &[TransactionAttempt]) -> Vec<Vec<&TransactionAttempt>> {
	use std::collections::HashMap;
	let by_id: HashMap<&str, &TransactionAttempt> =
		attempts.iter().map(|a| (a.id.as_str(), a)).collect();

	let mut children: HashMap<&str, Vec<&TransactionAttempt>> = HashMap::new();
	let mut roots: Vec<&TransactionAttempt> = Vec::new();
	for a in attempts {
		match a.replacement_of.as_deref() {
			Some(parent) if by_id.contains_key(parent) => {
				children.entry(parent).or_default().push(a);
			},
			_ => roots.push(a),
		}
	}

	roots
		.into_iter()
		.map(|root| {
			let mut comp: Vec<&TransactionAttempt> = vec![root];
			let mut stack: Vec<&TransactionAttempt> = vec![root];
			while let Some(node) = stack.pop() {
				if let Some(cs) = children.get(node.id.as_str()) {
					for c in cs {
						comp.push(c);
						stack.push(c);
					}
				}
			}
			comp
		})
		.collect()
}

/// Returns the bumpable tip of a single lineage component, or `None` if
/// no member is bumpable. A "tip" is the unique non-terminal attempt
/// with no non-terminal descendants — the latest in-flight bump.
pub fn lineage_tip<'a>(component: &'a [&'a TransactionAttempt]) -> Option<&'a TransactionAttempt> {
	use std::collections::HashSet;
	let by_id: std::collections::HashMap<&str, &TransactionAttempt> =
		component.iter().map(|a| (a.id.as_str(), *a)).collect();

	let mut has_nonterminal_descendant: HashSet<&str> = HashSet::new();
	for a in component {
		if a.is_terminal() {
			continue;
		}
		// Pre-broadcast replacement children — a row persisted to the ledger
		// before its raw transaction was broadcast — are not eligible to be
		// the lineage tip. They block neither their parent nor the bump
		// sweeper.
		if a.status == TransactionAttemptStatus::Planned && a.tx_hash.is_none() {
			continue;
		}
		// Walk up via replacement_of, marking ancestors as having a
		// non-terminal descendant.
		let mut cursor = a.replacement_of.as_deref();
		while let Some(parent_id) = cursor {
			if !has_nonterminal_descendant.insert(parent_id) {
				break;
			}
			cursor = by_id
				.get(parent_id)
				.and_then(|p| p.replacement_of.as_deref());
		}
	}

	component
		.iter()
		.find(|a| !a.is_terminal() && !has_nonterminal_descendant.contains(a.id.as_str()))
		.copied()
}

/// Count children in a lineage (attempts with `replacement_of` set).
/// `max_replacements_per_stage` is checked against this count.
pub fn replacement_count_in_lineage(component: &[&TransactionAttempt]) -> u32 {
	component
		.iter()
		.filter(|a| a.replacement_of.is_some())
		.count() as u32
}

/// Returns true if any attempt in the lineage is `Confirmed`.
pub fn has_confirmed_member(component: &[&TransactionAttempt]) -> bool {
	component
		.iter()
		.any(|a| a.status == TransactionAttemptStatus::Confirmed)
}

/// Returns the highest `(max_fee_per_gas, max_priority_fee_per_gas, gas_price)`
/// tuple across all lineage members — INCLUDING `SubmitRejected` and `Replaced`.
/// This is what makes `ReplacementUnderpriced` self-recover: the rejected
/// child's fees become the new floor for the next bump.
pub fn highest_fees_in_lineage(
	component: &[&TransactionAttempt],
) -> (Option<u128>, Option<u128>, Option<u128>) {
	let mut max_fee: Option<u128> = None;
	let mut max_priority: Option<u128> = None;
	let mut max_gas_price: Option<u128> = None;
	for a in component {
		if let Some(v) = a.tx.max_fee_per_gas {
			max_fee = Some(max_fee.map_or(v, |cur| cur.max(v)));
		}
		if let Some(v) = a.tx.max_priority_fee_per_gas {
			max_priority = Some(max_priority.map_or(v, |cur| cur.max(v)));
		}
		if let Some(v) = a.tx.gas_price {
			max_gas_price = Some(max_gas_price.map_or(v, |cur| cur.max(v)));
		}
	}
	(max_fee, max_priority, max_gas_price)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::U256;
	use solver_types::{Address, Transaction, TransactionAttempt, TransactionType};

	fn tx_with_fees(max_fee: u128, priority: u128) -> Transaction {
		Transaction {
			to: Some(Address(vec![1; 20])),
			data: vec![],
			value: U256::ZERO,
			chain_id: 1,
			nonce: Some(0),
			gas_limit: Some(100_000),
			gas_price: None,
			max_fee_per_gas: Some(max_fee),
			max_priority_fee_per_gas: Some(priority),
		}
	}

	fn attempt(
		id: &str,
		replacement_of: Option<&str>,
		status: TransactionAttemptStatus,
		max_fee: u128,
	) -> TransactionAttempt {
		let mut a = TransactionAttempt::planned(
			id.into(),
			solver_types::TransactionAttemptScope::order("order-1"),
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			tx_with_fees(max_fee, max_fee / 10),
		);
		a.status = status;
		a.replacement_of = replacement_of.map(String::from);
		a
	}

	#[test]
	fn lineage_components_single_chain() {
		let attempts = vec![
			attempt("a", None, TransactionAttemptStatus::Broadcast, 10),
			attempt("b", Some("a"), TransactionAttemptStatus::Broadcast, 12),
			attempt("c", Some("b"), TransactionAttemptStatus::Broadcast, 15),
		];
		let components = lineage_components(&attempts);
		assert_eq!(components.len(), 1);
		assert_eq!(components[0].len(), 3);
	}

	#[test]
	fn lineage_components_two_independent_chains() {
		let attempts = vec![
			attempt("a", None, TransactionAttemptStatus::Broadcast, 10),
			attempt("b", Some("a"), TransactionAttemptStatus::Broadcast, 12),
			attempt("x", None, TransactionAttemptStatus::Broadcast, 100),
			attempt("y", Some("x"), TransactionAttemptStatus::Broadcast, 120),
		];
		let components = lineage_components(&attempts);
		assert_eq!(components.len(), 2);
	}

	#[test]
	fn lineage_tip_is_deepest_non_terminal() {
		let attempts = vec![
			attempt("a", None, TransactionAttemptStatus::Broadcast, 10),
			attempt("b", Some("a"), TransactionAttemptStatus::Broadcast, 12),
			attempt("c", Some("b"), TransactionAttemptStatus::Broadcast, 15),
		];
		let refs: Vec<&TransactionAttempt> = attempts.iter().collect();
		let tip = lineage_tip(&refs).unwrap();
		assert_eq!(tip.id, "c");
	}

	#[test]
	fn lineage_tip_skips_terminal_descendants() {
		let attempts = vec![
			attempt("a", None, TransactionAttemptStatus::Broadcast, 10),
			attempt("b", Some("a"), TransactionAttemptStatus::SubmitRejected, 12),
		];
		let refs: Vec<&TransactionAttempt> = attempts.iter().collect();
		let tip = lineage_tip(&refs).unwrap();
		assert_eq!(
			tip.id, "a",
			"rejected child does not block parent from being tip"
		);
	}

	#[test]
	fn lineage_tip_ignores_pre_broadcast_planned_replacement_without_hash() {
		let parent = attempt("a", None, TransactionAttemptStatus::Broadcast, 10);
		let child = attempt("b", Some("a"), TransactionAttemptStatus::Planned, 12);
		assert!(child.tx_hash.is_none());

		let attempts = vec![parent, child];
		let refs: Vec<&TransactionAttempt> = attempts.iter().collect();
		let tip = lineage_tip(&refs).unwrap();
		assert_eq!(
			tip.id, "a",
			"pre-broadcast planned replacement without a hash must not block the parent"
		);
	}

	#[test]
	fn lineage_tip_returns_none_when_all_terminal() {
		let attempts = vec![
			attempt("a", None, TransactionAttemptStatus::Reverted, 10),
			attempt("b", Some("a"), TransactionAttemptStatus::Confirmed, 12),
		];
		let refs: Vec<&TransactionAttempt> = attempts.iter().collect();
		assert!(lineage_tip(&refs).is_none());
	}

	#[test]
	fn replacement_count_counts_children_only() {
		let attempts = vec![
			attempt("a", None, TransactionAttemptStatus::Broadcast, 10),
			attempt("b", Some("a"), TransactionAttemptStatus::Broadcast, 12),
			attempt("c", Some("b"), TransactionAttemptStatus::Broadcast, 15),
		];
		let refs: Vec<&TransactionAttempt> = attempts.iter().collect();
		assert_eq!(replacement_count_in_lineage(&refs), 2);
	}

	#[test]
	fn has_confirmed_member_detects_confirmation() {
		let attempts = vec![
			attempt("a", None, TransactionAttemptStatus::Broadcast, 10),
			attempt("b", Some("a"), TransactionAttemptStatus::Confirmed, 12),
		];
		let refs: Vec<&TransactionAttempt> = attempts.iter().collect();
		assert!(has_confirmed_member(&refs));
	}

	#[test]
	fn highest_fees_includes_submit_rejected() {
		let attempts = vec![
			attempt("a", None, TransactionAttemptStatus::Broadcast, 10),
			attempt("b", Some("a"), TransactionAttemptStatus::SubmitRejected, 50),
		];
		let refs: Vec<&TransactionAttempt> = attempts.iter().collect();
		let (max_fee, _, _) = highest_fees_in_lineage(&refs);
		assert_eq!(
			max_fee,
			Some(50),
			"rejected child's fees are the floor for next bump"
		);
	}

	#[test]
	fn lineage_built_from_order_query_when_replaced_by_missing() {
		// Simulates CAS-conflict scenario: parent.replaced_by failed to
		// write, but child.replacement_of did. lineage_components must
		// still group them via replacement_of (the source of truth).
		let mut a = attempt("a", None, TransactionAttemptStatus::Broadcast, 10);
		a.replaced_by = None; // explicitly unset
		let b = attempt("b", Some("a"), TransactionAttemptStatus::Broadcast, 12);
		let attempts = vec![a, b];
		let components = lineage_components(&attempts);
		assert_eq!(components.len(), 1);
		assert_eq!(components[0].len(), 2);
	}
}
