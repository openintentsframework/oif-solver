//! OIF contract revert classifier.
//!
//! Takes raw revert bytes from a failed-transaction eth_call replay and
//! produces a typed classification. Selector matches are computed from
//! `sol!` declarations so the catalog tracks the in-repo `oif-contracts/`
//! source.

use alloy_sol_types::{sol, SolError};

sol! {
	// StageComplete selectors — recovery may advance the order on these
	// AFTER chain-evidence proof. Only errors where chain probes are
	// strong enough to PROVE the stage completed.
	error AlreadyClaimed();
	error InvalidOrderStatus();

	// Terminal selectors (catalogued for explicit recognition).
	// AlreadyFilled is Terminal because chain_evidence_for_fill does
	// not verify output content / solver attribution.
	error AlreadyFilled();
	error FillDeadline();
	error TimestampPassed();
	error WrongChain(uint256, uint256);
	error InvalidSigner();
	error FilledTooLate(uint32, uint32);
	error NoDestination();
	error FillDeadlineAfterExpiry(uint32, uint32);
	error OrderIdMismatch(bytes32, bytes32);
	error SignatureAndInputsNotEqual();
	error SignatureNotSupported(bytes1);
	error UserCannotBeSettler();
	error NativeTokenNotSupported();
	error InvalidAttestation(bytes32, bytes32);
	error PayloadTooSmall();
	error NotImplemented();
	error ExclusiveTo(bytes32);
	error ZeroValue();
	error WrongOutputSettler(bytes32, bytes32);
	error WrongOutputOracle(bytes32, bytes32);
	error InvalidTimestampLength();

	// Transient errors — classified as Terminal today (no behavior change
	// vs Unknown selector). Catalogued so operator metrics can distinguish
	// transient reverts from truly unknown ones.
	error TimestampNotPassed();
	error NotProven();
	error ReentrancyDetected();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevertClassification {
	/// Revert HINTS the stage is already complete on-chain. Callers MUST
	/// confirm via a chain probe before advancing the order.
	StageComplete { reason: StageCompleteReason },
	/// Definitive stage failure. Carries selector hex for operator diagnostics.
	Terminal { selector_hex: String },
	/// No revert data, fewer than 4 bytes, or uncatalogued selector. Callers
	/// MUST preserve today's behavior (treat as Failed) — do NOT advance the
	/// order on Unknown.
	Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageCompleteReason {
	/// `AlreadyClaimed() = 0x646cf558` from `InputSettlerCompact.finalise`.
	/// Fires when finalising an already-finalised compact order.
	AlreadyClaimed,
	/// `InvalidOrderStatus() = 0x2916ae33` from `InputSettlerEscrow.finalise`.
	/// Fires when the escrow order isn't in the expected state — in practice
	/// because it was already finalised OR refunded. Chain probe distinguishes
	/// via the `Finalised` vs `Refunded` events.
	EscrowInvalidOrderStatus,
}

/// Classify a revert payload by 4-byte selector.
pub fn classify_revert(revert_data: &[u8]) -> RevertClassification {
	if revert_data.len() < 4 {
		return RevertClassification::Unknown;
	}
	let selector: [u8; 4] = revert_data[..4].try_into().expect("len >= 4 verified");

	if selector == AlreadyClaimed::SELECTOR {
		return RevertClassification::StageComplete {
			reason: StageCompleteReason::AlreadyClaimed,
		};
	}
	if selector == InvalidOrderStatus::SELECTOR {
		return RevertClassification::StageComplete {
			reason: StageCompleteReason::EscrowInvalidOrderStatus,
		};
	}

	let terminal_selectors: &[[u8; 4]] = &[
		AlreadyFilled::SELECTOR,
		FillDeadline::SELECTOR,
		TimestampPassed::SELECTOR,
		WrongChain::SELECTOR,
		InvalidSigner::SELECTOR,
		FilledTooLate::SELECTOR,
		NoDestination::SELECTOR,
		FillDeadlineAfterExpiry::SELECTOR,
		OrderIdMismatch::SELECTOR,
		SignatureAndInputsNotEqual::SELECTOR,
		SignatureNotSupported::SELECTOR,
		UserCannotBeSettler::SELECTOR,
		NativeTokenNotSupported::SELECTOR,
		InvalidAttestation::SELECTOR,
		PayloadTooSmall::SELECTOR,
		NotImplemented::SELECTOR,
		ExclusiveTo::SELECTOR,
		ZeroValue::SELECTOR,
		WrongOutputSettler::SELECTOR,
		WrongOutputOracle::SELECTOR,
		InvalidTimestampLength::SELECTOR,
		TimestampNotPassed::SELECTOR,
		NotProven::SELECTOR,
		ReentrancyDetected::SELECTOR,
	];
	if terminal_selectors.contains(&selector) {
		return RevertClassification::Terminal {
			selector_hex: hex::encode(selector),
		};
	}

	RevertClassification::Unknown
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn empty_bytes_returns_unknown() {
		assert!(matches!(
			classify_revert(&[]),
			RevertClassification::Unknown
		));
	}

	#[test]
	fn short_bytes_returns_unknown() {
		assert!(matches!(
			classify_revert(&[0x01, 0x02, 0x03]),
			RevertClassification::Unknown
		));
	}

	#[test]
	fn already_claimed_selector_is_stage_complete() {
		let revert = hex::decode("646cf558").unwrap();
		assert!(matches!(
			classify_revert(&revert),
			RevertClassification::StageComplete {
				reason: StageCompleteReason::AlreadyClaimed
			}
		));
	}

	#[test]
	fn invalid_order_status_selector_is_stage_complete() {
		let revert = hex::decode("2916ae33").unwrap();
		assert!(matches!(
			classify_revert(&revert),
			RevertClassification::StageComplete {
				reason: StageCompleteReason::EscrowInvalidOrderStatus
			}
		));
	}

	#[test]
	fn already_filled_classifies_as_terminal() {
		let revert = hex::decode("41a26a63").unwrap();
		match classify_revert(&revert) {
			RevertClassification::Terminal { selector_hex } => {
				assert_eq!(selector_hex, "41a26a63");
			},
			other => panic!("expected Terminal AlreadyFilled, got {other:?}"),
		}
	}

	#[test]
	fn fill_deadline_selector_is_terminal() {
		let revert = hex::decode("9f3ddb90").unwrap();
		assert!(matches!(
			classify_revert(&revert),
			RevertClassification::Terminal { .. }
		));
	}

	#[test]
	fn unknown_selector_is_unknown_not_terminal() {
		let revert = hex::decode("deadbeef").unwrap();
		assert!(matches!(
			classify_revert(&revert),
			RevertClassification::Unknown
		));
	}

	#[test]
	fn already_claimed_with_trailing_abi_args_still_classifies() {
		let mut revert = hex::decode("646cf558").unwrap();
		revert.extend_from_slice(&[0x00; 32]);
		assert!(matches!(
			classify_revert(&revert),
			RevertClassification::StageComplete {
				reason: StageCompleteReason::AlreadyClaimed
			}
		));
	}

	#[test]
	fn catalogued_selectors_match_documented_hex() {
		assert_eq!(hex::encode(AlreadyClaimed::SELECTOR), "646cf558");
		assert_eq!(hex::encode(InvalidOrderStatus::SELECTOR), "2916ae33");
		assert_eq!(hex::encode(AlreadyFilled::SELECTOR), "41a26a63");
	}
}
