//! Chain-truth probe for recovery.
//!
//! When local order fields and the attempt ledger lack a stage's tx hash,
//! this module queries the chain for the corresponding OIF event. A topic
//! match on the indexed `orderId` proves the stage; payload decoding is
//! not required for the existence check.

use alloy_sol_types::SolEvent;
use solver_delivery::DeliveryService;
use solver_types::standards::eip7683::interfaces::{
	Finalised, Open, OrderPurchased, OutputFilled, Refunded,
};
use solver_types::{Address, LogFilter, TransactionHash, H256};

/// Default block-range window for the chain log scan.
///
/// - ~1s block chain (Katana): ≈ 2.7 hours
/// - ~12s block chain (Ethereum mainnet): ≈ 33 hours
pub(crate) const DEFAULT_RECOVERY_SCAN_WINDOW_BLOCKS: u64 = 10_000;

#[derive(Debug, Clone)]
pub(crate) enum ChainEvidence {
	/// Positive event matched on chain with usable tx metadata.
	Proven {
		tx_hash: TransactionHash,
		block_number: u64,
	},
	/// Terminal negative event (refunded, purchased) matched on chain.
	NegativeTerminal { reason: NegativeTerminalReason },
	/// `get_logs` succeeded and returned empty for all queries.
	NotFound,
	/// RPC failed, anchor unresolvable, OR a positive log matched but lacked
	/// tx metadata for repair. Retryable. (Missing settler in `NetworkConfig`
	/// is handled separately by the caller and surfaces as `NotFound` with a
	/// WARN log; see `fill_chain_evidence` / `claim_chain_evidence` in mod.rs.)
	Unknown { error: String },
}

#[derive(Debug, Clone)]
pub(crate) enum NegativeTerminalReason {
	Refunded,
	Purchased,
}

/// Builds a single-event log filter keyed by indexed `orderId`.
///
/// Takes `order_id_bytes: &[u8; 32]` rather than `TransactionHash` so callers
/// go through `solver_types::order_id_to_bytes32` and never panic on
/// non-hex test IDs.
pub(crate) fn log_filter_for_event<E: SolEvent>(
	settler: &Address,
	order_id_bytes: &[u8; 32],
	from_block: u64,
	to_block: Option<u64>,
) -> LogFilter {
	let topic0 = H256(E::SIGNATURE_HASH.0);
	let topic1 = H256(*order_id_bytes);
	LogFilter::new(
		settler.clone(),
		from_block,
		to_block,
		vec![Some(topic0), Some(topic1)],
	)
}

/// Resolves `(from_block, to_block)` for a same-chain scan. Falls back to
/// recent window on anchor receipt fetch failure.
pub(crate) async fn anchor_block_for_same_chain(
	delivery: &DeliveryService,
	chain_id: u64,
	anchor_tx: Option<&TransactionHash>,
	window_blocks: u64,
) -> Result<(u64, Option<u64>), String> {
	let latest = delivery
		.get_block_number(chain_id)
		.await
		.map_err(|e| format!("get_block_number failed: {e}"))?;

	if let Some(hash) = anchor_tx {
		match delivery.get_receipt(hash, chain_id).await {
			Ok(receipt) => {
				// Subtract the window before the anchor: the proof event we're
				// scanning for may have fired BEFORE this anchor tx (e.g., a
				// competitor solver's Finalised landed at an earlier block,
				// causing our claim attempt at `receipt.block_number` to
				// revert). Starting the scan at the anchor block would miss
				// those earlier events and incorrectly return NotFound.
				let from_block = receipt.block_number.saturating_sub(window_blocks);
				return Ok((from_block, Some(latest)));
			},
			Err(error) => {
				tracing::debug!(
					chain_id,
					tx_hash = ?hash,
					%error,
					"anchor receipt fetch failed; using recent window"
				);
			},
		}
	}

	Ok((latest.saturating_sub(window_blocks), Some(latest)))
}

/// Internal probe result distinguishing "no match" from "match without usable metadata."
enum ProbeResult {
	Found {
		tx_hash: TransactionHash,
		block_number: u64,
	},
	NoMatch,
	MatchedButUnusable,
}

/// Probes a single event signature. Returns the first match.
async fn probe_event<E: SolEvent>(
	delivery: &DeliveryService,
	chain_id: u64,
	settler: &Address,
	order_id_bytes: &[u8; 32],
	from_block: u64,
	to_block: Option<u64>,
) -> Result<ProbeResult, String> {
	let filter = log_filter_for_event::<E>(settler, order_id_bytes, from_block, to_block);
	let logs = delivery
		.get_logs(chain_id, filter)
		.await
		.map_err(|e| format!("get_logs failed: {e}"))?;

	let Some(log) = logs.into_iter().next() else {
		return Ok(ProbeResult::NoMatch);
	};

	match (log.transaction_hash, log.block_number) {
		(Some(tx_hash), Some(block_number)) => Ok(ProbeResult::Found {
			tx_hash,
			block_number,
		}),
		_ => Ok(ProbeResult::MatchedButUnusable),
	}
}

/// Origin-chain probe for `Open`, emitted by InputSettlerEscrow.openFor.
pub(crate) async fn chain_evidence_for_prepare_open(
	delivery: &DeliveryService,
	chain_id: u64,
	input_settler: &Address,
	order_id_bytes: &[u8; 32],
	window_blocks: u64,
) -> ChainEvidence {
	let (from_block, to_block) =
		match anchor_block_for_same_chain(delivery, chain_id, None, window_blocks).await {
			Ok(pair) => pair,
			Err(error) => return ChainEvidence::Unknown { error },
		};

	match probe_event::<Open>(
		delivery,
		chain_id,
		input_settler,
		order_id_bytes,
		from_block,
		to_block,
	)
	.await
	{
		Ok(ProbeResult::Found {
			tx_hash,
			block_number,
		}) => ChainEvidence::Proven {
			tx_hash,
			block_number,
		},
		Ok(ProbeResult::NoMatch) => ChainEvidence::NotFound,
		Ok(ProbeResult::MatchedButUnusable) => ChainEvidence::Unknown {
			error: "Open log matched but lacked tx_hash or block_number".to_string(),
		},
		Err(error) => ChainEvidence::Unknown { error },
	}
}

/// Destination-chain probe for `OutputFilled`.
pub(crate) async fn chain_evidence_for_fill(
	delivery: &DeliveryService,
	chain_id: u64,
	output_settler: &Address,
	order_id_bytes: &[u8; 32],
	window_blocks: u64,
) -> ChainEvidence {
	let (from_block, to_block) =
		match anchor_block_for_same_chain(delivery, chain_id, None, window_blocks).await {
			Ok(pair) => pair,
			Err(error) => return ChainEvidence::Unknown { error },
		};

	match probe_event::<OutputFilled>(
		delivery,
		chain_id,
		output_settler,
		order_id_bytes,
		from_block,
		to_block,
	)
	.await
	{
		Ok(ProbeResult::Found {
			tx_hash,
			block_number,
		}) => ChainEvidence::Proven {
			tx_hash,
			block_number,
		},
		Ok(ProbeResult::NoMatch) => ChainEvidence::NotFound,
		Ok(ProbeResult::MatchedButUnusable) => ChainEvidence::Unknown {
			error: "OutputFilled log matched but lacked tx_hash or block_number".to_string(),
		},
		Err(error) => ChainEvidence::Unknown { error },
	}
}

/// Origin-chain probe: `Finalised` (positive), `Refunded`, `OrderPurchased`
/// (negative). Short-circuits on the first match.
pub(crate) async fn chain_evidence_for_claim(
	delivery: &DeliveryService,
	chain_id: u64,
	input_settler: &Address,
	order_id_bytes: &[u8; 32],
	anchor_tx: Option<&TransactionHash>,
	window_blocks: u64,
) -> ChainEvidence {
	let (from_block, to_block) =
		match anchor_block_for_same_chain(delivery, chain_id, anchor_tx, window_blocks).await {
			Ok(pair) => pair,
			Err(error) => return ChainEvidence::Unknown { error },
		};

	// Positive: Finalised
	match probe_event::<Finalised>(
		delivery,
		chain_id,
		input_settler,
		order_id_bytes,
		from_block,
		to_block,
	)
	.await
	{
		Ok(ProbeResult::Found {
			tx_hash,
			block_number,
		}) => {
			return ChainEvidence::Proven {
				tx_hash,
				block_number,
			};
		},
		Ok(ProbeResult::MatchedButUnusable) => {
			return ChainEvidence::Unknown {
				error: "Finalised log matched but lacked tx_hash or block_number".to_string(),
			};
		},
		Err(error) => return ChainEvidence::Unknown { error },
		Ok(ProbeResult::NoMatch) => {},
	}

	// Negative: Refunded
	match probe_event::<Refunded>(
		delivery,
		chain_id,
		input_settler,
		order_id_bytes,
		from_block,
		to_block,
	)
	.await
	{
		Ok(ProbeResult::Found { .. }) | Ok(ProbeResult::MatchedButUnusable) => {
			return ChainEvidence::NegativeTerminal {
				reason: NegativeTerminalReason::Refunded,
			};
		},
		Err(error) => return ChainEvidence::Unknown { error },
		Ok(ProbeResult::NoMatch) => {},
	}

	// Negative: OrderPurchased
	match probe_event::<OrderPurchased>(
		delivery,
		chain_id,
		input_settler,
		order_id_bytes,
		from_block,
		to_block,
	)
	.await
	{
		Ok(ProbeResult::Found { .. }) | Ok(ProbeResult::MatchedButUnusable) => {
			ChainEvidence::NegativeTerminal {
				reason: NegativeTerminalReason::Purchased,
			}
		},
		Err(error) => ChainEvidence::Unknown { error },
		Ok(ProbeResult::NoMatch) => ChainEvidence::NotFound,
	}
}
