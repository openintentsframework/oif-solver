//! Bridge transfer types and state machine.

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

/// Typed request for a bridge operation.
///
/// Separates ERC-20/share tokens (used for approve/balance) from OFT contracts
/// (used for quoteSend/send). This prevents the PR #315 bug where the two were confused.
#[derive(Debug, Clone)]
pub struct BridgeRequest {
	/// Operator-chosen pair ID (e.g., "usdc-eth-katana").
	pub pair_id: String,
	/// Source chain ID.
	pub source_chain: u64,
	/// Destination chain ID.
	pub dest_chain: u64,
	/// ERC-20/share token on source chain — used for approve() and balanceOf().
	pub source_token: Address,
	/// OFT contract on source chain — used for quoteSend() and send().
	pub source_oft: Address,
	/// ERC-20/share token on destination chain — for balance verification.
	pub dest_token: Address,
	/// OFT contract on destination chain — for event scanning.
	pub dest_oft: Address,
	/// Amount to bridge in source token units.
	pub amount: U256,
	/// Minimum amount to receive (slippage floor).
	pub min_amount: Option<U256>,
	/// Recipient address on the destination chain.
	pub recipient: Address,
}

/// Metadata needed for the delivery detection and redeem completion path.
/// Must be provided by the caller (monitor or admin API) when initiating a transfer.
#[derive(Debug, Clone)]
pub struct TransferMetadata {
	/// Destination token/share contract address (for Transfer event scanning).
	pub dest_token_address: String,
	/// Destination OFT contract address.
	pub dest_oft_address: String,
	/// Whether this is a Composer flow (ETH→Katana) vs OFT send (Katana→ETH).
	pub is_composer_flow: bool,
	/// Vault address on destination chain (only needed for Katana→ETH redeem path).
	pub vault_address: Option<String>,
}

/// Result from initiating a bridge transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDepositResult {
	/// Transaction hash on the source chain.
	pub tx_hash: String,
	/// LayerZero message GUID (if available from tx receipt).
	pub message_guid: Option<String>,
	/// Estimated arrival time (unix timestamp).
	pub estimated_arrival: Option<u64>,
}

/// Transfer state machine.
///
/// For Katana -> Ethereum, the flow adds a redemption step:
///   Submitted -> Relaying -> PendingRedemption -> Completed
/// For Ethereum -> Katana (via Composer):
///   Submitted -> Relaying -> Completed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BridgeTransferStatus {
	/// Bridge tx submitted, awaiting source chain confirmation.
	Submitted,
	/// Confirmed on source; LayerZero delivering to destination.
	Relaying,
	/// Shares arrived on Ethereum; vault redeem tx needed (Katana->ETH only).
	PendingRedemption,
	/// Final tokens available in solver wallet.
	Completed,
	/// Unrecoverable error, no funds at risk.
	Failed(String),
	/// Timed out or retry exhausted; funds may still be in flight.
	/// Pair stays locked until admin resolves via `/transfers/{id}/resolve`.
	NeedsIntervention(String),
}

impl std::fmt::Display for BridgeTransferStatus {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Submitted => write!(f, "submitted"),
			Self::Relaying => write!(f, "relaying"),
			Self::PendingRedemption => write!(f, "pending_redemption"),
			Self::Completed => write!(f, "completed"),
			Self::Failed(_) => write!(f, "failed"),
			Self::NeedsIntervention(_) => write!(f, "needs_intervention"),
		}
	}
}

impl BridgeTransferStatus {
	/// Returns the reason string for statuses that carry one.
	pub fn reason(&self) -> Option<&str> {
		match self {
			Self::Failed(r) | Self::NeedsIntervention(r) => Some(r),
			_ => None,
		}
	}

	/// Whether this status is terminal (no further transitions expected).
	pub fn is_terminal(&self) -> bool {
		matches!(self, Self::Completed | Self::Failed(_))
	}

	/// Whether this status blocks new auto-rebalances for the same pair.
	pub fn blocks_pair(&self) -> bool {
		!self.is_terminal()
	}
}

/// What triggered the transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RebalanceTrigger {
	/// Triggered by the RebalanceMonitor background task.
	Auto,
	/// Triggered by admin API manual trigger.
	Manual,
}

impl std::fmt::Display for RebalanceTrigger {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Auto => write!(f, "auto"),
			Self::Manual => write!(f, "manual"),
		}
	}
}

/// Persistent transfer record stored in Redis.
///
/// Public fields are exposed via the admin API.
/// Internal monitor fields are persisted but not part of the public API contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBridgeTransfer {
	// --- public fields ---
	/// Unique transfer ID (UUID).
	pub id: String,
	/// Canonical pair ID (e.g., "USDC:1:747474"). Direction-independent.
	pub pair_id: String,
	/// Source chain ID.
	pub source_chain: u64,
	/// Destination chain ID.
	pub dest_chain: u64,
	/// Amount in source token units (decimal string).
	pub amount: String,
	/// Current transfer status.
	pub status: BridgeTransferStatus,
	/// What triggered this transfer.
	pub trigger: RebalanceTrigger,
	/// Creation timestamp (unix seconds).
	pub created_at: u64,
	/// Last update timestamp (unix seconds).
	pub updated_at: u64,
	/// Bridge tx hash on the source chain.
	pub tx_hash: Option<String>,
	/// LayerZero message GUID for tracking.
	pub message_guid: Option<String>,
	/// Vault redeem tx hash on Ethereum (for PendingRedemption state).
	pub redeem_tx_hash: Option<String>,
	/// Native gas paid for the LayerZero messaging fee.
	pub fee_paid: Option<String>,

	// --- internal monitor fields (persisted, not in public API) ---
	/// Last time the monitor polled this transfer's status.
	pub last_status_poll_at: Option<u64>,
	/// Number of consecutive failures (e.g., redeem retries).
	pub failure_count: u32,
	/// Status before entering NeedsIntervention (for retry recovery).
	pub status_before_intervention: Option<BridgeTransferStatus>,
	/// Source chain block number when tx was confirmed (reference).
	pub source_confirmed_block: Option<u64>,
	/// Destination chain head when entering Relaying (event scan lower bound).
	pub dest_scan_from_block: Option<u64>,
	/// Last scanned destination block (resume scanning from here).
	pub last_scanned_dest_block: Option<u64>,
	/// Destination token/share contract address (for Transfer event scanning).
	pub dest_token_address: Option<String>,
	/// Destination OFT contract address.
	pub dest_oft_address: Option<String>,
	/// Whether this is a Composer flow (ETH→Katana: true) or OFT send (Katana→ETH: false).
	/// Determines whether delivery is terminal (Completed) or needs redeem (PendingRedemption).
	pub is_composer_flow: Option<bool>,
	/// Vault address on destination chain (for ERC-4626 redeem, Katana→ETH only).
	pub vault_address: Option<String>,
	/// Actual shares received on destination (decoded from Transfer event).
	/// Used for vault redeem — may differ from `amount` due to slippage/fees.
	pub received_shares: Option<String>,
	/// Operator-provided reason when a transfer is manually resolved.
	pub resolution_reason: Option<String>,
	/// Number of consecutive polls where the source tx was not found on-chain.
	/// Used to distinguish "pending in mempool" from "dropped/evicted".
	#[serde(default)]
	pub submitted_missing_checks: u32,
	/// Unix timestamp when the source tx was first observed missing.
	#[serde(default)]
	pub submitted_missing_since: Option<u64>,
}

impl PendingBridgeTransfer {
	/// Create a new transfer record in Submitted state.
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		pair_id: String,
		source_chain: u64,
		dest_chain: u64,
		amount: String,
		trigger: RebalanceTrigger,
		tx_hash: Option<String>,
		message_guid: Option<String>,
		fee_paid: Option<String>,
	) -> Self {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();

		Self {
			id: uuid::Uuid::new_v4().to_string(),
			pair_id,
			source_chain,
			dest_chain,
			amount,
			status: BridgeTransferStatus::Submitted,
			trigger,
			created_at: now,
			updated_at: now,
			tx_hash,
			message_guid,
			redeem_tx_hash: None,
			fee_paid,
			last_status_poll_at: None,
			failure_count: 0,
			status_before_intervention: None,
			source_confirmed_block: None,
			dest_scan_from_block: None,
			last_scanned_dest_block: None,
			dest_token_address: None,
			dest_oft_address: None,
			is_composer_flow: None,
			vault_address: None,
			received_shares: None,
			resolution_reason: None,
			submitted_missing_checks: 0,
			submitted_missing_since: None,
		}
	}

	/// Transition to a new status, updating the timestamp.
	pub fn transition_to(&mut self, new_status: BridgeTransferStatus) {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();

		// If transitioning to NeedsIntervention, save the previous status —
		// but only if we're not already in NeedsIntervention (avoid overwriting
		// the original recoverable state with another NeedsIntervention value).
		if matches!(new_status, BridgeTransferStatus::NeedsIntervention(_))
			&& !matches!(self.status, BridgeTransferStatus::NeedsIntervention(_))
		{
			self.status_before_intervention = Some(self.status.clone());
		}

		self.status = new_status;
		self.updated_at = now;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn transfer_with_status(status: BridgeTransferStatus) -> PendingBridgeTransfer {
		let mut transfer = PendingBridgeTransfer::new(
			"eth-katana".to_string(),
			1,
			747474,
			"1000000".to_string(),
			RebalanceTrigger::Auto,
			None,
			None,
			None,
		);
		transfer.status = status;
		transfer.updated_at = 1;
		transfer
	}

	#[test]
	fn test_transition_to_needs_intervention_preserves_original_status() {
		let mut transfer = transfer_with_status(BridgeTransferStatus::Relaying);

		transfer.transition_to(BridgeTransferStatus::NeedsIntervention(
			"monitor timeout".to_string(),
		));

		assert!(matches!(
			transfer.status,
			BridgeTransferStatus::NeedsIntervention(_)
		));
		assert_eq!(
			transfer.status_before_intervention,
			Some(BridgeTransferStatus::Relaying)
		);
	}

	#[test]
	fn test_transition_to_needs_intervention_does_not_overwrite_previous_status() {
		let mut transfer = transfer_with_status(BridgeTransferStatus::PendingRedemption);

		transfer.transition_to(BridgeTransferStatus::NeedsIntervention(
			"first intervention".to_string(),
		));
		transfer.transition_to(BridgeTransferStatus::NeedsIntervention(
			"second intervention".to_string(),
		));

		assert!(matches!(
			transfer.status,
			BridgeTransferStatus::NeedsIntervention(ref reason) if reason == "second intervention"
		));
		assert_eq!(
			transfer.status_before_intervention,
			Some(BridgeTransferStatus::PendingRedemption)
		);
	}

	#[test]
	fn test_transition_to_is_terminal_and_blocks_pair_matrix() {
		let cases = [
			(BridgeTransferStatus::Submitted, false, true),
			(BridgeTransferStatus::Relaying, false, true),
			(BridgeTransferStatus::PendingRedemption, false, true),
			(BridgeTransferStatus::Completed, true, false),
			(
				BridgeTransferStatus::Failed("boom".to_string()),
				true,
				false,
			),
			(
				BridgeTransferStatus::NeedsIntervention("pause".to_string()),
				false,
				true,
			),
		];

		for (status, is_terminal, blocks_pair) in cases {
			assert_eq!(status.is_terminal(), is_terminal, "{status:?}");
			assert_eq!(status.blocks_pair(), blocks_pair, "{status:?}");
		}
	}

	#[test]
	fn test_transition_to_updates_updated_at_timestamp() {
		let mut transfer = transfer_with_status(BridgeTransferStatus::Submitted);
		let previous_updated_at = transfer.updated_at;

		transfer.transition_to(BridgeTransferStatus::Completed);

		assert!(matches!(transfer.status, BridgeTransferStatus::Completed));
		assert_ne!(transfer.updated_at, previous_updated_at);
		assert!(transfer.updated_at > previous_updated_at);
	}
}
