//! Background sweeper that drives same-nonce gas bumping.
//!
//! Owns no in-memory state — every tick re-reads the attempt ledger.
//! Spawned from `Engine::run()` when `tx_bump.enabled`.

use crate::bump::lineage::{
	has_confirmed_member, highest_fees_in_lineage, lineage_components, lineage_tip,
	replacement_count_in_lineage,
};
use crate::bump::policy::{apply_bump_percent, bumped_fees_exceed_cap, BumpFees};
use crate::engine::event_bus::EventBus;
use crate::state::transaction_attempt::TransactionAttemptStore;
use alloy_primitives::U256;
use solver_config::{EffectiveTxBumpPolicy, TxBumpConfig};
use solver_delivery::{
	DeliveryError, DeliveryService, RevertClassification, TransactionAttemptRecorder,
	TransactionMonitoringEvent, TransactionTracking,
};
use solver_storage::StorageService;
use solver_types::{
	current_timestamp, DeliveryEvent, SolverEvent, TransactionAttempt, TransactionAttemptStatus,
	TransactionType,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

pub struct TransactionBumpService {
	config: TxBumpConfig,
	storage: Arc<StorageService>,
	attempt_store: Arc<TransactionAttemptStore>,
	delivery: Arc<DeliveryService>,
	event_bus: EventBus,
	attempt_recorder: Arc<dyn TransactionAttemptRecorder>,
	pricing: Arc<solver_pricing::PricingService>,
}

impl TransactionBumpService {
	pub fn new(
		config: TxBumpConfig,
		storage: Arc<StorageService>,
		attempt_store: Arc<TransactionAttemptStore>,
		delivery: Arc<DeliveryService>,
		event_bus: EventBus,
		attempt_recorder: Arc<dyn TransactionAttemptRecorder>,
		pricing: Arc<solver_pricing::PricingService>,
	) -> Self {
		Self {
			config,
			storage,
			attempt_store,
			delivery,
			event_bus,
			attempt_recorder,
			pricing,
		}
	}

	/// Drive the sweeper until `shutdown_rx` fires `true`. Mirrors the
	/// `rebalance.run(shutdown_rx)` lifecycle in `engine/mod.rs:503-506`.
	/// Uses `tokio::sync::watch` (NOT `tokio_util::CancellationToken`) to
	/// match the existing shutdown convention in this codebase.
	pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) {
		if !self.config.enabled {
			tracing::info!("tx_bump disabled; sweeper exiting");
			return;
		}
		let interval = Duration::from_secs(self.config.sweep_interval_secs);
		tracing::info!(
			sweep_interval_secs = self.config.sweep_interval_secs,
			chains = ?self.config.chains.keys().collect::<Vec<_>>(),
			"tx_bump sweeper started"
		);
		loop {
			tokio::select! {
				changed = shutdown_rx.changed() => {
					if changed.is_err() || *shutdown_rx.borrow() {
						tracing::info!("tx_bump sweeper shutdown");
						return;
					}
				}
				_ = tokio::time::sleep(interval) => {
					if let Err(e) = self.tick().await {
						tracing::warn!(error = %e, "tx_bump sweeper tick failed");
					}
				}
			}
		}
	}

	/// Single tick: Phase 1 (reconcile) then Phase 2 (dispatch).
	pub async fn tick(&self) -> Result<(), BumpError> {
		self.phase_1_reconcile().await?;
		self.phase_2_dispatch().await?;
		Ok(())
	}

	async fn phase_1_reconcile(&self) -> Result<(), BumpError> {
		let active_orders = load_active_order_ids(&self.storage).await?;
		for order_id in active_orders {
			let attempts = self
				.attempt_store
				.attempts_for_order(&order_id)
				.await
				.map_err(|e| BumpError::Storage(e.to_string()))?;

			// Bucket by tx_type. `TransactionType` is `Copy + PartialEq` but
			// not `Hash + Eq`, so we use a `Vec` of buckets instead of a
			// `HashMap` keyed by `TransactionType`.
			let mut buckets: Vec<(TransactionType, Vec<TransactionAttempt>)> = Vec::new();
			for a in attempts {
				if let Some(bucket) = buckets.iter_mut().find(|(t, _)| *t == a.tx_type) {
					bucket.1.push(a);
				} else {
					buckets.push((a.tx_type, vec![a]));
				}
			}

			for (_tx_type, group) in buckets {
				for component in lineage_components(&group) {
					if !has_confirmed_member(&component) {
						continue;
					}
					let winner_id = component
						.iter()
						.find(|a| a.status == TransactionAttemptStatus::Confirmed)
						.map(|a| a.id.clone())
						.unwrap();
					for member in component {
						if member.is_terminal() {
							continue;
						}
						let _ = self
							.attempt_store
							.update_attempt_status(
								&member.id,
								TransactionAttemptStatus::Replaced,
								Some(format!("superseded by {winner_id}")),
								|_| {},
							)
							.await;
						// CAS conflict (member transitioned mid-call) is
						// a no-op — next tick re-evaluates.
					}
				}
			}
		}
		Ok(())
	}

	async fn phase_2_dispatch(&self) -> Result<(), BumpError> {
		let active_orders = load_active_order_ids(&self.storage).await?;
		for order_id in active_orders {
			let attempts = self
				.attempt_store
				.attempts_for_order(&order_id)
				.await
				.map_err(|e| BumpError::Storage(e.to_string()))?;

			// Bucket by (chain_id, tx_type) so multi-chain orders apply the
			// correct per-chain policy. Vec-pair pattern because neither
			// TransactionType nor the tuple implements Hash.
			let mut by_chain_and_type: Vec<((u64, TransactionType), Vec<TransactionAttempt>)> =
				Vec::new();
			for a in attempts {
				if let Some(slot) = by_chain_and_type
					.iter_mut()
					.find(|((cid, t), _)| *cid == a.chain_id && *t == a.tx_type)
				{
					slot.1.push(a);
				} else {
					by_chain_and_type.push(((a.chain_id, a.tx_type), vec![a]));
				}
			}

			for ((chain_id, tx_type), group) in by_chain_and_type {
				let policy = match self.config.for_chain(chain_id) {
					Some(p) => p,
					None => continue,
				};
				for component in lineage_components(&group) {
					self.maybe_bump_component(&component, &policy, chain_id, &order_id, tx_type)
						.await;
				}
			}
		}
		Ok(())
	}

	#[allow(clippy::too_many_arguments)]
	async fn maybe_bump_component(
		&self,
		component: &[&TransactionAttempt],
		policy: &EffectiveTxBumpPolicy,
		chain_id: u64,
		order_id: &str,
		tx_type: TransactionType,
	) {
		// 2. Lineage tip
		let tip = match lineage_tip(component) {
			Some(t) => t,
			None => return,
		};

		// 3. Status: only Broadcast or Indeterminate are eligible.
		if !matches!(
			tip.status,
			TransactionAttemptStatus::Broadcast | TransactionAttemptStatus::Indeterminate
		) {
			return;
		}

		// 4. Age threshold.
		let now = current_timestamp();
		let age = now.saturating_sub(tip.updated_at);
		if age < policy.pending_threshold_secs {
			return;
		}

		// 4.5. Deadline guard. Skip bumping if the on-chain contract will
		//      reject the replacement regardless of fee:
		//      - Fill stage: `OutputSettlerBase.fill` reverts after
		//        `order.fillDeadline`.
		//      - Claim stage: after `order.expires`, the user can refund
		//        the escrow; a claim landing later would revert because
		//        input-settler state moved on.
		//      Fail-open if the order can't be retrieved or the standard
		//      doesn't expose a deadline accessor (returns None).
		if matches!(tx_type, TransactionType::Fill | TransactionType::Claim) {
			if let Some(deadline) = self.deadline_for_stage(order_id, tx_type).await {
				if now >= deadline {
					self.event_bus
						.publish(SolverEvent::Delivery(DeliveryEvent::BumpDeadlineExpired {
							order_id: order_id.to_string(),
							attempt_id: tip.id.clone(),
							chain_id,
							tx_type,
							current_time: now,
							deadline,
						}))
						.ok();
					return;
				}
			}
		}

		// 5. Signer present on the tip row.
		let expected_signer = match tip.signer.as_ref() {
			Some(s) => s.clone(),
			None => {
				self.event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::BumpMissingSigner {
						order_id: order_id.to_string(),
						attempt_id: tip.id.clone(),
						chain_id,
						tx_type,
					}))
					.ok();
				return;
			},
		};

		// 6. Submission signer present (silent skip — chain doesn't expose one).
		let submission_signer = match self.delivery.submission_signer(chain_id) {
			Some(s) => s,
			None => {
				self.event_bus
					.publish(SolverEvent::Delivery(
						DeliveryEvent::BumpSubmissionSignerUnavailable {
							order_id: order_id.to_string(),
							attempt_id: tip.id.clone(),
							chain_id,
							tx_type,
						},
					))
					.ok();
				return;
			},
		};

		// 7. Same-signer invariant.
		if expected_signer != submission_signer {
			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::BumpSignerMismatch {
					order_id: order_id.to_string(),
					attempt_id: tip.id.clone(),
					chain_id,
					tx_type,
					expected_signer: expected_signer.clone(),
					submission_signer: submission_signer.clone(),
				}))
				.ok();
			return;
		}

		// 8. Max replacements per stage.
		let replacement_count = replacement_count_in_lineage(component);
		if replacement_count >= policy.max_replacements_per_stage {
			self.event_bus
				.publish(SolverEvent::Delivery(
					DeliveryEvent::BumpMaxReplacementsReached {
						order_id: order_id.to_string(),
						attempt_id: tip.id.clone(),
						chain_id,
						tx_type,
						lineage_depth: replacement_count,
					},
				))
				.ok();
			return;
		}

		// 9. Bump math: build a virtual "floor tx" from the highest fees
		//    seen across the lineage (including SubmitRejected/Replaced),
		//    then apply `bump_percent`.
		let (max_fee, max_priority, gas_price) = highest_fees_in_lineage(component);
		let floor_tx = solver_types::Transaction {
			to: tip.tx.to.clone(),
			data: tip.tx.data.clone(),
			value: tip.tx.value,
			chain_id: tip.tx.chain_id,
			nonce: tip.tx.nonce,
			gas_limit: tip.tx.gas_limit,
			gas_price,
			max_fee_per_gas: max_fee,
			max_priority_fee_per_gas: max_priority,
		};
		let bumped = apply_bump_percent(&floor_tx, policy.bump_percent);

		// 10. Cap check.
		if let Some(cap_field) = bumped_fees_exceed_cap(
			&bumped,
			policy.max_fee_per_gas_cap_wei,
			policy.max_priority_fee_per_gas_cap_wei,
		) {
			let (computed_fee_wei, cap_wei) = match cap_field {
				solver_types::BumpCapField::MaxFeePerGas => {
					let computed = bumped.max_fee_per_gas.or(bumped.gas_price).unwrap_or(0);
					let cap = policy.max_fee_per_gas_cap_wei.unwrap_or(0);
					(computed.to_string(), cap.to_string())
				},
				solver_types::BumpCapField::MaxPriorityFeePerGas => {
					let computed = bumped.max_priority_fee_per_gas.unwrap_or(0);
					let cap = policy.max_priority_fee_per_gas_cap_wei.unwrap_or(0);
					(computed.to_string(), cap.to_string())
				},
			};
			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::BumpCapReached {
					order_id: order_id.to_string(),
					attempt_id: tip.id.clone(),
					chain_id,
					tx_type,
					cap_field,
					computed_fee_wei,
					cap_wei,
				}))
				.ok();
			return;
		}

		// Per-order profitability gate.
		let order_opt: Option<solver_types::Order> = match self
			.storage
			.retrieve::<solver_types::Order>(solver_types::StorageKey::Orders.as_str(), order_id)
			.await
		{
			Ok(o) => Some(o),
			Err(e) => {
				tracing::warn!(
					%order_id,
					error = %e,
					"tx_bump: order retrieve failed; proceeding with bump (fail-open)"
				);
				self.emit_profitability_check_skipped(
					order_id,
					&tip.id,
					chain_id,
					tx_type,
					"order not found",
				);
				if policy.profitability_gate_fail_closed {
					return;
				}
				None
			},
		};
		if let Some(order) = order_opt.as_ref() {
			if self
				.should_skip_for_profitability(order, &bumped, tip, chain_id, tx_type, policy)
				.await
			{
				return;
			}
		}

		// 11. Balance check (best-effort).
		let signer_hex = expected_signer.to_string();
		match self.delivery.get_balance(chain_id, &signer_hex, None).await {
			Ok(balance_str) => match balance_str.parse::<U256>() {
				Ok(balance) => {
					let required = required_balance_wei(&bumped, &tip.tx);
					if balance < required {
						tracing::warn!(
							%order_id,
							attempt_id = %tip.id,
							chain_id,
							signer = %signer_hex,
							balance = %balance,
							required = %required,
							"tx_bump: signer balance insufficient for bumped replacement; skipping tick"
						);
						return;
					}
				},
				Err(e) => {
					tracing::debug!(
						%order_id,
						attempt_id = %tip.id,
						chain_id,
						balance_str = %balance_str,
						error = %e,
						"tx_bump: balance parse error; skipping tick"
					);
					self.event_bus
						.publish(SolverEvent::Delivery(
							DeliveryEvent::BumpBalanceCheckSkipped {
								order_id: order_id.to_string(),
								attempt_id: tip.id.clone(),
								chain_id,
								tx_type,
								reason: format!("balance parse error: {e}"),
							},
						))
						.ok();
					return;
				},
			},
			Err(e) => {
				tracing::debug!(
					%order_id,
					attempt_id = %tip.id,
					chain_id,
					error = %e,
					"tx_bump: balance RPC error; skipping tick"
				);
				self.event_bus
					.publish(SolverEvent::Delivery(
						DeliveryEvent::BumpBalanceCheckSkipped {
							order_id: order_id.to_string(),
							attempt_id: tip.id.clone(),
							chain_id,
							tx_type,
							reason: format!("balance RPC error: {e}"),
						},
					))
					.ok();
				return;
			},
		}

		// 12. Hard nonce check. The same-nonce invariant is load-bearing for
		//     bump correctness: if `tip.tx.nonce` is None, the Alloy submit
		//     path will allocate a fresh nonce, producing a brand-new
		//     transaction labeled as a replacement. Refuse to bump in that
		//     case rather than relying on the debug_assert below (which is a
		//     no-op in release builds).
		if tip.tx.nonce.is_none() {
			tracing::warn!(
				%order_id,
				attempt_id = %tip.id,
				chain_id,
				?tx_type,
				"tx_bump: tip nonce missing; refusing to bump (would violate same-nonce invariant)"
			);
			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::BumpMissingNonce {
					order_id: order_id.to_string(),
					attempt_id: tip.id.clone(),
					chain_id,
					tx_type,
				}))
				.ok();
			return;
		}

		if tip.status == TransactionAttemptStatus::Indeterminate {
			if let Some(tip_hash) = tip.tx_hash.clone() {
				match self.delivery.get_receipt(&tip_hash, chain_id).await {
					Ok(receipt) if receipt.success => {
						self.event_bus
							.publish(SolverEvent::Delivery(DeliveryEvent::BumpTipAlreadyMined {
								order_id: order_id.to_string(),
								attempt_id: tip.id.clone(),
								chain_id,
								tx_type,
								tx_hash: tip_hash.clone(),
								success: true,
							}))
							.ok();
						if let Err(error) = self
							.attempt_store
							.mark_attempt_confirmed_from_receipt(&tip.id, tip_hash.clone(), receipt)
							.await
						{
							self.event_bus
								.publish(SolverEvent::Delivery(
									DeliveryEvent::TransactionAttemptLedgerConflict {
										order_id: order_id.to_string(),
										attempt_id: tip.id.clone(),
										tx_type,
										tx_hash: Some(tip_hash),
										attempted_status: TransactionAttemptStatus::Confirmed,
										error: error.to_string(),
										context: "bump receipt preflight confirmed".to_string(),
									},
								))
								.ok();
						}
						return;
					},
					Ok(receipt) => {
						self.event_bus
							.publish(SolverEvent::Delivery(DeliveryEvent::BumpTipAlreadyMined {
								order_id: order_id.to_string(),
								attempt_id: tip.id.clone(),
								chain_id,
								tx_type,
								tx_hash: tip_hash.clone(),
								success: false,
							}))
							.ok();
						let receipt_for_update = receipt.clone();
						let hash_for_update = tip_hash.clone();
						if let Err(error) = self
							.attempt_store
							.update_attempt_status(
								&tip.id,
								TransactionAttemptStatus::Reverted,
								Some("receipt preflight found reverted tip".to_string()),
								|attempt| {
									attempt.tx_hash = Some(hash_for_update.clone());
									attempt.receipt = Some(receipt_for_update.clone());
								},
							)
							.await
						{
							self.event_bus
								.publish(SolverEvent::Delivery(
									DeliveryEvent::TransactionAttemptLedgerConflict {
										order_id: order_id.to_string(),
										attempt_id: tip.id.clone(),
										tx_type,
										tx_hash: Some(tip_hash),
										attempted_status: TransactionAttemptStatus::Reverted,
										error: error.to_string(),
										context: "bump receipt preflight reverted".to_string(),
									},
								))
								.ok();
						}
						return;
					},
					Err(error) => {
						self.event_bus
							.publish(SolverEvent::Delivery(
								DeliveryEvent::BumpReceiptPreflightSkipped {
									order_id: order_id.to_string(),
									attempt_id: tip.id.clone(),
									chain_id,
									tx_type,
									tx_hash: tip_hash,
									error: error.to_string(),
									fail_closed: policy.receipt_preflight_fail_closed,
								},
							))
							.ok();
						if policy.receipt_preflight_fail_closed {
							return;
						}
					},
				}
			}
		}

		// 13. Build replacement_tx: clone tip.tx and override fee fields.
		let mut replacement_tx = tip.tx.clone();
		replacement_tx.max_fee_per_gas = bumped.max_fee_per_gas;
		replacement_tx.max_priority_fee_per_gas = bumped.max_priority_fee_per_gas;
		replacement_tx.gas_price = bumped.gas_price;

		// 14. Invariants: same nonce/chain/to/data/value as parent.
		debug_assert_eq!(
			replacement_tx.nonce, tip.tx.nonce,
			"bump must preserve nonce"
		);
		debug_assert_eq!(
			replacement_tx.chain_id, tip.tx.chain_id,
			"bump must preserve chain_id"
		);
		debug_assert_eq!(replacement_tx.to, tip.tx.to, "bump must preserve to");
		debug_assert_eq!(replacement_tx.data, tip.tx.data, "bump must preserve data");
		debug_assert_eq!(
			replacement_tx.value, tip.tx.value,
			"bump must preserve value"
		);

		// 14. Allocate child attempt id (the sweeper needs it before deliver
		//     returns so it can repair the post-deliver Planned/Broadcast row).
		let child_attempt_id = Uuid::new_v4().to_string();

		// 15. Build TransactionTracking with a callback that fans monitor
		//     events out to the event bus as DeliveryEvent::Transaction*.
		let event_bus = self.event_bus.clone();
		let callback = Box::new(move |event: TransactionMonitoringEvent| match event {
			TransactionMonitoringEvent::Confirmed {
				id,
				tx_hash,
				tx_type,
				receipt,
			} => {
				event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
						order_id: id,
						tx_hash,
						tx_type,
						receipt,
					}))
					.ok();
			},
			TransactionMonitoringEvent::Failed {
				id,
				tx_hash,
				tx_type,
				error,
				classification,
			} => match classification {
				RevertClassification::StageComplete { .. } => {
					event_bus
						.publish(SolverEvent::Delivery(
							DeliveryEvent::TransactionIndeterminate {
								order_id: id,
								tx_hash,
								tx_type,
								reason: format!("stage-complete revert: {error}"),
							},
						))
						.ok();
				},
				RevertClassification::Terminal { .. } | RevertClassification::Unknown => {
					event_bus
						.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
							order_id: id,
							tx_hash,
							tx_type,
							error,
						}))
						.ok();
				},
			},
			TransactionMonitoringEvent::Indeterminate {
				id,
				tx_hash,
				tx_type,
				reason,
			} => {
				event_bus
					.publish(SolverEvent::Delivery(
						DeliveryEvent::TransactionIndeterminate {
							order_id: id,
							tx_hash,
							tx_type,
							reason,
						},
					))
					.ok();
			},
			TransactionMonitoringEvent::AttemptLedgerConflict {
				id,
				attempt_id,
				tx_type,
				tx_hash,
				attempted_status,
				error,
				context,
			} => {
				event_bus
					.publish(SolverEvent::Delivery(
						DeliveryEvent::TransactionAttemptLedgerConflict {
							order_id: id,
							attempt_id,
							tx_type,
							tx_hash,
							attempted_status,
							error,
							context: context.to_string(),
						},
					))
					.ok();
			},
		});

		let tracking = TransactionTracking {
			id: order_id.to_string(),
			tx_type,
			attempt_recorder: self.attempt_recorder.clone(),
			callback,
			attempt_id: Some(child_attempt_id.clone()),
			replacement_of: Some(tip.id.clone()),
		};

		// 16. Submit and handle outcomes.
		match self.delivery.deliver(replacement_tx, Some(tracking)).await {
			Ok(child_tx_hash) => {
				// Post-deliver repair: if the recorder created the child row
				// in `Planned` (no tx_hash) before submit completed, fix it
				// up to `Broadcast` with the hash. Best-effort; CAS conflicts
				// and terminal rows are both safe to ignore (the monitor's
				// own callback may have already advanced the row).
				match self.attempt_store.get_attempt(&child_attempt_id).await {
					Ok(child) => {
						if child.status == TransactionAttemptStatus::Planned
							&& child.tx_hash.is_none()
						{
							let hash_to_set = child_tx_hash.clone();
							let _ = self
								.attempt_store
								.update_attempt_status(
									&child_attempt_id,
									TransactionAttemptStatus::Broadcast,
									None,
									|a| {
										a.tx_hash = Some(hash_to_set);
									},
								)
								.await;
						}
					},
					Err(e) => {
						tracing::debug!(
							child_attempt_id = %child_attempt_id,
							error = %e,
							"tx_bump: could not read child attempt for post-deliver repair"
						);
					},
				}

				// Best-effort backfill of parent.replaced_by hint.
				if let Err(e) = self
					.attempt_store
					.set_replaced_by(&tip.id, &child_attempt_id)
					.await
				{
					tracing::debug!(
						parent_id = %tip.id,
						child_id = %child_attempt_id,
						error = %e,
						"tx_bump: set_replaced_by failed (best-effort hint)"
					);
				}

				tracing::info!(
					event = "BumpDispatched",
					%order_id,
					parent_attempt_id = %tip.id,
					child_attempt_id = %child_attempt_id,
					chain_id,
					?tx_type,
					bump_percent = policy.bump_percent,
					"tx_bump: dispatched replacement transaction"
				);
			},
			Err(DeliveryError::ReplacementUnderpriced { hint }) => {
				tracing::info!(
					%order_id,
					parent_attempt_id = %tip.id,
					chain_id,
					?tx_type,
					%hint,
					"tx_bump: replacement underpriced; lineage stays eligible for next tick"
				);
			},
			Err(DeliveryError::InsufficientNativeGas(_)) => {
				// `submit()` already recorded `SubmitRejected` on the child row.
			},
			Err(other) => {
				tracing::warn!(
					event = "BumpSubmitFailed",
					%order_id,
					parent_attempt_id = %tip.id,
					chain_id,
					?tx_type,
					error = %other,
					"tx_bump: replacement submit failed"
				);
				self.event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::BumpSubmitFailed {
						order_id: order_id.to_string(),
						parent_attempt_id: tip.id.clone(),
						chain_id,
						tx_type,
						error: other.to_string(),
					}))
					.ok();
			},
		}
	}

	/// Look up the on-chain deadline for the given stage, if the order's
	/// standard exposes one. Returns `None` (fail-open) on:
	/// - storage retrieval error
	/// - order data parse failure
	/// - the standard not implementing `fill_deadline_secs` / `expires_secs`
	/// - any stage other than `Fill` or `Claim`
	///
	/// Fail-open is correct: a missing deadline produces current
	/// (deadline-unaware) bump behavior. No regression risk.
	async fn deadline_for_stage(
		&self,
		order_id: &str,
		tx_type: solver_types::TransactionType,
	) -> Option<u64> {
		let order: solver_types::Order = self
			.storage
			.retrieve(solver_types::StorageKey::Orders.as_str(), order_id)
			.await
			.ok()?;
		let parsed = order.parse_order_data().ok()?;
		match tx_type {
			solver_types::TransactionType::Fill => parsed.fill_deadline_secs(),
			solver_types::TransactionType::Claim => parsed.expires_secs(),
			_ => None,
		}
	}

	/// Emit a `BumpProfitabilityCheckSkipped` event. Called from every
	/// fail-open branch of `should_skip_for_profitability` (and from the
	/// order-lookup branch at the call site in `maybe_bump_component`)
	/// regardless of whether the gate is in fail-open or fail-closed mode.
	fn emit_profitability_check_skipped(
		&self,
		order_id: &str,
		attempt_id: &str,
		chain_id: u64,
		tx_type: solver_types::TransactionType,
		reason: &str,
	) {
		self.event_bus
			.publish(SolverEvent::Delivery(
				DeliveryEvent::BumpProfitabilityCheckSkipped {
					order_id: order_id.to_string(),
					attempt_id: attempt_id.to_string(),
					chain_id,
					tx_type,
					reason: reason.to_string(),
				},
			))
			.ok();
	}

	/// Returns `true` if the bump should be skipped due to insufficient
	/// order-level profitability headroom.
	///
	/// Fail-open branches (missing quote, pricing error, decimal parse,
	/// etc.) emit `BumpProfitabilityCheckSkipped` and then either skip
	/// (when `policy.profitability_gate_fail_closed == true`) or proceed
	/// (default) with the bump. The event fires in both modes.
	async fn should_skip_for_profitability(
		&self,
		order: &solver_types::Order,
		bumped: &crate::bump::policy::BumpFees,
		tip: &solver_types::TransactionAttempt,
		chain_id: u64,
		tx_type: solver_types::TransactionType,
		policy: &EffectiveTxBumpPolicy,
	) -> bool {
		use rust_decimal::Decimal;
		use std::str::FromStr;

		// `fail_closed` is the boolean the seven fail-open branches return:
		// `true` skips the bump, `false` proceeds.
		let fail_closed = policy.profitability_gate_fail_closed;

		// Fail-open: no quote_id → no profitability data.
		let Some(quote_id) = order.quote_id.as_ref() else {
			tracing::warn!(
				order_id = %order.id,
				"tx_bump: order has no quote_id; profitability gate cannot run (fail-open)"
			);
			self.emit_profitability_check_skipped(
				&order.id,
				&tip.id,
				chain_id,
				tx_type,
				"no quote_id",
			);
			return fail_closed;
		};

		// Fail-open: stored quote lookup error → proceed with warn.
		let stored: solver_types::StoredQuote = match self
			.storage
			.retrieve(solver_types::StorageKey::Quotes.as_str(), quote_id)
			.await
		{
			Ok(s) => s,
			Err(e) => {
				tracing::warn!(
					order_id = %order.id,
					%quote_id,
					error = %e,
					"tx_bump: stored quote lookup failed; proceeding with bump (fail-open)"
				);
				self.emit_profitability_check_skipped(
					&order.id,
					&tip.id,
					chain_id,
					tx_type,
					"stored quote lookup failed",
				);
				return fail_closed;
			},
		};
		let cb = &stored.cost_context.cost_breakdown;

		// Fail-open: tip has no gas_limit → cannot compute cost.
		let Some(gas_units) = tip.tx.gas_limit else {
			tracing::warn!(
				order_id = %order.id,
				tip_id = %tip.id,
				"tx_bump: tip.tx.gas_limit is None; proceeding with bump (fail-open)"
			);
			self.emit_profitability_check_skipped(
				&order.id,
				&tip.id,
				chain_id,
				tx_type,
				"tip gas_limit missing",
			);
			return fail_closed;
		};

		// Take EIP-1559 max_fee_per_gas first; fall back to legacy gas_price.
		let Some(fee_per_gas) = bumped.max_fee_per_gas.or(bumped.gas_price) else {
			tracing::warn!(
				order_id = %order.id,
				"tx_bump: bumped fees missing both max_fee_per_gas and gas_price; proceeding (fail-open)"
			);
			self.emit_profitability_check_skipped(
				&order.id,
				&tip.id,
				chain_id,
				tx_type,
				"bumped fees missing",
			);
			return fail_closed;
		};

		let bumped_cost_wei = fee_per_gas.saturating_mul(gas_units as u128);

		// Fail-open: pricing error → proceed.
		let bumped_cost_str = match self
			.pricing
			.wei_to_currency(&bumped_cost_wei.to_string(), &cb.currency)
			.await
		{
			Ok(s) => s,
			Err(e) => {
				tracing::warn!(
					order_id = %order.id,
					chain_id,
					error = %e,
					"tx_bump: wei_to_currency failed; proceeding with bump (fail-open)"
				);
				self.emit_profitability_check_skipped(
					&order.id,
					&tip.id,
					chain_id,
					tx_type,
					"wei_to_currency error",
				);
				return fail_closed;
			},
		};

		let bumped_cost = match Decimal::from_str(&bumped_cost_str) {
			Ok(d) => d,
			Err(e) => {
				tracing::warn!(
					order_id = %order.id,
					cost_str = %bumped_cost_str,
					error = %e,
					"tx_bump: bumped cost not parseable as Decimal; proceeding (fail-open)"
				);
				self.emit_profitability_check_skipped(
					&order.id,
					&tip.id,
					chain_id,
					tx_type,
					"decimal parse error",
				);
				return fail_closed;
			},
		};

		let original_budget = match tx_type {
			solver_types::TransactionType::Prepare => cb.gas_open,
			solver_types::TransactionType::Fill => cb.gas_fill,
			solver_types::TransactionType::PostFill => cb.gas_post_fill,
			solver_types::TransactionType::PreClaim => cb.gas_pre_claim,
			solver_types::TransactionType::Claim => cb.gas_claim,
		};

		let headroom = cb.gas_buffer + cb.min_profit;
		let delta = bumped_cost - original_budget;

		if delta > headroom {
			self.event_bus
				.publish(SolverEvent::Delivery(
					DeliveryEvent::BumpExceedsProfitability {
						order_id: order.id.clone(),
						attempt_id: tip.id.clone(),
						chain_id,
						tx_type,
						proposed_cost: bumped_cost.to_string(),
						original_stage_budget: original_budget.to_string(),
						headroom: headroom.to_string(),
						currency: cb.currency.clone(),
					},
				))
				.ok();
			return true;
		}
		false
	}
}

/// Compute the up-front native-gas budget required to submit `bumped` over
/// the original tip transaction: `gas_limit * fee + value`. Saturating math
/// guards against pathological inputs.
fn required_balance_wei(bumped: &BumpFees, original_tx: &solver_types::Transaction) -> U256 {
	let gas_limit = U256::from(original_tx.gas_limit.unwrap_or(0));
	let fee = bumped.max_fee_per_gas.or(bumped.gas_price).unwrap_or(0);
	gas_limit
		.saturating_mul(U256::from(fee))
		.saturating_add(original_tx.value)
}

#[derive(Debug, thiserror::Error)]
pub enum BumpError {
	#[error("Storage error: {0}")]
	Storage(String),
}

/// Loads non-terminal order IDs. Mirrors `RecoveryService::load_active_orders`
/// (which queries the order store by `status_kind` index).
async fn load_active_order_ids(storage: &Arc<StorageService>) -> Result<Vec<String>, BumpError> {
	use crate::state::order::{
		FAILED_STATUS_KIND_INDEX_VALUE, FINALIZED_STATUS_KIND_INDEX_VALUE, STATUS_KIND_INDEX_FIELD,
	};
	use solver_storage::QueryFilter;
	use solver_types::{Order, StorageKey};

	let terminal_status_kinds = vec![
		serde_json::json!(FINALIZED_STATUS_KIND_INDEX_VALUE),
		serde_json::json!(FAILED_STATUS_KIND_INDEX_VALUE),
	];

	let rows = storage
		.query::<Order>(
			StorageKey::Orders.as_str(),
			QueryFilter::NotIn(STATUS_KIND_INDEX_FIELD.to_string(), terminal_status_kinds),
		)
		.await
		.map_err(|e| BumpError::Storage(e.to_string()))?;
	Ok(rows.into_iter().map(|(id, _)| id).collect())
}

#[cfg(test)]
mod tests {
	use super::*;
	use mockall::predicate::*;
	use solver_delivery::{
		DeliveryInterface, MockDeliveryInterface, RevertClassification, StageCompleteReason,
		TransactionTrackingWithConfig,
	};
	use solver_storage::implementations::file::{FileStorage, TtlConfig};
	use solver_types::{
		utils::tests::builders::OrderBuilder, Address, BumpCapField, OrderStatus,
		TransactionAttempt, TransactionAttemptStatus, TransactionHash, TransactionType,
	};
	use std::collections::HashMap;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Arc;

	/// Drain matching events from a broadcast subscriber for assertions.
	fn drain_bus_events(
		sub: &mut tokio::sync::broadcast::Receiver<SolverEvent>,
	) -> Vec<SolverEvent> {
		let mut out = Vec::new();
		while let Ok(ev) = sub.try_recv() {
			out.push(ev);
		}
		out
	}

	/// Mock-test helper: simulate the recorder lifecycle that the real
	/// submit path performs. Without this, `MockDeliveryInterface::submit`
	/// would not create the child attempt row — tests that assert on the
	/// row need this to faithfully simulate production.
	///
	/// `signer` mirrors the production Alloy path, which records the
	/// actual submission signer on the child row. Tests should pass the
	/// same signer they used to seed the parent attempt so follow-up ticks
	/// see a same-signer lineage instead of `BumpMissingSigner`.
	async fn simulate_submit_recording(
		recorder: &Arc<dyn TransactionAttemptRecorder>,
		tracking: &TransactionTrackingWithConfig,
		tx: &solver_types::Transaction,
		outcome: &Result<TransactionHash, DeliveryError>,
		signer: Option<Address>,
	) {
		let init = solver_delivery::PlannedAttemptInit {
			order_id: tracking.tracking.id.clone(),
			signer,
			tx_type: tracking.tracking.tx_type,
			tx: tx.clone(),
			attempt_id_override: tracking.tracking.attempt_id.clone(),
			replacement_of: tracking.tracking.replacement_of.clone(),
		};
		let attempt = recorder.record_planned_attempt(init).await.unwrap();
		match outcome {
			Ok(hash) => {
				let _ = recorder
					.record_attempt_update(
						&attempt.id,
						TransactionAttemptStatus::Broadcast,
						Some(hash.clone()),
						None,
						None,
					)
					.await;
			},
			Err(e) => {
				let _ = recorder
					.record_attempt_update(
						&attempt.id,
						TransactionAttemptStatus::SubmitRejected,
						None,
						None,
						Some(e.to_string()),
					)
					.await;
			},
		}
	}

	fn test_service(
		cfg: TxBumpConfig,
		delivery: MockDeliveryInterface,
	) -> (
		TransactionBumpService,
		Arc<TransactionAttemptStore>,
		Arc<StorageService>,
		EventBus,
		tempfile::TempDir,
	) {
		let tmp = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			tmp.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(delivery) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let event_bus = EventBus::new(100);
		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let service = TransactionBumpService::new(
			cfg,
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			event_bus.clone(),
			recorder,
			test_pricing(),
		);
		(service, attempt_store, storage, event_bus, tmp)
	}

	fn default_enabled_config() -> TxBumpConfig {
		let mut cfg = TxBumpConfig {
			enabled: true,
			default_pending_threshold_secs: 1, // age out quickly in tests
			default_receipt_preflight_fail_closed: false,
			..TxBumpConfig::default()
		};
		cfg.chains
			.insert(1u64, solver_config::TxBumpChainConfig::default());
		cfg
	}

	fn tx_with_fees(max_fee: u128) -> solver_types::Transaction {
		use alloy_primitives::U256;
		solver_types::Transaction {
			to: Some(Address(vec![1; 20])),
			data: vec![],
			value: U256::ZERO,
			chain_id: 1,
			nonce: Some(0),
			gas_limit: Some(100_000),
			gas_price: None,
			max_fee_per_gas: Some(max_fee),
			max_priority_fee_per_gas: Some(max_fee / 10),
		}
	}

	fn test_pricing() -> Arc<solver_pricing::PricingService> {
		Arc::new(solver_pricing::PricingService::new(
			Box::new(
				solver_pricing::implementations::mock::MockPricing::new(&serde_json::json!({}))
					.expect("mock pricing init"),
			),
			vec![],
		))
	}

	/// Seed an attempt with a fixed id and status. If `status != Planned`,
	/// also flips the row to that status via the public update path so the
	/// tx_hash field is populated and `updated_at` is current.
	async fn seed_attempt(
		store: &TransactionAttemptStore,
		id: &str,
		status: TransactionAttemptStatus,
		replacement_of: Option<&str>,
		signer: Option<Address>,
		max_fee: u128,
	) -> TransactionAttempt {
		let init = solver_delivery::PlannedAttemptInit {
			order_id: "order-1".into(),
			signer,
			tx_type: TransactionType::Fill,
			tx: tx_with_fees(max_fee),
			attempt_id_override: Some(id.into()),
			replacement_of: replacement_of.map(String::from),
		};
		let attempt = store.record_planned_attempt(init).await.unwrap();
		if status != TransactionAttemptStatus::Planned {
			let _ = store
				.update_attempt_status(&attempt.id, status, None, |a| {
					a.tx_hash = Some(TransactionHash(vec![0; 32]));
				})
				.await;
		}
		attempt
	}

	/// Seed an active (non-terminal) order so `load_active_order_ids` returns it.
	async fn seed_active_order(storage: &Arc<StorageService>, order_id: &str) {
		use crate::state::order::OrderStateMachine;
		let sm = OrderStateMachine::new(storage.clone());
		let order = OrderBuilder::new()
			.with_id(order_id.to_string())
			.with_status(OrderStatus::Executing)
			.build();
		sm.store_order(&order).await.unwrap();
	}

	/// Seed an active order whose data carries a specific `fill_deadline`
	/// (seconds since epoch). The data is built via `Eip7683OrderDataBuilder`
	/// so `Order::parse_order_data()` succeeds at the gate site.
	async fn seed_active_order_with_fill_deadline(
		storage: &Arc<StorageService>,
		order_id: &str,
		fill_deadline_secs: u32,
	) {
		use crate::state::order::OrderStateMachine;
		use solver_types::utils::tests::builders::Eip7683OrderDataBuilder;
		let sm = OrderStateMachine::new(storage.clone());
		let eip7683 = Eip7683OrderDataBuilder::new()
			.fill_deadline(fill_deadline_secs)
			.build();
		let data = serde_json::to_value(&eip7683).expect("serialize eip7683 order data");
		let order = OrderBuilder::new()
			.with_id(order_id.to_string())
			.with_status(OrderStatus::Executing)
			.with_data(data)
			.build();
		sm.store_order(&order).await.unwrap();
	}

	/// Seed an active order with `quote_id` set + a matching `StoredQuote`.
	/// Replaces `seed_active_order` for tests that need profitability data.
	async fn seed_active_order_with_quote(
		storage: &Arc<StorageService>,
		order_id: &str,
		quote_id: &str,
		gas_fill: rust_decimal::Decimal,
		gas_buffer: rust_decimal::Decimal,
		min_profit: rust_decimal::Decimal,
	) {
		use crate::state::order::OrderStateMachine;
		use rust_decimal::Decimal;
		use solver_types::costs::{CostBreakdown, CostContext};
		use solver_types::{
			FailureHandlingMode, OifOrder, OrderPayload, OrderStatus, Quote, QuotePreview,
			SignatureType, StorageKey, StoredQuote, SwapType,
		};

		// Order: same status as seed_active_order, with quote_id set.
		let mut order = OrderBuilder::new()
			.with_id(order_id.to_string())
			.with_status(OrderStatus::Executing)
			.build();
		order.quote_id = Some(quote_id.to_string());

		let sm = OrderStateMachine::new(storage.clone());
		sm.store_order(&order).await.unwrap();

		let cb = CostBreakdown {
			gas_open: Decimal::ZERO,
			gas_fill,
			gas_post_fill: Decimal::ZERO,
			gas_pre_claim: Decimal::ZERO,
			gas_claim: Decimal::ZERO,
			gas_buffer,
			rate_buffer: Decimal::ZERO,
			base_price: Decimal::ZERO,
			min_profit,
			operational_cost: gas_fill + gas_buffer,
			subtotal: gas_fill + gas_buffer,
			total: gas_fill + gas_buffer + min_profit,
			currency: "USD".into(),
		};

		let stored = StoredQuote {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: solver_types::current_timestamp() + 300,
				eta: Some(60),
				quote_id: quote_id.to_string(),
				provider: Some("test_solver".to_string()),
				preview: QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: CostContext {
				cost_breakdown: cb,
				execution_costs_by_chain: std::collections::HashMap::new(),
				liquidity_cost_adjustment: Decimal::ZERO,
				protocol_fees: std::collections::HashMap::new(),
				swap_type: SwapType::ExactInput,
				cost_amounts_in_tokens: std::collections::HashMap::new(),
				swap_amounts: std::collections::HashMap::new(),
				adjusted_amounts: std::collections::HashMap::new(),
			},
			settlement_name: None,
		};
		storage
			.store(StorageKey::Quotes.as_str(), quote_id, &stored, None)
			.await
			.unwrap();
	}

	/// Always-large `get_balance` mock (so the balance check never blocks dispatch).
	fn mock_large_balance(mock: &mut MockDeliveryInterface) {
		mock.expect_get_balance()
			.returning(|_, _, _| Box::pin(async move { Ok("1000000000000000000000".to_string()) }));
	}

	fn receipt(hash: TransactionHash, success: bool) -> solver_types::TransactionReceipt {
		solver_types::TransactionReceipt {
			hash,
			block_number: 12345,
			success,
			block_timestamp: None,
			logs: vec![],
		}
	}

	// =====================================================================
	// 1. Happy bump: dispatches replacement with bumped fees.
	// =====================================================================
	#[tokio::test]
	async fn happy_bump_dispatches_replacement_with_bumped_fees() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		let signer = Address(vec![9; 20]);
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);

		// We need a handle to the recorder before service construction —
		// we build the service first, capture the attempt_store, and use
		// it inside the expect_submit closure.
		let (service, attempt_store, storage, _bus, _tmp) =
			test_service(cfg, MockDeliveryInterface::new());
		seed_active_order(&storage, "order-1").await;
		let _parent = seed_attempt(
			&attempt_store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000, // 10 gwei
		)
		.await;

		// Re-build the mock with submit() expectation now that we have a store.
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let recorder_for_mock = recorder.clone();
		mock.expect_submit()
			.times(1)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					let outcome: Result<TransactionHash, DeliveryError> =
						Ok(TransactionHash(vec![0xab; 32]));
					simulate_submit_recording(
						&recorder,
						&tracking,
						&tx,
						&outcome,
						Some(Address(vec![9; 20])),
					)
					.await;
					outcome
				})
			});

		// Replace the delivery in a fresh service that reuses the same store.
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let service = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			service.event_bus.clone(),
			recorder.clone(),
			test_pricing(),
		);

		// Wait so the age threshold elapses.
		tokio::time::sleep(Duration::from_secs(2)).await;
		service.tick().await.unwrap();

		let all = attempt_store.attempts_for_order("order-1").await.unwrap();
		assert_eq!(all.len(), 2, "should now have parent + child");
		let parent = all.iter().find(|a| a.id == "parent-1").unwrap();
		assert!(parent.replaced_by.is_some(), "parent.replaced_by hint set");
		let child = all.iter().find(|a| a.id != "parent-1").unwrap();
		assert_eq!(child.replacement_of.as_deref(), Some("parent-1"));
		// 15% bump default: 10 gwei -> 11.5 gwei
		assert_eq!(child.tx.max_fee_per_gas, Some(11_500_000_000));
	}

	// =====================================================================
	// 2. Disabled config: run() exits without ticking.
	// =====================================================================
	#[tokio::test]
	async fn disabled_skips_dispatch() {
		let mut cfg = default_enabled_config();
		cfg.enabled = false;
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		// No need for other mocks because run() exits immediately when disabled.

		let (svc, _store, _storage, _bus, _tmp) = test_service(cfg, mock);
		let svc = Arc::new(svc);
		let (tx, rx) = tokio::sync::watch::channel(false);
		let svc2 = svc.clone();
		let h = tokio::spawn(async move { svc2.run(rx).await });
		tokio::time::sleep(Duration::from_millis(100)).await;
		let _ = tx.send(true);
		h.await.unwrap();
		// expect_submit().times(0) asserts on drop.
	}

	// =====================================================================
	// 3. Chain not in allowlist: skipped silently.
	// =====================================================================
	#[tokio::test]
	async fn chain_not_in_allowlist_skips() {
		let mut cfg = default_enabled_config();
		cfg.chains.clear();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		// submission_signer / balance may or may not be called depending on
		// where the allowlist check sits; configure them as no-strict mocks.
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, _bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000,
		)
		.await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
	}

	// =====================================================================
	// 4. Age below threshold: skipped.
	// =====================================================================
	#[tokio::test]
	async fn age_below_threshold_skips() {
		let mut cfg = default_enabled_config();
		cfg.default_pending_threshold_secs = 3600;
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, _bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000,
		)
		.await;
		svc.tick().await.unwrap();
	}

	// =====================================================================
	// 5. Cap reached: skipped with BumpCapReached event.
	// =====================================================================
	#[tokio::test]
	async fn cap_reached_skips_with_event() {
		let mut cfg = default_enabled_config();
		cfg.default_max_fee_per_gas_cap_wei = Some("11000000000".into());
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000, // bumped 15% -> 11.5 gwei, exceeds 11 gwei cap
		)
		.await;
		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|e| matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::BumpCapReached {
					cap_field: BumpCapField::MaxFeePerGas,
					..
				})
			)),
			"expected BumpCapReached, got events: {events:?}"
		);
	}

	// =====================================================================
	// 6. Max replacements reached: skipped with BumpMaxReplacementsReached.
	// =====================================================================
	#[tokio::test]
	async fn max_replacements_reached_skips_with_event() {
		let mut cfg = default_enabled_config();
		// Allow only 2 replacements per stage.
		if let Some(c) = cfg.chains.get_mut(&1) {
			c.max_replacements_per_stage = Some(2);
		}
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"a",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000,
		)
		.await;
		seed_attempt(
			&store,
			"b",
			TransactionAttemptStatus::Broadcast,
			Some("a"),
			Some(Address(vec![9; 20])),
			11_500_000_000,
		)
		.await;
		seed_attempt(
			&store,
			"c",
			TransactionAttemptStatus::Broadcast,
			Some("b"),
			Some(Address(vec![9; 20])),
			13_225_000_000,
		)
		.await;

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|e| matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::BumpMaxReplacementsReached { .. })
			)),
			"expected BumpMaxReplacementsReached, got events: {events:?}"
		);
	}

	// =====================================================================
	// 7. ReplacementUnderpriced preserves the rejected child's fees on its row.
	// =====================================================================
	#[tokio::test]
	async fn replacement_underpriced_preserves_rejected_child_fees() {
		let cfg = default_enabled_config();
		let (service, attempt_store, storage, bus, _tmp) =
			test_service(cfg, MockDeliveryInterface::new());
		seed_active_order(&storage, "order-1").await;
		let signer = Address(vec![9; 20]);
		seed_attempt(
			&attempt_store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000,
		)
		.await;

		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let recorder_for_mock = recorder.clone();
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		mock.expect_submit()
			.times(1)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					let outcome: Result<TransactionHash, DeliveryError> =
						Err(DeliveryError::ReplacementUnderpriced {
							hint: "node says too low".into(),
						});
					simulate_submit_recording(
						&recorder,
						&tracking,
						&tx,
						&outcome,
						Some(Address(vec![9; 20])),
					)
					.await;
					outcome
				})
			});
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let service = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			bus.clone(),
			recorder.clone(),
			test_pricing(),
		);

		tokio::time::sleep(Duration::from_secs(2)).await;
		service.tick().await.unwrap();

		let all = attempt_store.attempts_for_order("order-1").await.unwrap();
		assert_eq!(all.len(), 2);
		let child = all.iter().find(|a| a.id != "parent-1").unwrap();
		assert_eq!(child.status, TransactionAttemptStatus::SubmitRejected);
		assert!(
			child.tx.max_fee_per_gas.unwrap() > 10_000_000_000,
			"child fee {} must be > parent 10 gwei (proof of 15% bump preserved)",
			child.tx.max_fee_per_gas.unwrap()
		);
	}

	// =====================================================================
	// 8. ReplacementUnderpriced self-escalates: tick 2 dispatches at higher fee.
	// =====================================================================
	#[tokio::test]
	async fn replacement_underpriced_self_escalates_on_second_tick() {
		let cfg = default_enabled_config();
		let (service, attempt_store, storage, bus, _tmp) =
			test_service(cfg, MockDeliveryInterface::new());
		seed_active_order(&storage, "order-1").await;
		let signer = Address(vec![9; 20]);
		seed_attempt(
			&attempt_store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000,
		)
		.await;

		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let recorder_for_mock = recorder.clone();
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let counter = Arc::new(AtomicUsize::new(0));
		let counter_for_mock = counter.clone();
		// Capture the second-tick tx's max_fee_per_gas for an assertion.
		let second_tick_fee = Arc::new(std::sync::Mutex::new(None::<u128>));
		let second_tick_fee_for_mock = second_tick_fee.clone();
		mock.expect_submit()
			.times(2)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				let n = counter_for_mock.fetch_add(1, Ordering::SeqCst);
				let second_tick_fee = second_tick_fee_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					if n == 0 {
						let outcome: Result<TransactionHash, DeliveryError> =
							Err(DeliveryError::ReplacementUnderpriced {
								hint: "too low".into(),
							});
						simulate_submit_recording(
							&recorder,
							&tracking,
							&tx,
							&outcome,
							Some(Address(vec![9; 20])),
						)
						.await;
						outcome
					} else {
						*second_tick_fee.lock().unwrap() = tx.max_fee_per_gas;
						let outcome: Result<TransactionHash, DeliveryError> =
							Ok(TransactionHash(vec![0xcd; 32]));
						simulate_submit_recording(
							&recorder,
							&tracking,
							&tx,
							&outcome,
							Some(Address(vec![9; 20])),
						)
						.await;
						outcome
					}
				})
			});
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let service = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			bus.clone(),
			recorder.clone(),
			test_pricing(),
		);

		tokio::time::sleep(Duration::from_secs(2)).await;
		service.tick().await.unwrap();
		// Second tick: lineage age has elapsed; rejected child's bumped fee is the new floor.
		tokio::time::sleep(Duration::from_secs(2)).await;
		service.tick().await.unwrap();

		// Tick 1 bumped 10 gwei -> 11.5 gwei (rejected). Tick 2 must bump
		// above 11.5 gwei (self-escalation using rejected child's fees as floor).
		let f = second_tick_fee
			.lock()
			.unwrap()
			.expect("second tick should have run");
		assert!(
			f > 11_500_000_000,
			"second tick max_fee {f} should exceed first-bump 11.5 gwei (self-escalation)"
		);
	}

	// =====================================================================
	// 9. Reconciliation marks loser as Replaced.
	// =====================================================================
	#[tokio::test]
	async fn reconciliation_marks_loser_replaced() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, _bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"p",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000,
		)
		.await;
		seed_attempt(
			&store,
			"b",
			TransactionAttemptStatus::Confirmed,
			Some("p"),
			Some(Address(vec![9; 20])),
			11_500_000_000,
		)
		.await;
		// Make parent.replaced_by = Some("b") to mirror lineage hint.
		store.set_replaced_by("p", "b").await.unwrap();

		svc.tick().await.unwrap();

		let p = store.get_attempt("p").await.unwrap();
		assert_eq!(p.status, TransactionAttemptStatus::Replaced);
	}

	// =====================================================================
	// 10. Reconciliation still works when parent.replaced_by was never set
	//     (CAS-fail simulation): traversal is via child.replacement_of only.
	// =====================================================================
	#[tokio::test]
	async fn reconciliation_with_no_lineage_parent() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, _bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"p",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000,
		)
		.await;
		seed_attempt(
			&store,
			"b",
			TransactionAttemptStatus::Confirmed,
			Some("p"),
			Some(Address(vec![9; 20])),
			11_500_000_000,
		)
		.await;
		// Intentionally do NOT call set_replaced_by — simulates CAS-fail.

		svc.tick().await.unwrap();

		let p = store.get_attempt("p").await.unwrap();
		assert_eq!(p.status, TransactionAttemptStatus::Replaced);
	}

	// =====================================================================
	// 11. Reconciliation respects is_terminal: Reverted parent is NOT overwritten.
	// =====================================================================
	#[tokio::test]
	async fn reconciliation_respects_is_terminal() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, _bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"p",
			TransactionAttemptStatus::Reverted,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000,
		)
		.await;
		seed_attempt(
			&store,
			"b",
			TransactionAttemptStatus::Confirmed,
			Some("p"),
			Some(Address(vec![9; 20])),
			11_500_000_000,
		)
		.await;

		svc.tick().await.unwrap();

		let p = store.get_attempt("p").await.unwrap();
		assert_eq!(
			p.status,
			TransactionAttemptStatus::Reverted,
			"terminal parent must NOT be overwritten by reconciliation"
		);
	}

	// =====================================================================
	// 12. Signer mismatch emits event and skips.
	// =====================================================================
	#[tokio::test]
	async fn signer_mismatch_emits_event_and_skips() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		let runtime_signer = Address(vec![0xbb; 20]);
		let runtime_signer_clone = runtime_signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(runtime_signer_clone.clone()));
		mock_large_balance(&mut mock);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![0xaa; 20])),
			10_000_000_000,
		)
		.await;
		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|e| matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::BumpSignerMismatch { .. })
			)),
			"expected BumpSignerMismatch, got events: {events:?}"
		);
	}

	// =====================================================================
	// 13. Tip with missing signer emits BumpMissingSigner and skips (no panic).
	// =====================================================================
	#[tokio::test]
	async fn tip_missing_signer_emits_event_no_panic() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			None, // signer absent
			10_000_000_000,
		)
		.await;
		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|e| matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::BumpMissingSigner { .. })
			)),
			"expected BumpMissingSigner, got events: {events:?}"
		);
	}

	// =====================================================================
	// 14. Deadline guard: Fill past fillDeadline → skip + BumpDeadlineExpired.
	// =====================================================================
	#[tokio::test]
	async fn bump_skips_fill_after_fill_deadline_expired() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		// The whole point: submit MUST NOT fire.
		mock.expect_submit().times(0);
		mock.expect_submission_signer()
			.returning(|_| Some(Address(vec![9; 20])));
		mock_large_balance(&mut mock);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		// Seed an order whose fill_deadline is in the PAST (10s ago).
		let now = solver_types::current_timestamp() as u32;
		seed_active_order_with_fill_deadline(&storage, "order-1", now.saturating_sub(10)).await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000,
		)
		.await;

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|e| matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::BumpDeadlineExpired { .. })
			)),
			"expected BumpDeadlineExpired, got events: {events:?}"
		);
	}

	// =====================================================================
	// 15. Deadline guard: Fill before fillDeadline → bump proceeds as normal.
	// =====================================================================
	#[tokio::test]
	async fn bump_proceeds_when_fill_deadline_in_future() {
		let cfg = default_enabled_config();
		let signer = Address(vec![9; 20]);

		// Stage 1: throwaway service to obtain attempt_store + storage Arcs.
		let throwaway_mock = {
			let mut m = MockDeliveryInterface::new();
			let s = signer.clone();
			m.expect_submission_signer()
				.returning(move |_| Some(s.clone()));
			mock_large_balance(&mut m);
			m
		};
		let (service, attempt_store, storage, _bus, _tmp) =
			test_service(cfg.clone(), throwaway_mock);

		let now = solver_types::current_timestamp() as u32;
		// fill_deadline far in future → gate passes.
		seed_active_order_with_fill_deadline(&storage, "order-1", now + 1800).await;
		seed_attempt(
			&attempt_store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000,
		)
		.await;

		// Stage 2: real mock that expects submit to fire.
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let recorder_for_mock = recorder.clone();
		mock.expect_submit()
			.times(1)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					let outcome: Result<TransactionHash, DeliveryError> =
						Ok(TransactionHash(vec![0xab; 32]));
					simulate_submit_recording(
						&recorder,
						&tracking,
						&tx,
						&outcome,
						Some(Address(vec![9; 20])),
					)
					.await;
					outcome
				})
			});
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let svc = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			service.event_bus.clone(),
			recorder,
			test_pricing(),
		);

		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		// mock.expect_submit().times(1) panics on Drop if unmet → asserts success.
	}

	#[tokio::test]
	async fn stage_complete_revert_from_bump_callback_is_indeterminate_not_failed() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		let signer = Address(vec![9; 20]);
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		mock.expect_submit().times(1).returning(|_tx, tracking| {
			Box::pin(async move {
				let tracking = tracking.expect("sweeper must supply tracking");
				(tracking.tracking.callback)(TransactionMonitoringEvent::Failed {
					id: "order-1".into(),
					tx_hash: TransactionHash(vec![0xab; 32]),
					tx_type: TransactionType::Fill,
					error: "Already claimed".into(),
					classification: RevertClassification::StageComplete {
						reason: StageCompleteReason::AlreadyClaimed,
					},
				});
				Ok(TransactionHash(vec![0xcd; 32]))
			})
		});

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer),
			10_000_000_000,
		)
		.await;
		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|e| matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::TransactionIndeterminate { .. })
			)),
			"expected TransactionIndeterminate, got events: {events:?}"
		);
		assert!(
			!events.iter().any(|e| matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::TransactionFailed { .. })
			)),
			"StageComplete revert must not publish TransactionFailed: {events:?}"
		);
	}

	// =====================================================================
	// 14. Profitability gate: cost exceeds order margin → skip with event.
	// =====================================================================
	#[tokio::test]
	async fn bump_skips_when_cost_exceeds_order_margin() {
		use rust_decimal::Decimal;

		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		let signer = Address(vec![9; 20]);
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		// The whole point of this test: submit MUST NOT fire.
		mock.expect_submit().times(0);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);

		// Order-1 with tight headroom: gas_fill=$0.10, buffer=$0.02,
		// min_profit=$0.03 → headroom = $0.05.
		seed_active_order_with_quote(
			&storage,
			"order-1",
			"quote-1",
			Decimal::new(10, 2), // $0.10
			Decimal::new(2, 2),  // $0.02
			Decimal::new(3, 2),  // $0.03
		)
		.await;

		// Parent at 100 gwei × 100k gas (gas_limit baked into tx_with_fees).
		// 15% bump → 115 gwei. With MockPricing's default ETH/USD,
		// bumped_cost = 115e9 × 100_000 wei × ETH price ≫ headroom ($0.05).
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			100_000_000_000u128, // 100 gwei
		)
		.await;

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);

		assert!(
			events.iter().any(|e| matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::BumpExceedsProfitability { .. })
			)),
			"expected BumpExceedsProfitability, got events: {events:?}"
		);
	}

	// =====================================================================
	// 15. Profitability gate: cost within headroom → bump proceeds.
	// Uses the same two-stage construction as happy_bump_dispatches_*.
	// =====================================================================
	#[tokio::test]
	async fn bump_proceeds_when_cost_within_order_margin() {
		use rust_decimal::Decimal;

		let cfg = default_enabled_config();
		let signer = Address(vec![9; 20]);

		// Stage 1: throwaway service to obtain attempt_store + storage Arcs.
		let throwaway_mock = {
			let mut m = MockDeliveryInterface::new();
			let s = signer.clone();
			m.expect_submission_signer()
				.returning(move |_| Some(s.clone()));
			mock_large_balance(&mut m);
			m
		};
		let (service, attempt_store, storage, _bus, _tmp) =
			test_service(cfg.clone(), throwaway_mock);

		// Generous headroom: gas_fill=$10, buffer=$5, min_profit=$5 → $10 over.
		// 10 gwei × 100k gas × ETH price ≪ headroom → bump fires.
		seed_active_order_with_quote(
			&storage,
			"order-1",
			"quote-1",
			Decimal::new(10, 0), // $10
			Decimal::new(5, 0),  // $5
			Decimal::new(5, 0),  // $5
		)
		.await;
		seed_attempt(
			&attempt_store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000u128, // 10 gwei
		)
		.await;

		// Stage 2: real mock with submit-recording closure.
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let recorder_for_mock = recorder.clone();
		mock.expect_submit()
			.times(1)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					let outcome: Result<TransactionHash, DeliveryError> =
						Ok(TransactionHash(vec![0xab; 32]));
					simulate_submit_recording(
						&recorder,
						&tracking,
						&tx,
						&outcome,
						Some(Address(vec![9; 20])),
					)
					.await;
					outcome
				})
			});
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let svc = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			service.event_bus.clone(),
			recorder,
			test_pricing(),
		);

		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		// mock.expect_submit().times(1) panics on Drop if unmet → asserts success.
	}

	// =====================================================================
	// 16. Profitability gate fail-open: no quote_id → bump proceeds silently.
	// =====================================================================
	#[tokio::test]
	async fn bump_proceeds_when_order_has_no_quote_id() {
		let cfg = default_enabled_config();
		let signer = Address(vec![9; 20]);

		// Stage 1.
		let throwaway_mock = {
			let mut m = MockDeliveryInterface::new();
			let s = signer.clone();
			m.expect_submission_signer()
				.returning(move |_| Some(s.clone()));
			mock_large_balance(&mut m);
			m
		};
		let (service, attempt_store, storage, _bus, _tmp) =
			test_service(cfg.clone(), throwaway_mock);

		// Use existing seed_active_order → OrderBuilder default leaves
		// quote_id = None → gate hits fail-open.
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&attempt_store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000u128,
		)
		.await;

		// Stage 2: real mock — same pattern as test 15.
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let recorder_for_mock = recorder.clone();
		mock.expect_submit()
			.times(1)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					let outcome: Result<TransactionHash, DeliveryError> =
						Ok(TransactionHash(vec![0xab; 32]));
					simulate_submit_recording(
						&recorder,
						&tracking,
						&tx,
						&outcome,
						Some(Address(vec![9; 20])),
					)
					.await;
					outcome
				})
			});
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let svc = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			service.event_bus.clone(),
			recorder,
			test_pricing(),
		);

		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		// expect_submit().times(1) asserts the bump fired despite no quote_id.
	}

	// =====================================================================
	// 17. Profitability gate fail-open (default) emits
	// `BumpProfitabilityCheckSkipped` with reason="no quote_id" while the
	// bump still proceeds. Locks in the observability half of OZ's review.
	// =====================================================================
	#[tokio::test]
	async fn bump_proceeds_when_no_quote_id_emits_skipped_event() {
		let cfg = default_enabled_config();
		// Sanity-check: default is fail-open across the workspace.
		assert!(
			!cfg.chains
				.get(&1u64)
				.unwrap()
				.profitability_gate_fail_closed
				.unwrap_or(cfg.default_profitability_gate_fail_closed),
			"default policy must be fail-open"
		);

		let signer = Address(vec![9; 20]);

		// Stage 1: throwaway service to obtain attempt_store + storage Arcs.
		let throwaway_mock = {
			let mut m = MockDeliveryInterface::new();
			let s = signer.clone();
			m.expect_submission_signer()
				.returning(move |_| Some(s.clone()));
			mock_large_balance(&mut m);
			m
		};
		let (service, attempt_store, storage, bus, _tmp) =
			test_service(cfg.clone(), throwaway_mock);

		// Default OrderBuilder leaves quote_id = None.
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&attempt_store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000u128,
		)
		.await;

		// Stage 2: real mock — submit MUST fire (fail-open proceeds).
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let recorder_for_mock = recorder.clone();
		mock.expect_submit()
			.times(1)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					let outcome: Result<TransactionHash, DeliveryError> =
						Ok(TransactionHash(vec![0xab; 32]));
					simulate_submit_recording(
						&recorder,
						&tracking,
						&tx,
						&outcome,
						Some(Address(vec![9; 20])),
					)
					.await;
					outcome
				})
			});
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let svc = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			service.event_bus.clone(),
			recorder,
			test_pricing(),
		);

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);

		let found = events.iter().any(|e| {
			matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::BumpProfitabilityCheckSkipped {
					order_id, reason, tx_type, chain_id, ..
				}) if order_id == "order-1"
					&& reason == "no quote_id"
					&& *tx_type == TransactionType::Fill
					&& *chain_id == 1u64
			)
		});
		assert!(
			found,
			"expected BumpProfitabilityCheckSkipped(no quote_id), got: {events:?}"
		);
		// expect_submit().times(1) on Drop also asserts the bump fired.
	}

	// =====================================================================
	// 18. Profitability gate fail-closed: same scenario, but the bump is
	// skipped while the same event still fires.
	// =====================================================================
	#[tokio::test]
	async fn bump_skipped_when_fail_closed_and_no_quote_id() {
		let mut cfg = default_enabled_config();
		// Flip the global default to fail-closed. The chain entry inherits
		// it through `for_chain`.
		cfg.default_profitability_gate_fail_closed = true;

		let signer = Address(vec![9; 20]);

		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		// The point: submit MUST NOT fire under fail-closed.
		mock.expect_submit().times(0);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);

		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000u128,
		)
		.await;

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);

		let found = events.iter().any(|e| {
			matches!(
				e,
				SolverEvent::Delivery(DeliveryEvent::BumpProfitabilityCheckSkipped {
					order_id, reason, ..
				}) if order_id == "order-1" && reason == "no quote_id"
			)
		});
		assert!(
			found,
			"expected BumpProfitabilityCheckSkipped(no quote_id), got: {events:?}"
		);
		// expect_submit().times(0) asserts the bump was skipped.
	}

	#[tokio::test]
	async fn bump_skips_and_emits_event_when_nonce_missing() {
		let cfg = default_enabled_config();
		let signer = Address(vec![9; 20]);
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		mock.expect_submit().times(0);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		let mut tx = tx_with_fees(10_000_000_000);
		tx.nonce = None;
		let attempt = store
			.record_planned_attempt(solver_delivery::PlannedAttemptInit {
				order_id: "order-1".into(),
				signer: Some(signer),
				tx_type: TransactionType::Fill,
				tx,
				attempt_id_override: Some("parent-1".into()),
				replacement_of: None,
			})
			.await
			.unwrap();
		store
			.update_attempt_status(
				&attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(TransactionHash(vec![0; 32]));
				},
			)
			.await
			.unwrap();

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|event| matches!(
				event,
				SolverEvent::Delivery(DeliveryEvent::BumpMissingNonce {
					order_id,
					attempt_id,
					..
				}) if order_id == "order-1" && attempt_id == "parent-1"
			)),
			"expected BumpMissingNonce, got: {events:?}"
		);
	}

	#[tokio::test]
	async fn bump_balance_check_accepts_u256_max_balance() {
		let cfg = default_enabled_config();
		let (service, attempt_store, storage, bus, _tmp) =
			test_service(cfg, MockDeliveryInterface::new());
		seed_active_order(&storage, "order-1").await;
		let signer = Address(vec![9; 20]);
		seed_attempt(
			&attempt_store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(signer.clone()),
			10_000_000_000,
		)
		.await;

		let recorder: Arc<dyn TransactionAttemptRecorder> = attempt_store.clone();
		let recorder_for_mock = recorder.clone();
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock.expect_get_balance().returning(|_, _, _| {
			Box::pin(async move { Ok(alloy_primitives::U256::MAX.to_string()) })
		});
		mock.expect_submit()
			.times(1)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					let outcome: Result<TransactionHash, DeliveryError> =
						Ok(TransactionHash(vec![0xab; 32]));
					simulate_submit_recording(
						&recorder,
						&tracking,
						&tx,
						&outcome,
						Some(Address(vec![9; 20])),
					)
					.await;
					outcome
				})
			});
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let service = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			attempt_store.clone(),
			delivery_svc,
			bus,
			recorder,
			test_pricing(),
		);

		tokio::time::sleep(Duration::from_secs(2)).await;
		service.tick().await.unwrap();
		let all = attempt_store.attempts_for_order("order-1").await.unwrap();
		assert_eq!(all.len(), 2, "max U256 balance should not disable bumping");
	}

	#[tokio::test]
	async fn bump_receipt_preflight_marks_tip_confirmed_and_does_not_submit() {
		let cfg = default_enabled_config();
		let signer = Address(vec![9; 20]);
		let tip_hash = TransactionHash(vec![0x44; 32]);
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let hash_for_receipt = tip_hash.clone();
		mock.expect_get_receipt()
			.with(eq(tip_hash.clone()), eq(1u64))
			.times(1)
			.returning(move |hash, _| {
				let hash = hash.clone();
				Box::pin(async move { Ok(receipt(hash, true)) })
			});
		mock.expect_submit().times(0);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		let attempt = seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Indeterminate,
			None,
			Some(signer),
			10_000_000_000,
		)
		.await;
		store
			.update_attempt_status(
				&attempt.id,
				TransactionAttemptStatus::Indeterminate,
				None,
				|attempt| {
					attempt.tx_hash = Some(hash_for_receipt.clone());
				},
			)
			.await
			.unwrap();

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let attempt = store.get_attempt("parent-1").await.unwrap();
		assert_eq!(attempt.status, TransactionAttemptStatus::Confirmed);
		assert!(attempt.receipt.is_some());
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|event| matches!(
				event,
				SolverEvent::Delivery(DeliveryEvent::BumpTipAlreadyMined {
					attempt_id,
					success: true,
					..
				}) if attempt_id == "parent-1"
			)),
			"expected successful BumpTipAlreadyMined, got: {events:?}"
		);
	}

	#[tokio::test]
	async fn bump_receipt_preflight_marks_reverted_tip_and_does_not_submit() {
		let cfg = default_enabled_config();
		let signer = Address(vec![9; 20]);
		let tip_hash = TransactionHash(vec![0x45; 32]);
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let hash_for_update = tip_hash.clone();
		mock.expect_get_receipt()
			.with(eq(tip_hash.clone()), eq(1u64))
			.times(1)
			.returning(move |hash, _| {
				let hash = hash.clone();
				Box::pin(async move { Ok(receipt(hash, false)) })
			});
		mock.expect_submit().times(0);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		let attempt = seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Indeterminate,
			None,
			Some(signer),
			10_000_000_000,
		)
		.await;
		store
			.update_attempt_status(
				&attempt.id,
				TransactionAttemptStatus::Indeterminate,
				None,
				|attempt| {
					attempt.tx_hash = Some(hash_for_update.clone());
				},
			)
			.await
			.unwrap();

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let attempt = store.get_attempt("parent-1").await.unwrap();
		assert_eq!(attempt.status, TransactionAttemptStatus::Reverted);
		assert!(attempt.receipt.is_some());
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|event| matches!(
				event,
				SolverEvent::Delivery(DeliveryEvent::BumpTipAlreadyMined {
					attempt_id,
					success: false,
					..
				}) if attempt_id == "parent-1"
			)),
			"expected reverted BumpTipAlreadyMined, got: {events:?}"
		);
	}

	#[tokio::test]
	async fn bump_receipt_preflight_confirmed_update_conflict_emits_event() {
		let cfg = default_enabled_config();
		let signer = Address(vec![9; 20]);
		let tip_hash = TransactionHash(vec![0x46; 32]);
		let (service, store, storage, bus, _tmp) = test_service(cfg, MockDeliveryInterface::new());
		seed_active_order(&storage, "order-1").await;
		let attempt = seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Indeterminate,
			None,
			Some(signer.clone()),
			10_000_000_000,
		)
		.await;
		store
			.update_attempt_status(
				&attempt.id,
				TransactionAttemptStatus::Indeterminate,
				None,
				|attempt| {
					attempt.tx_hash = Some(tip_hash.clone());
				},
			)
			.await
			.unwrap();

		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		let store_for_mock = store.clone();
		mock.expect_get_receipt()
			.with(eq(tip_hash.clone()), eq(1u64))
			.times(1)
			.returning(move |hash, _| {
				let hash = hash.clone();
				let store = store_for_mock.clone();
				Box::pin(async move {
					store
						.update_attempt_status(
							"parent-1",
							TransactionAttemptStatus::Replaced,
							None,
							|_| {},
						)
						.await
						.unwrap();
					Ok(receipt(hash, true))
				})
			});
		mock.expect_submit().times(0);
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let svc = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			store.clone(),
			delivery_svc,
			bus.clone(),
			store.clone(),
			test_pricing(),
		);

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|event| matches!(
				event,
				SolverEvent::Delivery(DeliveryEvent::TransactionAttemptLedgerConflict {
					attempt_id,
					attempted_status: TransactionAttemptStatus::Confirmed,
					context,
					..
				}) if attempt_id == "parent-1"
					&& context == "bump receipt preflight confirmed"
			)),
			"expected attempt ledger conflict, got: {events:?}"
		);
	}

	#[tokio::test]
	async fn bump_receipt_preflight_error_fail_closed_skips_submit() {
		let mut cfg = default_enabled_config();
		cfg.default_receipt_preflight_fail_closed = true;
		let signer = Address(vec![9; 20]);
		let tip_hash = TransactionHash(vec![0x47; 32]);
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		mock.expect_get_receipt()
			.with(eq(tip_hash.clone()), eq(1u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move { Err(DeliveryError::Network("receipt unavailable".into())) })
			});
		mock.expect_submit().times(0);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		let attempt = seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Indeterminate,
			None,
			Some(signer),
			10_000_000_000,
		)
		.await;
		store
			.update_attempt_status(
				&attempt.id,
				TransactionAttemptStatus::Indeterminate,
				None,
				|attempt| {
					attempt.tx_hash = Some(tip_hash.clone());
				},
			)
			.await
			.unwrap();

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|event| matches!(
				event,
				SolverEvent::Delivery(DeliveryEvent::BumpReceiptPreflightSkipped {
					attempt_id,
					fail_closed: true,
					..
				}) if attempt_id == "parent-1"
			)),
			"expected fail-closed receipt preflight skip, got: {events:?}"
		);
		assert_eq!(store.attempts_for_order("order-1").await.unwrap().len(), 1);
	}

	#[tokio::test]
	async fn bump_receipt_preflight_error_fail_open_submits_when_configured() {
		let cfg = default_enabled_config();
		let signer = Address(vec![9; 20]);
		let tip_hash = TransactionHash(vec![0x48; 32]);
		let (service, store, storage, bus, _tmp) = test_service(cfg, MockDeliveryInterface::new());
		seed_active_order(&storage, "order-1").await;
		let attempt = seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Indeterminate,
			None,
			Some(signer.clone()),
			10_000_000_000,
		)
		.await;
		store
			.update_attempt_status(
				&attempt.id,
				TransactionAttemptStatus::Indeterminate,
				None,
				|attempt| {
					attempt.tx_hash = Some(tip_hash.clone());
				},
			)
			.await
			.unwrap();

		let recorder: Arc<dyn TransactionAttemptRecorder> = store.clone();
		let recorder_for_mock = recorder.clone();
		let mut mock = MockDeliveryInterface::new();
		let signer_clone = signer.clone();
		mock.expect_submission_signer()
			.returning(move |_| Some(signer_clone.clone()));
		mock_large_balance(&mut mock);
		mock.expect_get_receipt()
			.with(eq(tip_hash.clone()), eq(1u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move { Err(DeliveryError::Network("receipt unavailable".into())) })
			});
		mock.expect_submit()
			.times(1)
			.returning(move |tx, tracking| {
				let recorder = recorder_for_mock.clone();
				Box::pin(async move {
					let tracking = tracking.expect("sweeper must supply tracking");
					let outcome: Result<TransactionHash, DeliveryError> =
						Ok(TransactionHash(vec![0xcd; 32]));
					simulate_submit_recording(
						&recorder,
						&tracking,
						&tx,
						&outcome,
						Some(Address(vec![9; 20])),
					)
					.await;
					outcome
				})
			});
		let delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> =
			HashMap::from([(1u64, Arc::new(mock) as Arc<dyn DeliveryInterface>)]);
		let delivery_svc = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let svc = TransactionBumpService::new(
			service.config.clone(),
			storage.clone(),
			store.clone(),
			delivery_svc,
			bus.clone(),
			recorder,
			test_pricing(),
		);

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|event| matches!(
				event,
				SolverEvent::Delivery(DeliveryEvent::BumpReceiptPreflightSkipped {
					attempt_id,
					fail_closed: false,
					..
				}) if attempt_id == "parent-1"
			)),
			"expected fail-open receipt preflight event, got: {events:?}"
		);
		assert_eq!(store.attempts_for_order("order-1").await.unwrap().len(), 2);
	}

	#[tokio::test]
	async fn bump_emits_event_for_missing_submission_signer() {
		let cfg = default_enabled_config();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submission_signer().returning(|_| None);
		mock.expect_submit().times(0);

		let (svc, store, storage, bus, _tmp) = test_service(cfg, mock);
		seed_active_order(&storage, "order-1").await;
		seed_attempt(
			&store,
			"parent-1",
			TransactionAttemptStatus::Broadcast,
			None,
			Some(Address(vec![9; 20])),
			10_000_000_000,
		)
		.await;

		let mut sub = bus.subscribe();
		tokio::time::sleep(Duration::from_secs(2)).await;
		svc.tick().await.unwrap();
		let events = drain_bus_events(&mut sub);
		assert!(
			events.iter().any(|event| matches!(
				event,
				SolverEvent::Delivery(DeliveryEvent::BumpSubmissionSignerUnavailable {
					attempt_id,
					..
				}) if attempt_id == "parent-1"
			)),
			"expected BumpSubmissionSignerUnavailable, got: {events:?}"
		);
	}
}
