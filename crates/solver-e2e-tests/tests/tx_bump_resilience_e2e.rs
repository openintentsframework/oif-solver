//! Transaction bump resilience e2e tests.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test tx_bump_resilience_e2e \
//!       -- --ignored --test-threads=1 --nocapture

use std::collections::HashMap;
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use anyhow::{anyhow, Context as _, Result};
use solver_e2e_tests::{
	amount_with_decimals, Finalised, Harness, HarnessOptions, OutputFilled, StandardOrderBuilder,
	DEST_CHAIN_ID, FILL_TIMEOUT, ORIGIN_CHAIN_ID, SETTLE_TIMEOUT,
};
use solver_types::{
	OperatorTxBumpChainConfig, OperatorTxBumpConfig, OrderStatus, TransactionAttempt,
	TransactionAttemptStatus, TransactionType,
};

const POLL: Duration = Duration::from_millis(250);
const BUMP_WAIT: Duration = Duration::from_secs(45);
const RESTART_RTO: Duration = Duration::from_secs(60);
const LOAD_WAIT: Duration = Duration::from_secs(180);

fn tx_bump_config() -> OperatorTxBumpConfig {
	OperatorTxBumpConfig {
		enabled: true,
		sweep_interval_secs: Some(1),
		default_pending_threshold_secs: Some(1),
		default_bump_percent: Some(20),
		default_max_replacements_per_stage: Some(3),
		default_max_fee_per_gas_cap_wei: Some("1000000000000".to_string()),
		default_max_priority_fee_per_gas_cap_wei: Some("100000000000".to_string()),
		default_profitability_gate_fail_closed: Some(false),
		default_receipt_preflight_fail_closed: Some(true),
		chains: HashMap::from([
			(ORIGIN_CHAIN_ID, OperatorTxBumpChainConfig::default()),
			(DEST_CHAIN_ID, OperatorTxBumpChainConfig::default()),
		]),
	}
}

fn bump_harness_options() -> HarnessOptions {
	HarnessOptions {
		tx_bump: Some(tx_bump_config()),
		broadcaster_default_finality_blocks: Some(0),
		..Default::default()
	}
}

async fn pause_mining(h: &Harness, chain_id: u64) -> Result<()> {
	h.set_interval_mining(chain_id, 0).await?;
	h.set_automine(chain_id, false).await
}

async fn resume_mining(h: &Harness, chain_id: u64) -> Result<()> {
	h.set_automine(chain_id, true).await?;
	h.set_interval_mining(chain_id, 1).await
}

fn order_key(order_id: B256) -> String {
	format!("0x{}", hex::encode(order_id.0))
}

fn attempt_hash(attempt: &TransactionAttempt) -> Result<solver_types::TransactionHash> {
	attempt
		.tx_hash
		.clone()
		.ok_or_else(|| anyhow!("attempt {} missing tx_hash", attempt.id))
}

fn is_broadcast_with_hash(attempt: &TransactionAttempt) -> bool {
	attempt.status == TransactionAttemptStatus::Broadcast
		&& attempt.tx_hash.is_some()
		&& attempt.nonce.is_some()
}

fn is_live_attempt_with_hash(attempt: &TransactionAttempt) -> bool {
	attempt.tx_hash.is_some()
		&& attempt.nonce.is_some()
		&& matches!(
			attempt.status,
			TransactionAttemptStatus::Broadcast
				| TransactionAttemptStatus::Confirmed
				| TransactionAttemptStatus::Indeterminate
		)
}

fn is_fresh_root_attempt_with_hash(attempt: &TransactionAttempt) -> bool {
	attempt.replacement_of.is_none()
		&& (is_live_attempt_with_hash(attempt) || {
			attempt.tx_hash.is_some()
				&& attempt.nonce.is_some()
				&& attempt.status == TransactionAttemptStatus::Replaced
		})
}

fn has_broadcast_replacement(attempts: &[TransactionAttempt]) -> bool {
	attempts
		.iter()
		.any(|attempt| attempt.replacement_of.is_some() && is_broadcast_with_hash(attempt))
}

async fn wait_for_attempts<F>(
	h: &Harness,
	order_id: &str,
	tx_type: TransactionType,
	timeout: Duration,
	predicate: F,
) -> Result<Vec<TransactionAttempt>>
where
	F: Fn(&[TransactionAttempt]) -> bool,
{
	let deadline = Instant::now() + timeout;
	loop {
		let attempts = h.stored_attempts_by_type(order_id, tx_type).await?;
		if predicate(&attempts) {
			return Ok(attempts);
		}
		if Instant::now() >= deadline {
			h.dump_solver_stderr();
			return Err(anyhow!(
				"timeout waiting for {tx_type:?} attempts on {order_id}; last={attempts:?}"
			));
		}
		tokio::time::sleep(POLL).await;
	}
}

async fn wait_for_order_status<F>(
	h: &Harness,
	order_id: &str,
	timeout: Duration,
	predicate: F,
) -> Result<solver_types::Order>
where
	F: Fn(&OrderStatus) -> bool,
{
	let deadline = Instant::now() + timeout;
	loop {
		let order = h.stored_order(order_id).await?;
		if predicate(&order.status) {
			return Ok(order);
		}
		if Instant::now() >= deadline {
			h.dump_solver_stderr();
			return Err(anyhow!(
				"timeout waiting for order {order_id}; last status={:?}",
				order.status
			));
		}
		tokio::time::sleep(POLL).await;
	}
}

async fn wait_for_solver_log_contains(h: &Harness, needle: &str, timeout: Duration) -> Result<()> {
	let deadline = Instant::now() + timeout;
	loop {
		if h.solver_log_contains(needle)? {
			return Ok(());
		}
		if Instant::now() >= deadline {
			h.dump_solver_stderr();
			return Err(anyhow!(
				"timeout waiting for solver log containing {needle:?}"
			));
		}
		tokio::time::sleep(POLL).await;
	}
}

fn parent_child(
	attempts: &[TransactionAttempt],
) -> Result<(&TransactionAttempt, &TransactionAttempt)> {
	let child = attempts
		.iter()
		.find(|attempt| attempt.replacement_of.is_some())
		.ok_or_else(|| anyhow!("no child replacement in attempts: {attempts:?}"))?;
	let parent_id = child.replacement_of.as_deref().unwrap();
	let parent = attempts
		.iter()
		.find(|attempt| attempt.id == parent_id)
		.ok_or_else(|| anyhow!("child {} parent {parent_id} not found", child.id))?;
	Ok((parent, child))
}

fn attempt_with_hash<'a>(
	attempts: &'a [TransactionAttempt],
	hash: &solver_types::TransactionHash,
) -> Result<&'a TransactionAttempt> {
	attempts
		.iter()
		.find(|attempt| attempt.tx_hash.as_ref() == Some(hash))
		.ok_or_else(|| anyhow!("attempt with hash {hash:?} not found in {attempts:?}"))
}

fn parent_for_child<'a>(
	attempts: &'a [TransactionAttempt],
	child: &TransactionAttempt,
) -> Result<&'a TransactionAttempt> {
	let parent_id = child
		.replacement_of
		.as_deref()
		.ok_or_else(|| anyhow!("child {} has no replacement_of", child.id))?;
	attempts
		.iter()
		.find(|attempt| attempt.id == parent_id)
		.ok_or_else(|| anyhow!("child {} parent {parent_id} not found", child.id))
}

fn assert_replacement(parent: &TransactionAttempt, child: &TransactionAttempt) {
	assert_eq!(child.replacement_of.as_deref(), Some(parent.id.as_str()));
	assert_eq!(child.nonce, parent.nonce);
	assert!(
		child.tx.max_fee_per_gas.unwrap_or_default()
			> parent.tx.max_fee_per_gas.unwrap_or_default(),
		"child fee must exceed parent fee: parent={:?}, child={:?}",
		parent.tx.max_fee_per_gas,
		child.tx.max_fee_per_gas
	);
}

fn assert_same_nonce_attempts_are_in_lineage(
	attempts: &[TransactionAttempt],
	root: &TransactionAttempt,
) {
	let Some(root_nonce) = root.nonce else {
		return;
	};
	let mut lineage_ids = std::collections::HashSet::from([root.id.clone()]);
	let mut progressed = true;
	while progressed {
		progressed = false;
		for attempt in attempts
			.iter()
			.filter(|attempt| attempt.nonce == Some(root_nonce))
		{
			if lineage_ids.contains(&attempt.id) {
				continue;
			}
			if attempt
				.replacement_of
				.as_ref()
				.is_some_and(|parent_id| lineage_ids.contains(parent_id))
			{
				lineage_ids.insert(attempt.id.clone());
				progressed = true;
			}
		}
	}

	for attempt in attempts
		.iter()
		.filter(|attempt| attempt.nonce == Some(root_nonce))
	{
		assert!(
			lineage_ids.contains(&attempt.id),
			"same-nonce reuse is only valid through explicit bump lineage: root={root:?}, attempts={attempts:?}"
		);
	}
}

fn confirmed_winners(attempts: &[TransactionAttempt]) -> Vec<&TransactionAttempt> {
	attempts
		.iter()
		.filter(|attempt| attempt.status == TransactionAttemptStatus::Confirmed)
		.collect()
}

fn assert_one_confirmed_winner(
	order_id: &str,
	tx_type: TransactionType,
	attempts: &[TransactionAttempt],
) {
	let winners = confirmed_winners(attempts);
	assert_eq!(
		winners.len(),
		1,
		"expected one confirmed {tx_type:?} winner for {order_id}, got {attempts:?}"
	);
}

async fn open_default_order(
	h: &Harness,
	suffix: &str,
) -> Result<(B256, solver_e2e_tests::StandardOrder)> {
	let order = StandardOrderBuilder::happy_path(h, suffix).build();
	h.user_approve(
		h.origin.token_a,
		h.origin.input_settler,
		amount_with_decimals(1_000),
	)
	.await?;
	let order_id = h.user_open(order.clone()).await?;
	Ok((order_id, order))
}

async fn wait_for_first_attempt(
	h: &Harness,
	order_id: &str,
	tx_type: TransactionType,
) -> Result<TransactionAttempt> {
	let attempts = wait_for_attempts(h, order_id, tx_type, BUMP_WAIT, |attempts| {
		attempts.iter().any(is_live_attempt_with_hash)
	})
	.await?;
	attempts
		.into_iter()
		.find(is_live_attempt_with_hash)
		.ok_or_else(|| anyhow!("no {tx_type:?} attempt for {order_id}"))
}

async fn wait_for_fresh_root_attempt(
	h: &Harness,
	order_id: &str,
	tx_type: TransactionType,
) -> Result<TransactionAttempt> {
	let attempts = wait_for_attempts(h, order_id, tx_type, BUMP_WAIT, |attempts| {
		attempts.iter().any(is_fresh_root_attempt_with_hash)
	})
	.await?;
	attempts
		.into_iter()
		.find(is_fresh_root_attempt_with_hash)
		.ok_or_else(|| anyhow!("no root {tx_type:?} attempt for {order_id}"))
}

fn assert_no_unrelated_nonce_reuse(
	first_order_id: &str,
	first_nonce: Option<u64>,
	second_order_id: &str,
	second_attempt: &TransactionAttempt,
) {
	assert_eq!(
		second_attempt.replacement_of, None,
		"second order's first attempt must be a fresh tx, not a bump: {second_attempt:?}"
	);
	if let (Some(first_nonce), Some(second_nonce)) = (first_nonce, second_attempt.nonce) {
		assert!(
			second_nonce > first_nonce,
			"different order reused stale nonce: first_order={first_order_id}, second_order={second_order_id}, first_nonce={first_nonce}, second_attempt={second_attempt:?}"
		);
	}
}

fn count_log_lines_with_all(logs: &str, needles: &[&str]) -> usize {
	logs.lines()
		.filter(|line| needles.iter().all(|needle| line.contains(needle)))
		.count()
}

fn order_has_reached_or_passed_fill(status: &OrderStatus) -> bool {
	matches!(
		status,
		OrderStatus::Executed
			| OrderStatus::PostFilled
			| OrderStatus::Settled
			| OrderStatus::PreClaimed
			| OrderStatus::Finalized
			| OrderStatus::Failed(_, _)
	)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn fill_bump_replaces_underpriced_pending_fill_and_writes_canonical_hash() -> Result<()> {
	let h = Harness::boot_with(bump_harness_options()).await?;
	pause_mining(&h, DEST_CHAIN_ID).await?;

	let (order_id, _order) = open_default_order(&h, "tx-bump-fill").await?;
	let order_id_str = order_key(order_id);

	let attempts = wait_for_attempts(&h, &order_id_str, TransactionType::Fill, BUMP_WAIT, |a| {
		has_broadcast_replacement(a)
	})
	.await?;
	let (parent_before_mine, child_before_mine) = parent_child(&attempts)?;
	assert_replacement(parent_before_mine, child_before_mine);
	let parent_hash = attempt_hash(parent_before_mine)?;
	let child_hash = attempt_hash(child_before_mine)?;
	h.drop_transaction(DEST_CHAIN_ID, &parent_hash).await?;

	resume_mining(&h, DEST_CHAIN_ID).await?;
	h.mine_blocks(DEST_CHAIN_ID, 3).await?;
	h.await_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		FILL_TIMEOUT,
	)
	.await?;

	let order = wait_for_order_status(&h, &order_id_str, SETTLE_TIMEOUT, |status| {
		matches!(
			status,
			OrderStatus::Executed | OrderStatus::Settled | OrderStatus::Finalized
		)
	})
	.await?;
	assert_eq!(order.fill_tx_hash, Some(child_hash.clone()));
	assert_ne!(order.fill_tx_hash, Some(parent_hash));

	let attempts = wait_for_attempts(&h, &order_id_str, TransactionType::Fill, BUMP_WAIT, |a| {
		attempt_with_hash(a, &child_hash)
			.is_ok_and(|attempt| attempt.status == TransactionAttemptStatus::Confirmed)
	})
	.await?;
	let child = attempt_with_hash(&attempts, &child_hash)?;
	let parent = parent_for_child(&attempts, child)?;
	assert_eq!(child.status, TransactionAttemptStatus::Confirmed);
	assert_eq!(parent.replaced_by.as_deref(), Some(child.id.as_str()));
	assert!(
		!h.solver_log_contents()?
			.contains("TransactionCanonicalHashConflict"),
		"happy replacement path must not emit canonical-hash conflict"
	);

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn claim_bump_replaces_underpriced_pending_claim_and_writes_canonical_hash() -> Result<()> {
	let mut options = bump_harness_options();
	options.use_hyperlane_settlement = true;
	if let Some(tx_bump) = options.tx_bump.as_mut() {
		tx_bump.default_pending_threshold_secs = Some(3);
	}
	let h = Harness::boot_with(options).await?;
	let (order_id, _order) = open_default_order(&h, "tx-bump-claim").await?;
	let order_id_str = order_key(order_id);
	pause_mining(&h, ORIGIN_CHAIN_ID).await?;

	h.await_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		FILL_TIMEOUT,
	)
	.await?;

	let parent_before_drop = wait_for_fresh_root_attempt(&h, &order_id_str, TransactionType::Claim)
		.await
		.context("wait for parent Claim attempt")?;
	assert_eq!(parent_before_drop.replacement_of, None);
	let parent_hash = attempt_hash(&parent_before_drop)?;
	h.drop_transaction(ORIGIN_CHAIN_ID, &parent_hash).await?;

	let attempts = wait_for_attempts(&h, &order_id_str, TransactionType::Claim, BUMP_WAIT, |a| {
		has_broadcast_replacement(a)
	})
	.await?;
	let (parent_before_mine, child_before_mine) = parent_child(&attempts)?;
	assert_replacement(parent_before_mine, child_before_mine);
	assert_eq!(attempt_hash(parent_before_mine)?, parent_hash);
	let child_hash = attempt_hash(child_before_mine)?;

	resume_mining(&h, ORIGIN_CHAIN_ID).await?;
	h.mine_blocks(ORIGIN_CHAIN_ID, 3).await?;
	h.await_event::<Finalised>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		SETTLE_TIMEOUT,
	)
	.await?;

	let order = wait_for_order_status(&h, &order_id_str, SETTLE_TIMEOUT, |status| {
		matches!(status, OrderStatus::Finalized)
	})
	.await?;
	assert_eq!(order.claim_tx_hash, Some(child_hash.clone()));
	assert_ne!(order.claim_tx_hash, Some(parent_hash));

	let attempts = wait_for_attempts(&h, &order_id_str, TransactionType::Claim, BUMP_WAIT, |a| {
		parent_child(a).is_ok_and(|(parent, child)| {
			parent.replaced_by.as_deref() == Some(child.id.as_str())
				&& child.status == TransactionAttemptStatus::Confirmed
		})
	})
	.await?;
	let (parent, child) = parent_child(&attempts)?;
	assert_eq!(child.status, TransactionAttemptStatus::Confirmed);
	assert_eq!(parent.replaced_by.as_deref(), Some(child.id.as_str()));

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn receipt_preflight_confirmed_tip_does_not_resubmit() -> Result<()> {
	let mut options = bump_harness_options();
	if let Some(tx_bump) = options.tx_bump.as_mut() {
		tx_bump.default_pending_threshold_secs = Some(20);
	}
	let h = Harness::boot_with(options).await?;
	let (order_id, _order) = open_default_order(&h, "tx-bump-preflight").await?;
	let order_id_str = order_key(order_id);

	h.await_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		FILL_TIMEOUT,
	)
	.await?;

	let mut attempts = wait_for_attempts(
		&h,
		&order_id_str,
		TransactionType::PostFill,
		BUMP_WAIT,
		|a| {
			a.iter()
				.any(|attempt| attempt.status == TransactionAttemptStatus::Confirmed)
		},
	)
	.await?;
	let mut confirmed = attempts
		.iter()
		.find(|attempt| attempt.status == TransactionAttemptStatus::Confirmed)
		.cloned()
		.context("confirmed post-fill attempt")?;
	let original_count = attempts.len();
	confirmed.status = TransactionAttemptStatus::Indeterminate;
	confirmed.error = Some("test stale ledger state".to_string());
	confirmed.receipt = None;
	confirmed.updated_at = solver_types::current_timestamp().saturating_sub(30);
	h.save_stored_attempt(&confirmed).await?;

	attempts = wait_for_attempts(
		&h,
		&order_id_str,
		TransactionType::PostFill,
		BUMP_WAIT,
		|a| {
			a.iter().any(|attempt| {
				attempt.id == confirmed.id && attempt.status == TransactionAttemptStatus::Confirmed
			})
		},
	)
	.await?;
	assert_eq!(
		attempts.len(),
		original_count,
		"receipt preflight must reconcile without submitting a replacement"
	);
	wait_for_solver_log_contains(&h, "event=\"BumpTipAlreadyMined\"", BUMP_WAIT).await?;
	assert!(
		h.solver_log_contains("success=true")?,
		"receipt preflight must emit BumpTipAlreadyMined {{ success: true }}"
	);

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn restart_during_bump_dispatch_recovers_lineage() -> Result<()> {
	let mut h = Harness::boot_with(bump_harness_options()).await?;
	pause_mining(&h, DEST_CHAIN_ID).await?;

	let started = Instant::now();
	let (order_id, _order) = open_default_order(&h, "tx-bump-restart").await?;
	let order_id_str = order_key(order_id);
	let attempts_before_restart =
		wait_for_attempts(&h, &order_id_str, TransactionType::Fill, BUMP_WAIT, |a| {
			has_broadcast_replacement(a)
		})
		.await?;
	let (parent_before_restart, child_before_restart) = parent_child(&attempts_before_restart)?;
	let child_hash = attempt_hash(child_before_restart)?;
	h.drop_transaction(DEST_CHAIN_ID, &attempt_hash(parent_before_restart)?)
		.await?;
	let count_before_restart = attempts_before_restart.len();

	h.stop_solver().await?;
	resume_mining(&h, DEST_CHAIN_ID).await?;
	h.mine_blocks(DEST_CHAIN_ID, 3).await?;
	h.await_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		FILL_TIMEOUT,
	)
	.await?;
	h.restart_solver().await?;
	let stable = wait_for_attempts(&h, &order_id_str, TransactionType::Fill, RESTART_RTO, |a| {
		attempt_with_hash(a, &child_hash)
			.is_ok_and(|attempt| attempt.status == TransactionAttemptStatus::Confirmed)
	})
	.await?;
	let elapsed = started.elapsed();
	tracing::info!(?elapsed, "restart-during-bump reached stable lineage");
	assert!(
		elapsed <= RESTART_RTO,
		"restart recovery plus first sweep exceeded {RESTART_RTO:?}: {elapsed:?}"
	);
	assert!(
		stable.len() <= count_before_restart,
		"restart created too many siblings: before={count_before_restart}, after={stable:?}"
	);
	let child = attempt_with_hash(&stable, &child_hash)?;
	let parent = parent_for_child(&stable, child)?;
	assert_eq!(child.status, TransactionAttemptStatus::Confirmed);
	assert_eq!(parent.replaced_by.as_deref(), Some(child.id.as_str()));
	let order = h.stored_order(&order_id_str).await?;
	assert!(!matches!(order.status, OrderStatus::Failed(_, _)));

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn nonce_not_reused_after_restart_with_pending_in_flight_tx() -> Result<()> {
	let mut h = Harness::boot_with(bump_harness_options()).await?;
	pause_mining(&h, DEST_CHAIN_ID).await?;

	let (first_order_id, _first_order) = open_default_order(&h, "tx-bump-nonce-pending-a").await?;
	let first_order_id_str = order_key(first_order_id);
	let first_attempt =
		wait_for_fresh_root_attempt(&h, &first_order_id_str, TransactionType::Fill).await?;
	let first_nonce = first_attempt.nonce;
	assert!(
		first_attempt.replacement_of.is_none(),
		"first observed attempt should be the fresh parent: {first_attempt:?}"
	);

	h.stop_solver().await?;
	h.restart_solver().await?;

	let (second_order_id, _second_order) =
		open_default_order(&h, "tx-bump-nonce-pending-b").await?;
	let second_order_id_str = order_key(second_order_id);
	let second_attempt =
		wait_for_fresh_root_attempt(&h, &second_order_id_str, TransactionType::Fill).await?;
	assert_no_unrelated_nonce_reuse(
		&first_order_id_str,
		first_nonce,
		&second_order_id_str,
		&second_attempt,
	);

	let first_attempts = h
		.stored_attempts_by_type(&first_order_id_str, TransactionType::Fill)
		.await?;
	assert_same_nonce_attempts_are_in_lineage(&first_attempts, &first_attempt);

	resume_mining(&h, DEST_CHAIN_ID).await?;
	h.mine_blocks(DEST_CHAIN_ID, 3).await?;

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn nonce_not_reused_after_restart_with_confirmed_during_downtime_tx() -> Result<()> {
	let mut h = Harness::boot_with(bump_harness_options()).await?;
	pause_mining(&h, DEST_CHAIN_ID).await?;

	let (first_order_id, _first_order) =
		open_default_order(&h, "tx-bump-nonce-confirmed-a").await?;
	let first_order_id_str = order_key(first_order_id);
	let first_attempt =
		wait_for_first_attempt(&h, &first_order_id_str, TransactionType::Fill).await?;
	let first_nonce = first_attempt.nonce;

	h.stop_solver().await?;
	resume_mining(&h, DEST_CHAIN_ID).await?;
	h.mine_blocks(DEST_CHAIN_ID, 3).await?;
	h.await_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		first_order_id,
		FILL_TIMEOUT,
	)
	.await?;
	h.restart_solver().await?;

	wait_for_attempts(
		&h,
		&first_order_id_str,
		TransactionType::Fill,
		RESTART_RTO,
		|attempts| {
			attempts.iter().any(|attempt| {
				attempt.id == first_attempt.id
					&& attempt.status == TransactionAttemptStatus::Confirmed
			})
		},
	)
	.await?;

	let (second_order_id, _second_order) =
		open_default_order(&h, "tx-bump-nonce-confirmed-b").await?;
	let second_order_id_str = order_key(second_order_id);
	let second_attempt =
		wait_for_fresh_root_attempt(&h, &second_order_id_str, TransactionType::Fill).await?;
	assert_no_unrelated_nonce_reuse(
		&first_order_id_str,
		first_nonce,
		&second_order_id_str,
		&second_attempt,
	);

	let second_attempts = h
		.stored_attempts_by_type(&second_order_id_str, TransactionType::Fill)
		.await?;
	assert!(
		second_attempts
			.iter()
			.all(|attempt| attempt.nonce != first_nonce),
		"confirmed downtime nonce reused by unrelated order: first_nonce={first_nonce:?}, second_attempts={second_attempts:?}"
	);

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn many_pending_orders_sweeper_progresses_without_duplicate_offchain_events() -> Result<()> {
	let h = Harness::boot_with(bump_harness_options()).await?;
	pause_mining(&h, DEST_CHAIN_ID).await?;

	let mut order_ids = Vec::new();
	for index in 0..10 {
		let (order_id, _order) = open_default_order(&h, &format!("tx-bump-load-{index}")).await?;
		let order_id_str = order_key(order_id);
		order_ids.push((order_id, order_id_str));
	}

	for (_order_id, order_id_str) in &order_ids {
		wait_for_attempts(
			&h,
			order_id_str,
			TransactionType::Fill,
			LOAD_WAIT,
			|attempts| {
				attempts
					.iter()
					.any(|attempt| attempt.replacement_of.is_some())
			},
		)
		.await?;
	}

	resume_mining(&h, DEST_CHAIN_ID).await?;
	h.mine_blocks(DEST_CHAIN_ID, 5).await?;

	let started = Instant::now();
	for (order_id, order_id_str) in &order_ids {
		h.await_event::<OutputFilled>(
			DEST_CHAIN_ID,
			h.destination.output_settler,
			*order_id,
			FILL_TIMEOUT,
		)
		.await?;
		let order = wait_for_order_status(
			&h,
			order_id_str,
			LOAD_WAIT,
			order_has_reached_or_passed_fill,
		)
		.await?;
		assert!(
			!matches!(order.status, OrderStatus::Failed(_, _)),
			"order {order_id_str} failed under bump load: {order:?}"
		);

		let attempts = h
			.stored_attempts_by_type(order_id_str, TransactionType::Fill)
			.await?;
		assert_one_confirmed_winner(order_id_str, TransactionType::Fill, &attempts);
		assert!(
			attempts.len() <= 4,
			"max_replacements_per_stage=3 allows at most parent + 3 children: {attempts:?}"
		);
	}
	assert!(
		started.elapsed() <= LOAD_WAIT,
		"multi-order load exceeded {LOAD_WAIT:?}: {:?}",
		started.elapsed()
	);

	let logs = h.solver_log_contents()?;
	for (_order_id, order_id_str) in &order_ids {
		let post_fill_ready_count =
			count_log_lines_with_all(&logs, &["event=\"PostFillReady\"", order_id_str]);
		let executing_count =
			count_log_lines_with_all(&logs, &["event=\"OrderExecuting\"", order_id_str]);
		assert!(
			post_fill_ready_count <= 1,
			"duplicate PostFillReady event for {order_id_str}: {post_fill_ready_count}"
		);
		assert!(
			executing_count <= 1,
			"duplicate Executing event for {order_id_str}: {executing_count}"
		);
	}

	Ok(())
}
