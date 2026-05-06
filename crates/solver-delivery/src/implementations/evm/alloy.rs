//! Transaction delivery implementations for the solver service.
//!
//! This module provides concrete implementations of the DeliveryInterface trait,
//! supporting blockchain transaction submission and monitoring using the Alloy library.

use crate::implementations::evm::fees::{
	FeePolicyConfig, FeePolicyRegistry, SolverEip1559Estimator,
};
// Re-import directly because the schema validator below builds a transient
// `FeePolicyRegistry` purely to surface field-level wei-parse errors. Going
// through `from_config` keeps validation and runtime conversion behind a
// single source of truth — there's exactly one place that decides what
// "valid" looks like.
use crate::implementations::evm::nonce::{
	classify_submission_outcome, ResettableNonceManager, SubmissionOutcome,
};
use crate::{
	DeliveryError, DeliveryInterface, FeeParams, InsufficientNativeGasInfo,
	TransactionMonitoringEvent, TransactionTrackingWithConfig,
};
use alloy_consensus::BlockHeader;
use alloy_network::{BlockResponse, EthereumWallet};
use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
use alloy_provider::{
	fillers::{ChainIdFiller, GasFiller},
	DynProvider, Provider, ProviderBuilder,
};
use alloy_rpc_client::RpcClient;
use alloy_rpc_types::{BlockNumberOrTag, TransactionRequest};
use alloy_transport::layers::RetryBackoffLayer;
use alloy_transport::TransportError;
use async_trait::async_trait;
use solver_account::AccountSigner;
use solver_types::{
	ConfigSchema, Field, FieldType, NetworksConfig, Schema, Transaction as SolverTransaction,
	TransactionHash, TransactionReceipt,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Interval between receipt-polling attempts inside `monitor_transaction`.
/// 2 seconds matches typical Ethereum mainnet block time and is short enough
/// not to materially delay confirmation reporting on faster chains.
const TX_CONFIRMATION_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Drift-monitor parameters. The monitor periodically compares local nonce
/// cache against chain pending. Some lead is normal during in-flight
/// broadcasts; only SUSTAINED drift indicates a possible cache leak.
///
/// IMPORTANT: this monitor is OBSERVABILITY ONLY. It does not mutate the
/// cache, retry transactions, or change any runtime behavior. Its only
/// effect is structured tracing events.
///
/// Type discipline: thresholds compared against `cache_lead()` are `i128`
/// to match its return type. Tick counts are `u32`. No mixed-integer
/// comparisons should appear anywhere in this monitor — if you find one,
/// fix the constant's type, not the comparison site.
const NONCE_DRIFT_POLL_INTERVAL_SECS: u64 = 60;
/// Per-tick drift threshold. lead < this → trace-level event (normal).
/// `i128` to match `cache_lead` return type.
const NONCE_DRIFT_WARN_THRESHOLD: i128 = 3;
/// Consecutive ticks over threshold before WARN escalation. `u32`.
const NONCE_DRIFT_WARN_AFTER_TICKS: u32 = 5; // ~5 minutes at 60s interval
/// Consecutive ticks over threshold before ERROR escalation. `u32`.
const NONCE_DRIFT_ERROR_AFTER_TICKS: u32 = 15; // ~15 minutes

/// Outcome of polling for a transaction's confirmation.
///
/// `Indeterminate` is intentionally distinct from `Reverted` so the spawned
/// monitor task can map a confirmation-deadline expiry to
/// `TransactionMonitoringEvent::Indeterminate` (non-terminal) instead of
/// `TransactionMonitoringEvent::Failed` (terminal). A `Failed` event would
/// transition the order to `OrderStatus::Failed(_, _)`, which startup
/// recovery skips at `crates/solver-core/src/recovery/mod.rs:148-154` —
/// permanently losing an order whose tx may yet confirm on chain.
enum PollOutcome {
	Confirmed(TransactionReceipt),
	Reverted(String),
	Indeterminate(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeGasBudget {
	gas_budget_wei: U256,
	required_wei: U256,
}

fn native_gas_budget_wei(tx: &SolverTransaction) -> Option<NativeGasBudget> {
	let gas_limit = tx.gas_limit?;
	let fee_per_gas = tx.max_fee_per_gas.or(tx.gas_price)?;
	let gas_budget_wei = U256::from(gas_limit).saturating_mul(U256::from(fee_per_gas));
	let required_wei = gas_budget_wei.saturating_add(tx.value);

	Some(NativeGasBudget {
		gas_budget_wei,
		required_wei,
	})
}

fn native_gas_shortfall(balance: U256, required: U256) -> Option<U256> {
	(balance < required).then(|| required.saturating_sub(balance))
}

/// One cached fee-params entry. `inserted_at` is captured at insertion time and
/// compared against TTL on read; we use `std::time::Instant` so tests can pass an
/// explicit `now` to exercise expiry without sleeping.
#[derive(Debug, Clone)]
struct CachedFeeParams {
	params: FeeParams,
	inserted_at: Instant,
}

/// Short-lived per-chain cache for `get_fee_params` results.
///
/// The motivation is documented in the plan (Task 4): moving from `eth_gasPrice`
/// to `feeHistory` + latest-block reads increases quote-time RPC pressure.
/// A short TTL preserves freshness while damping per-quote RPC load. Caching
/// is keyed by `chain_id` only — fee policy is currently per-chain, not
/// per-caller, so no further keying is required.
#[derive(Debug, Default)]
struct FeeParamsCache {
	entries: tokio::sync::RwLock<HashMap<u64, CachedFeeParams>>,
}

impl FeeParamsCache {
	/// Look up a cached entry, returning it only if it was inserted within `ttl`
	/// of `now`. Stale or missing entries return `None`. Purely a read; no
	/// eviction is performed (entries are overwritten on the next successful
	/// `insert`, and per-chain footprint is bounded by the number of supported
	/// chains).
	async fn get(&self, chain_id: u64, ttl: Duration, now: Instant) -> Option<FeeParams> {
		let guard = self.entries.read().await;
		guard.get(&chain_id).and_then(|cached| {
			let age = now.saturating_duration_since(cached.inserted_at);
			if age <= ttl {
				Some(cached.params.clone())
			} else {
				None
			}
		})
	}

	/// Insert or overwrite the entry for `chain_id`. `inserted_at` is taken
	/// from the caller so the freshly-resolved `FeeParams` and the cache
	/// timestamp share a single clock reading (see `get_fee_params`).
	async fn insert(&self, chain_id: u64, params: FeeParams, inserted_at: Instant) {
		let mut guard = self.entries.write().await;
		guard.insert(
			chain_id,
			CachedFeeParams {
				params,
				inserted_at,
			},
		);
	}
}

/// TTL defaults for the fee-params cache, per the plan (Task 4 Step 2).
///
/// - Mainnet: 3s. Block time ~12s; fee history within 3s is fresh enough for
///   quotes and amortizes the extra RPC round-trips compared to `eth_gasPrice`.
/// - Katana (747474): 1s. Sub-second blocks; keep cache short to avoid
///   under-quoting on fast fee shifts.
/// - Other chains: 2s. Conservative default that still cuts per-quote RPC
///   pressure roughly in half on a 12s block-time chain.
fn fee_params_cache_ttl(chain_id: u64) -> Duration {
	match chain_id {
		1 => Duration::from_secs(3),
		747474 => Duration::from_secs(1),
		_ => Duration::from_secs(2),
	}
}

/// Alloy-based EVM delivery implementation.
///
/// This implementation uses the Alloy library to submit and monitor transactions
/// on EVM-compatible blockchains. It handles transaction signing, submission,
/// and confirmation tracking. Supports multiple networks with a single instance.
pub struct AlloyDelivery {
	/// Alloy providers for each supported network.
	providers: HashMap<u64, DynProvider>,
	/// Resettable nonce manager per chain. Replaces Alloy's opaque
	/// `CachedNonceManager` so we can resync the local cache from chain
	/// after a `nonce too low` submission error.
	nonce_managers: HashMap<u64, ResettableNonceManager>,
	/// Signer address per chain — needed to call `eth_getTransactionCount(from, "pending")`
	/// for the resync path. The signer itself stays inside the provider's wallet filler.
	signer_addresses: HashMap<u64, Address>,
	/// Short-lived per-chain cache of resolved `FeeParams`. See
	/// `FeeParamsCache` and `fee_params_cache_ttl` for rationale and TTL
	/// defaults.
	fee_params_cache: Arc<FeeParamsCache>,
	/// Validated per-chain fee policy. Sourced from the required
	/// `fee_policy` block in the delivery config; missing entries for any
	/// configured network are a startup error (see `FeePolicyRegistry`).
	fee_policy: FeePolicyRegistry,
}

/// What the broadcast wrapper should do with the local nonce cache,
/// given a classified submission outcome. Pure decision, no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceCacheAction {
	/// Tx accepted (or kept-advanced for replacement / ambiguous outcomes) —
	/// keep cache advanced as-is.
	Keep,
	/// Tx provably rejected pre-pool. Caller should attempt to fetch
	/// chain pending and call `reset_next_nonce`. If the fetch fails,
	/// caller MUST fall back to `Keep` — we don't roll back without
	/// authoritative chain state.
	AttemptRollback,
	/// Caller should run the existing nonce_too_low resync-and-retry path.
	NonceTooLowRetry,
}

/// Pure outcome → action mapping. No I/O, easy to unit-test.
fn nonce_action_for_outcome(outcome: SubmissionOutcome) -> NonceCacheAction {
	match outcome {
		SubmissionOutcome::DefinitelyRejected => NonceCacheAction::AttemptRollback,
		SubmissionOutcome::NonceTooLow => NonceCacheAction::NonceTooLowRetry,
		SubmissionOutcome::Replacement | SubmissionOutcome::Ambiguous => NonceCacheAction::Keep,
	}
}

/// Applies a `NonceCacheAction` to the cache. The `chain_pending` argument
/// represents the *result* of the rollback-time fetch: `Some(pending)` if
/// the fetch succeeded, `None` if it failed (or we never attempted it).
///
/// Returns the cache value after applying the action, for tracing.
///
/// Pure synchronous helper so the rollback invariant is unit-testable
/// without spinning up a provider or async runtime.
///
/// **Visibility:** intentionally `fn` (private to this module), not `pub`.
/// This is delivery-layer policy glue — it encodes how the alloy broadcast
/// wrapper reacts to a classified submission outcome. It is NOT part of the
/// nonce-manager public API. If another module ever needs to invoke this
/// policy, the right move is to surface a higher-level operation on the
/// nonce manager (e.g. `try_rollback_to_chain_pending`), not export this
/// helper directly.
fn apply_nonce_cache_action(
	mgr: &ResettableNonceManager,
	signer: Address,
	action: NonceCacheAction,
	chain_pending: Option<u64>,
) -> Option<u64> {
	match action {
		NonceCacheAction::Keep => mgr.peek(signer),
		NonceCacheAction::AttemptRollback => match chain_pending {
			Some(pending) => Some(mgr.reset_next_nonce(signer, pending)),
			// No authoritative chain state — KEEP advanced. We never reset
			// the cache without a successful pending-fetch.
			None => mgr.peek(signer),
		},
		// The nonce_too_low path has its own existing resync-and-retry; the
		// helper short-circuits to a no-op here so callers can't accidentally
		// invoke double-handling. Production code paths that classify as
		// NonceTooLow MUST take the existing retry branch, not this helper.
		NonceCacheAction::NonceTooLowRetry => mgr.peek(signer),
	}
}

/// Drift event severity, derived purely from the consecutive-ticks count.
/// Pure data type for unit testability — no I/O, no logging logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DriftSeverity {
	Normal,
	Warn,
	Error,
}

/// Decide the drift event severity from the consecutive-ticks count.
/// Pure function for unit testability.
fn drift_severity_for_ticks(ticks_over_threshold: u32) -> DriftSeverity {
	if ticks_over_threshold >= NONCE_DRIFT_ERROR_AFTER_TICKS {
		DriftSeverity::Error
	} else if ticks_over_threshold >= NONCE_DRIFT_WARN_AFTER_TICKS {
		DriftSeverity::Warn
	} else {
		DriftSeverity::Normal
	}
}

/// Spawn the passive nonce-drift monitor. Polls each (chain, signer)
/// every `NONCE_DRIFT_POLL_INTERVAL_SECS`, computes `cache_lead`, and emits
/// a tracing event escalating from trace → warn → error as drift sustains.
///
/// MUTATIONS: none. The monitor never resets, retries, or modifies the
/// cache. Its sole effect is logs.
///
/// SHUTDOWN: this monitor runs for the lifetime of the process. The
/// surrounding `AlloyDelivery` does not currently expose a shutdown channel
/// for delivery-spawned tasks, and adding one would ripple through several
/// call sites for no observability gain. Drift checks are cheap (one RPC
/// call per chain per minute), so the cost of running until process exit is
/// negligible. If a shutdown channel is later added to delivery, plumb a
/// `tokio::sync::watch::Receiver<bool>` here and bias the `select!` on it.
fn spawn_nonce_drift_monitor(
	nonce_managers: HashMap<u64, ResettableNonceManager>,
	signer_addresses: HashMap<u64, Address>,
	providers: HashMap<u64, DynProvider>,
) {
	tokio::spawn(async move {
		let mut consecutive: HashMap<(u64, Address), u32> = HashMap::new();
		let mut interval =
			tokio::time::interval(Duration::from_secs(NONCE_DRIFT_POLL_INTERVAL_SECS));
		// Skip the immediate first tick so we don't poll before providers have
		// settled — `tokio::time::interval` fires at t=0 by default.
		interval.tick().await;
		loop {
			interval.tick().await;
			for (chain_id, mgr) in &nonce_managers {
				let Some(signer) = signer_addresses.get(chain_id) else {
					continue;
				};
				let Some(provider) = providers.get(chain_id) else {
					continue;
				};
				let pending = match provider.get_transaction_count(*signer).pending().await {
					Ok(p) => p,
					Err(e) => {
						tracing::trace!(
							chain_id = *chain_id,
							signer = %signer,
							error = %e,
							"drift monitor: failed to fetch chain pending; skipping this tick"
						);
						continue;
					},
				};
				let lead = mgr.cache_lead(*signer, pending);
				let key = (*chain_id, *signer);

				if lead < NONCE_DRIFT_WARN_THRESHOLD {
					consecutive.remove(&key);
					tracing::trace!(
						chain_id = *chain_id,
						signer = %signer,
						cache_lead = lead as i64,
						chain_pending = pending,
						"nonce drift within tolerance"
					);
					continue;
				}

				// Drift is over threshold this tick.
				let count = consecutive.entry(key).or_insert(0);
				*count = count.saturating_add(1);
				match drift_severity_for_ticks(*count) {
					DriftSeverity::Normal => {
						tracing::trace!(
							chain_id = *chain_id,
							signer = %signer,
							cache_lead = lead as i64,
							chain_pending = pending,
							consecutive_ticks = *count,
							"nonce drift over threshold (not yet sustained)"
						);
					},
					DriftSeverity::Warn => {
						tracing::warn!(
							chain_id = *chain_id,
							signer = %signer,
							cache_lead = lead as i64,
							chain_pending = pending,
							consecutive_ticks = *count,
							"nonce drift sustained — possible cache leak"
						);
					},
					DriftSeverity::Error => {
						tracing::error!(
							chain_id = *chain_id,
							signer = %signer,
							cache_lead = lead as i64,
							chain_pending = pending,
							consecutive_ticks = *count,
							"nonce drift sustained for {} ticks — almost certainly a cache leak; investigate",
							*count
						);
					},
				}
			}
		}
	});
}

impl AlloyDelivery {
	/// Creates a new AlloyDelivery instance.
	///
	/// Configures Alloy providers for multiple networks with the specified
	/// RPC URLs and signers for transaction submission. The default_signer is used
	/// for networks that don't have a specific signer configured.
	pub async fn new(
		network_ids: Vec<u64>,
		networks: &NetworksConfig,
		signers: HashMap<u64, AccountSigner>,
		default_signer: AccountSigner,
		fee_policy_config: &FeePolicyConfig,
	) -> Result<Self, DeliveryError> {
		// Validate at least one network
		if network_ids.is_empty() {
			return Err(DeliveryError::Network(
				"At least one network_id must be specified".to_string(),
			));
		}

		// Validate fee policy covers every requested chain. Missing entries
		// are a hard startup error — there is no implicit `default_for_chain`
		// fallback per the production invariant.
		let fee_policy = FeePolicyRegistry::from_config(fee_policy_config, &network_ids)
			.map_err(|e| DeliveryError::Network(format!("Invalid fee_policy: {e}")))?;

		let mut providers = HashMap::new();
		let mut nonce_managers = HashMap::new();
		let mut signer_addresses = HashMap::new();

		for network_id in &network_ids {
			// Get network configuration
			let network = networks.get(network_id).ok_or_else(|| {
				DeliveryError::Network(format!("Network {network_id} not found in configuration"))
			})?;

			// Get HTTP URL from network configuration
			let http_url = network.get_http_url().ok_or_else(|| {
				DeliveryError::Network(format!(
					"No HTTP RPC URL configured for network {network_id}"
				))
			})?;

			// Parse RPC URL
			let url = http_url.parse().map_err(|e| {
				DeliveryError::Network(format!("Invalid RPC URL for network {network_id}: {e}"))
			})?;

			// Get the signer for this network, or use the default
			let signer = signers
				.get(network_id)
				.cloned()
				.unwrap_or_else(|| default_signer.clone());

			// Create signer with chain ID
			let chain_signer = signer.with_chain_id(Some(*network_id));
			let signer_address = chain_signer.address();
			let wallet = EthereumWallet::from(chain_signer);

			// Retry only the rate-limit / transient cases (default policy). Execution
			// reverts on read-only calls (eth_estimateGas / eth_call) are deterministic
			// — retrying wastes the CU budget and stretches every subsequent call's
			// backoff. Submission-revert handling is now done at the application layer
			// by `classify_submission_outcome` (see nonce.rs), which routes
			// definitely-rejected reverts to the cache-rollback policy without needing
			// blind RPC-layer retries.
			let retry_layer = RetryBackoffLayer::new(
				3,    // max_retry
				1500, // backoff (ms, doubles each retry)
				10,   // cups: compute units per second
			);

			// Create RPC client with retry capabilities
			let client = RpcClient::builder().layer(retry_layer).http(url);

			// Build the provider WITHOUT a NonceFiller — we own nonce assignment via
			// `ResettableNonceManager` so we can resync from chain after a
			// `nonce too low` submission error. `submit()` sets `tx.nonce` explicitly.
			let provider = ProviderBuilder::new()
				.filler(GasFiller)
				.filler(ChainIdFiller::default())
				.wallet(wallet)
				.connect_client(client);

			provider
				.client()
				.set_poll_interval(std::time::Duration::from_secs(7));

			// Use type erasure to simplify the provider type
			let dyn_provider = provider.erased();
			match (
				dyn_provider.get_transaction_count(signer_address).await,
				dyn_provider
					.get_transaction_count(signer_address)
					.pending()
					.await,
			) {
				(Ok(latest), Ok(pending)) => {
					tracing::info!(
						chain_id = *network_id,
						signer = %signer_address,
						latest_nonce = latest,
						pending_nonce = pending,
						"Initialized EVM delivery nonce state"
					);
				},
				(latest_result, pending_result) => {
					tracing::warn!(
						chain_id = *network_id,
						signer = %signer_address,
						latest_error = ?latest_result.err(),
						pending_error = ?pending_result.err(),
						"Could not read initial EVM delivery nonce state"
					);
				},
			}
			providers.insert(*network_id, dyn_provider);
			nonce_managers.insert(*network_id, ResettableNonceManager::new());
			signer_addresses.insert(*network_id, signer_address);
		}

		// Spawn the passive nonce-drift monitor. The monitor is observability
		// only — it never mutates the cache, retries transactions, or affects
		// runtime behavior. `ResettableNonceManager` is `Clone` and shares its
		// inner cache via `Arc<Mutex<_>>`, and `DynProvider` is also clone-
		// shareable, so the spawned task observes the same live state.
		spawn_nonce_drift_monitor(
			nonce_managers.clone(),
			signer_addresses.clone(),
			providers.clone(),
		);

		Ok(Self {
			providers,
			nonce_managers,
			signer_addresses,
			fee_params_cache: Arc::new(FeeParamsCache::default()),
			fee_policy,
		})
	}

	/// Gets the provider for a specific chain ID.
	fn get_provider(&self, chain_id: u64) -> Result<&DynProvider, DeliveryError> {
		self.providers.get(&chain_id).ok_or_else(|| {
			DeliveryError::Network(format!("No provider configured for chain ID {chain_id}"))
		})
	}

	/// Gets the nonce manager for a specific chain ID.
	fn get_nonce_manager(&self, chain_id: u64) -> Result<&ResettableNonceManager, DeliveryError> {
		self.nonce_managers.get(&chain_id).ok_or_else(|| {
			DeliveryError::Network(format!(
				"No nonce manager configured for chain ID {chain_id}"
			))
		})
	}

	/// Gets the signer address for a specific chain ID.
	fn get_signer_address(&self, chain_id: u64) -> Result<Address, DeliveryError> {
		self.signer_addresses
			.get(&chain_id)
			.copied()
			.ok_or_else(|| {
				DeliveryError::Network(format!("No signer configured for chain ID {chain_id}"))
			})
	}

	/// Returns the next nonce to use for `from` on `chain_id`, taking it from the
	/// resettable cache. Every call samples chain `pending`, but normal allocation
	/// is monotonic: a stale RPC pending nonce must not move the local cache
	/// backward and reissue a nonce already handed out by this process. Backward
	/// reset is reserved for the explicit `nonce too low` resync path.
	async fn next_nonce_for(&self, chain_id: u64, from: Address) -> Result<u64, DeliveryError> {
		let provider = self.get_provider(chain_id)?;
		let pending = provider
			.get_transaction_count(from)
			.pending()
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to fetch pending nonce: {e}")))?;
		let mgr = self.get_nonce_manager(chain_id)?;
		let previous_local_next_nonce = mgr.peek(from);
		let local_next_nonce = mgr.set_next_nonce(from, pending);
		tracing::debug!(
			chain_id,
			signer = %from,
			chain_pending_nonce = pending,
			previous_local_next_nonce = ?previous_local_next_nonce,
			local_next_nonce,
			"Reconciled EVM delivery nonce cache"
		);
		let nonce_taken = mgr
			.take_next(from)
			.expect("nonce just reconciled via reconcile_with_chain_pending");
		tracing::debug!(
			chain_id,
			signer = %from,
			chain_pending = pending,
			local_before = ?previous_local_next_nonce,
			nonce_used = nonce_taken,
			local_after = nonce_taken + 1,
			"allocated nonce for broadcast"
		);
		Ok(nonce_taken)
	}

	/// Resync the local nonce manager from chain pending and return the next
	/// nonce to use for the resync retry. Advances the cache past whatever
	/// the chain already knows about.
	async fn resync_nonce_for(&self, chain_id: u64, from: Address) -> Result<u64, DeliveryError> {
		let provider = self.get_provider(chain_id)?;
		let pending = provider
			.get_transaction_count(from)
			.pending()
			.await
			.map_err(|e| {
				DeliveryError::Network(format!("Failed to fetch pending nonce for resync: {e}"))
			})?;
		let mgr = self.get_nonce_manager(chain_id)?;
		let before = mgr.peek(from);
		mgr.reset_next_nonce(from, pending);
		tracing::warn!(
			chain_id,
			signer = %from,
			previous_local_next_nonce = ?before,
			chain_pending_nonce = pending,
			"Reset EVM delivery nonce cache from chain pending"
		);
		Ok(mgr
			.take_next(from)
			.expect("nonce just reset via reset_next_nonce"))
	}
}

/// Configuration schema for Alloy delivery provider.
///
/// This schema defines the required configuration fields for the Alloy
/// delivery provider, including RPC URL and chain ID validation.
pub struct AlloyDeliverySchema;

impl AlloyDeliverySchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(
		config: &serde_json::Value,
	) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for AlloyDeliverySchema {
	fn validate(&self, config: &serde_json::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new(
					"network_ids",
					FieldType::Array(Box::new(FieldType::Integer {
						min: Some(1),
						max: None,
					})),
				)
				.with_validator(|value| {
					if let Some(arr) = value.as_array() {
						if arr.is_empty() {
							return Err("network_ids cannot be empty".to_string());
						}
						Ok(())
					} else {
						Err("network_ids must be an array".to_string())
					}
				}),
				// `fee_policy` is required for every Alloy delivery instance.
				// We don't enumerate every leaf field via `FieldType::Table`
				// here — the schema layer can't represent string-typed wei
				// values cleanly. Instead we deserialize into `FeePolicyConfig`
				// AND build a transient `FeePolicyRegistry` (with no required
				// chain ids — that completeness check is enforced at startup
				// against the live `network_ids`). The registry build is what
				// actually parses the wei strings, so any field-level error
				// surfaces with the offending field name in the message.
				Field::new("fee_policy", FieldType::Table(Schema::new(vec![], vec![])))
					.with_validator(|value| {
						let cfg = serde_json::from_value::<FeePolicyConfig>(value.clone())
							.map_err(|e| format!("fee_policy is invalid: {e}"))?;
						FeePolicyRegistry::from_config(&cfg, &[])
							.map_err(|e| format!("fee_policy is invalid: {e}"))?;
						Ok(())
					}),
			],
			// Optional fields
			vec![Field::new(
				"accounts",
				FieldType::Table(Schema::new(
					vec![], // No required fields - network IDs are dynamic
					vec![], // No optional fields - all entries should be account names
				)),
			)
			.with_validator(|value| {
				if let Some(table) = value.as_object() {
					// Validate that keys are valid integers (network IDs)
					// and values are strings (account names)
					for (key, val) in table {
						// Try to parse key as network ID
						if key.parse::<u64>().is_err() {
							return Err(format!("Invalid network ID in accounts: {key}"));
						}
						// Check value is a string
						if val.as_str().is_none() {
							return Err(format!("Account name for network {key} must be a string"));
						}
					}
					Ok(())
				} else {
					Err("accounts must be a table".to_string())
				}
			})],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl DeliveryInterface for AlloyDelivery {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(AlloyDeliverySchema)
	}

	async fn submit(
		&self,
		tx: SolverTransaction,
		tracking: Option<TransactionTrackingWithConfig>,
	) -> Result<TransactionHash, DeliveryError> {
		// Get the chain ID from the transaction
		let chain_id = tx.chain_id;

		// Get the appropriate provider for this chain
		let provider = self.get_provider(chain_id)?;
		let from = self.get_signer_address(chain_id)?;

		let mut tx_attempt = tx.clone();
		let fee_params = self.get_fee_params(chain_id).await?;
		fee_params.apply_if_missing(&mut tx_attempt);

		tracing::info!(
			chain_id,
			nonce = ?tx_attempt.nonce,
			fee_model = ?fee_params.model,
			gas_price = ?tx_attempt.gas_price,
			max_fee_per_gas = ?tx_attempt.max_fee_per_gas,
			max_priority_fee_per_gas = ?tx_attempt.max_priority_fee_per_gas,
			cost_per_gas = fee_params.cost_per_gas,
			"Applied transaction fee policy"
		);

		// PRE-SUBMIT DIAGNOSTIC SNAPSHOT.
		// Captures the signer's native balance and chain pending nonce before
		// `eth_sendRawTransaction`, plus the up-front native token reservation
		// that the RPC will require. If the balance read succeeds and the
		// signer cannot cover `gas_limit × fee_per_gas + value`, return before
		// consuming a nonce from the local cache.
		let native_gas_budget = native_gas_budget_wei(&tx_attempt);
		let pre_submit_balance = match provider.get_balance(from).await {
			Ok(balance) => Some(balance),
			Err(e) => {
				tracing::warn!(
					chain_id,
					signer = %from,
					error = %e,
					"Could not read native balance for gas preflight; proceeding without affordability check"
				);
				None
			},
		};
		let pre_submit_pending = provider.get_transaction_count(from).pending().await.ok();
		let native_shortfall = match (pre_submit_balance, native_gas_budget.as_ref()) {
			(Some(balance), Some(budget)) => native_gas_shortfall(balance, budget.required_wei),
			_ => None,
		};
		if let (Some(balance), Some(budget), Some(shortfall)) = (
			pre_submit_balance,
			native_gas_budget.as_ref(),
			native_shortfall,
		) {
			tracing::error!(
				chain_id,
				signer = %from,
				balance_wei = %balance,
				required_wei = %budget.required_wei,
				shortfall_wei = %shortfall,
				gas_budget_wei = %budget.gas_budget_wei,
				value_wei = %tx_attempt.value,
				gas_limit = ?tx_attempt.gas_limit,
				gas_price = ?tx_attempt.gas_price,
				max_fee_per_gas = ?tx_attempt.max_fee_per_gas,
				max_priority_fee_per_gas = ?tx_attempt.max_priority_fee_per_gas,
				"Insufficient native gas for transaction preflight; top up signer before retrying"
			);
			return Err(DeliveryError::InsufficientNativeGas(Box::new(
				InsufficientNativeGasInfo {
					chain_id,
					signer: from.to_string(),
					balance_wei: balance.to_string(),
					required_wei: budget.required_wei.to_string(),
					shortfall_wei: shortfall.to_string(),
					gas_limit: tx_attempt.gas_limit,
					max_fee_per_gas: tx_attempt.max_fee_per_gas,
					gas_price: tx_attempt.gas_price,
					value_wei: tx_attempt.value.to_string(),
				},
			)));
		}
		let balance_below_required = match (pre_submit_balance, native_gas_budget.as_ref()) {
			(Some(balance), Some(budget)) => Some(balance < budget.required_wei),
			_ => None,
		};
		tracing::debug!(
			chain_id,
			signer = %from,
			pending_nonce = ?pre_submit_pending,
			tx_nonce = ?tx_attempt.nonce,
			balance_wei = ?pre_submit_balance.map(|b| b.to_string()),
			gas_limit = ?tx_attempt.gas_limit,
			value_wei = %tx_attempt.value,
			gas_price = ?tx_attempt.gas_price,
			max_fee_per_gas = ?tx_attempt.max_fee_per_gas,
			max_priority_fee_per_gas = ?tx_attempt.max_priority_fee_per_gas,
			gas_budget_wei = ?native_gas_budget.as_ref().map(|b| b.gas_budget_wei.to_string()),
			required_wei = ?native_gas_budget.as_ref().map(|b| b.required_wei.to_string()),
			shortfall_wei = ?native_shortfall.map(|b| b.to_string()),
			balance_below_required = ?balance_below_required,
			"PRE-SUBMIT diagnostic snapshot"
		);

		// Fill nonce from the resettable manager only after preflight succeeds.
		// Insufficient native gas must not advance the local nonce cache.
		if tx_attempt.nonce.is_none() {
			tx_attempt.nonce = Some(self.next_nonce_for(chain_id, from).await?);
		}

		let request: TransactionRequest = tx_attempt.clone().into();

		// Log request details for debugging
		if tracking.is_some() {
			tracing::debug!(
				"Sending transaction with monitoring on chain {}: to={:?}, value={:?}, data_len={}, gas_limit={:?}, nonce={:?}",
				chain_id,
				request.to,
				request.value,
				request.input.input().map(|d| d.len()).unwrap_or(0),
				request.gas,
				request.nonce
			);
		} else {
			tracing::debug!(
				"Sending transaction on chain {}: to={:?}, value={:?}, data_len={}, gas_limit={:?}, nonce={:?}",
				chain_id,
				request.to,
				request.value,
				request.input.input().map(|d| d.len()).unwrap_or(0),
				request.gas,
				request.nonce
			);
		}

		// First attempt. Classify any submission error into one of four buckets
		// (NonceTooLow / DefinitelyRejected / Replacement / Ambiguous) and act
		// on the local nonce cache accordingly. See `nonce_action_for_outcome`
		// and `apply_nonce_cache_action`.
		let pending_tx = match provider.send_transaction(request).await {
			Ok(p) => {
				tracing::debug!(
					chain_id,
					signer = %from,
					nonce_used = ?tx_attempt.nonce,
					tx_hash = %p.tx_hash(),
					"tx submitted; nonce committed"
				);
				p
			},
			Err(first_err) => {
				let first_err_str = first_err.to_string();
				let outcome = classify_submission_outcome(&first_err_str);
				match nonce_action_for_outcome(outcome) {
					NonceCacheAction::NonceTooLowRetry => {
						// EXISTING path — resync local cache from chain
						// pending and retry once with the resynced nonce.
						tracing::warn!(
							chain_id,
							signer = %from,
							nonce_used = ?tx_attempt.nonce,
							error = %first_err,
							"submission failed: nonce too low; resyncing and retrying"
						);

						let retry_nonce = self.resync_nonce_for(chain_id, from).await?;
						let mut retry_tx = tx_attempt.clone();
						retry_tx.nonce = Some(retry_nonce);
						let retry_request: TransactionRequest = retry_tx.into();

						match provider.send_transaction(retry_request).await {
							Ok(p) => {
								tracing::info!(
									chain_id,
									retry_nonce,
									"Resynced nonce retry succeeded"
								);
								p
							},
							Err(retry_err) => {
								let retry_err_str = retry_err.to_string();
								let retry_outcome = classify_submission_outcome(&retry_err_str);
								match nonce_action_for_outcome(retry_outcome) {
									NonceCacheAction::NonceTooLowRetry => {
										tracing::error!(
											chain_id,
											retry_nonce,
											error = %retry_err,
											"Resynced nonce retry still failed with nonce too low — surfacing structured error"
										);
										let message = format!(
											"Chain {chain_id}: retry with resynced nonce {retry_nonce} still failed: {retry_err}"
										);
										return Err(DeliveryError::NonceTooLow(message));
									},
									action @ NonceCacheAction::AttemptRollback => {
										let mgr = self.get_nonce_manager(chain_id)?;
										let cache_before = mgr.peek(from);
										let pending_result =
											provider.get_transaction_count(from).pending().await;
										let (pending_opt, fetch_err): (
											Option<u64>,
											Option<String>,
										) = match pending_result {
											Ok(p) => (Some(p), None),
											Err(e) => (None, Some(e.to_string())),
										};
										let cache_after = apply_nonce_cache_action(
											mgr,
											from,
											action,
											pending_opt,
										);
										if let Some(pending) = pending_opt {
											tracing::warn!(
												chain_id,
												signer = %from,
												retry_nonce,
												chain_pending = pending,
												cache_before = ?cache_before,
												cache_after = ?cache_after,
												error = %retry_err_str,
												"resynced retry rejected pre-pool; nonce cache rolled back to chain pending"
											);
										} else {
											tracing::warn!(
												chain_id,
												signer = %from,
												retry_nonce,
												cache_before = ?cache_before,
												cache_after = ?cache_after,
												error = %retry_err_str,
												pending_fetch_error = ?fetch_err,
												"resynced retry rejected pre-pool BUT chain-pending fetch failed; nonce cache kept advanced"
											);
										}
									},
									action @ NonceCacheAction::Keep => {
										let mgr = self.get_nonce_manager(chain_id)?;
										let cache_after =
											apply_nonce_cache_action(mgr, from, action, None);
										tracing::warn!(
											chain_id,
											signer = %from,
											retry_nonce,
											cache_after = ?cache_after,
											outcome = ?retry_outcome,
											error = %retry_err_str,
											"resynced retry failed; nonce cache kept advanced (replacement-class or ambiguous error)"
										);
									},
								}
								tracing::error!(
									"Resynced nonce retry failed on chain {}: {}",
									chain_id,
									retry_err
								);
								return Err(DeliveryError::Network(format!(
									"Resynced nonce retry failed: {retry_err}"
								)));
							},
						}
					},
					action @ NonceCacheAction::AttemptRollback => {
						// Try to fetch authoritative chain pending. The helper
						// `apply_nonce_cache_action` enforces the invariant: on
						// Some(pending) it resets, on None it KEEPS the cache —
						// we never reset without authoritative chain state.
						let mgr = self.get_nonce_manager(chain_id)?;
						let cache_before = mgr.peek(from);
						let pending_result = provider.get_transaction_count(from).pending().await;
						let (pending_opt, fetch_err): (Option<u64>, Option<String>) =
							match pending_result {
								Ok(p) => (Some(p), None),
								Err(e) => (None, Some(e.to_string())),
							};
						let cache_after = apply_nonce_cache_action(mgr, from, action, pending_opt);
						if let Some(pending) = pending_opt {
							tracing::warn!(
								chain_id,
								signer = %from,
								nonce_used = ?tx_attempt.nonce,
								chain_pending = pending,
								cache_before = ?cache_before,
								cache_after = ?cache_after,
								error = %first_err_str,
								"tx rejected pre-pool; nonce cache rolled back to chain pending"
							);
						} else {
							tracing::warn!(
								chain_id,
								signer = %from,
								nonce_used = ?tx_attempt.nonce,
								cache_before = ?cache_before,
								cache_after = ?cache_after,
								error = %first_err_str,
								pending_fetch_error = ?fetch_err,
								"tx rejected pre-pool BUT chain-pending fetch failed; nonce cache kept advanced (no authoritative state)"
							);
						}
						return Err(DeliveryError::Network(format!(
							"Failed to send transaction: {first_err}"
						)));
					},
					action @ NonceCacheAction::Keep => {
						let mgr = self.get_nonce_manager(chain_id)?;
						let cache_after = apply_nonce_cache_action(mgr, from, action, None);
						tracing::warn!(
							chain_id,
							signer = %from,
							nonce_used = ?tx_attempt.nonce,
							cache_after = ?cache_after,
							outcome = ?outcome,
							error = %first_err_str,
							"tx submission did not accept; nonce cache kept advanced (replacement-class or ambiguous error)"
						);
						return Err(DeliveryError::Network(format!(
							"Failed to send transaction: {first_err}"
						)));
					},
				}
			},
		};

		// Get the transaction hash
		let tx_hash = *pending_tx.tx_hash();
		let tx_hash_obj = TransactionHash(tx_hash.0.to_vec());

		// POST-SUBMIT DIAGNOSTIC. Logged at DEBUG so it's silent in normal ops
		// but available via RUST_LOG=solver_delivery=debug for forensic runs.
		// NOTE: load-balanced RPC providers (e.g. Alchemy) have eventual
		// consistency between write and read endpoints — `pending_nonce` after
		// a successful submit can report the pre-submit value for tens of
		// seconds even though the tx has been accepted, propagated, and is on
		// its way to mining. Do NOT use it to decide retry/failure.
		let post_submit_pending = provider.get_transaction_count(from).pending().await.ok();
		let to_hex = tx_attempt
			.to
			.as_ref()
			.map(|addr| format!("0x{}", hex::encode(&addr.0)));
		tracing::debug!(
			chain_id,
			%tx_hash,
			signer = %from,
			to = ?to_hex,
			value_wei = %tx_attempt.value,
			data_len = tx_attempt.data.len(),
			tx_nonce = ?tx_attempt.nonce,
			gas_limit = ?tx_attempt.gas_limit,
			gas_price = ?tx_attempt.gas_price,
			max_fee_per_gas = ?tx_attempt.max_fee_per_gas,
			max_priority_fee_per_gas = ?tx_attempt.max_priority_fee_per_gas,
			pre_submit_pending_nonce = ?pre_submit_pending,
			post_submit_pending_nonce = ?post_submit_pending,
			pre_submit_balance_wei = ?pre_submit_balance.map(|b| b.to_string()),
			gas_budget_wei = ?native_gas_budget.as_ref().map(|b| b.gas_budget_wei.to_string()),
			required_wei = ?native_gas_budget.as_ref().map(|b| b.required_wei.to_string()),
			"POST-SUBMIT diagnostic snapshot (read-replica lag may make pending_nonce stale)"
		);

		// NOTE: a previous version of this code did a 3-attempt
		// `get_transaction_by_hash` "visibility check" right after submit and
		// returned an error + reset the nonce cache when the read came back
		// null. That was a false-positive trap: Alchemy's read endpoints lag
		// by tens of seconds (load-balanced read replicas), so a tx that has
		// been accepted by the pool, propagated, and is on its way to mining
		// can still return null for `get_transaction_by_hash`. Verified: a tx
		// declared "ghost" by that check actually mined at the requested
		// nonce. Removing the check; rely on `monitor_transaction` (when
		// tracking is provided) to detect actual confirmation, and on the
		// existing nonce-too-low retry path to handle stale local nonce.

		// If tracking is provided, set up monitoring
		if let Some(tracking) = tracking {
			let tx_hash_clone = tx_hash_obj.clone();
			// Erase the root provider to a `DynProvider` so it matches
			// `monitor_transaction`'s signature (and `ProviderProbe` inside it).
			let provider_clone = pending_tx.provider().clone().erased();
			tokio::spawn(async move {
				let result = monitor_transaction(
					provider_clone,
					tx_hash,
					tracking.min_confirmations,
					Duration::from_secs(tracking.tx_confirmation_timeout_seconds),
				)
				.await;

				match result {
					PollOutcome::Confirmed(receipt) => {
						(tracking.tracking.callback)(TransactionMonitoringEvent::Confirmed {
							id: tracking.tracking.id,
							tx_hash: tx_hash_clone,
							tx_type: tracking.tracking.tx_type,
							receipt,
						});
					},
					PollOutcome::Reverted(error) => {
						(tracking.tracking.callback)(TransactionMonitoringEvent::Failed {
							id: tracking.tracking.id,
							tx_hash: tx_hash_clone,
							tx_type: tracking.tracking.tx_type,
							error,
						});
					},
					PollOutcome::Indeterminate(reason) => {
						(tracking.tracking.callback)(TransactionMonitoringEvent::Indeterminate {
							id: tracking.tracking.id,
							tx_hash: tx_hash_clone,
							tx_type: tracking.tracking.tx_type,
							reason,
						});
					},
				}
			});
		}

		Ok(tx_hash_obj)
	}

	async fn get_receipt(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<TransactionReceipt, DeliveryError> {
		let tx_hash = FixedBytes::<32>::from_slice(&hash.0);

		// Get the provider for the specified chain
		let provider = self.get_provider(chain_id)?;

		match provider.get_transaction_receipt(tx_hash).await {
			Ok(Some(receipt)) => {
				// Convert alloy receipt to solver receipt using From implementation
				Ok(TransactionReceipt::from(&receipt))
			},
			Ok(None) => Err(DeliveryError::Network(format!(
				"Transaction not found on chain {chain_id}"
			))),
			Err(e) => Err(DeliveryError::Network(format!(
				"Failed to get receipt on chain {chain_id}: {e}"
			))),
		}
	}

	/// Gets effective fee parameters for the network.
	///
	/// EIP-1559 path: pulls the `eth_feeHistory` window at the policy's
	/// configured percentile, runs the rewards through `SolverEip1559Estimator`
	/// (median-of-nonzero + per-chain priority floor + projection), and applies
	/// the chain's `quote_cost_strategy` to derive `cost_per_gas`.
	///
	/// Base-fee resolution mirrors alloy's `estimate_eip1559_fees_with` ladder:
	/// prefer the value embedded in the fee-history response, fall back to the
	/// latest block's `base_fee_per_gas`, and only downgrade to legacy
	/// (`eth_gasPrice`) when neither is present.
	///
	/// On `feeHistory` RPC error we WARN and degrade to legacy `eth_gasPrice`
	/// rather than failing the quote entirely. This degraded result is NOT
	/// cached — we want the next quote to retry the EIP-1559 path.
	async fn get_fee_params(&self, chain_id: u64) -> Result<FeeParams, DeliveryError> {
		// Cache hit short-circuits the RPC round-trip(s). `now` is the single
		// clock reading we use both for the lookup and (on miss) for the
		// subsequent insert, so cache age is consistent with the resolved
		// value's freshness.
		let now = Instant::now();
		let ttl = fee_params_cache_ttl(chain_id);
		if let Some(params) = self.fee_params_cache.get(chain_id, ttl, now).await {
			tracing::debug!(chain_id, "Fee params cache hit");
			return Ok(params);
		}
		tracing::debug!(chain_id, "Fee params cache miss");

		let provider = self.get_provider(chain_id)?;
		// Per Task 8: the fee policy is sourced from required startup config,
		// not hard-coded defaults. The registry is built against the same
		// `network_ids` we constructed providers for, so a lookup here is
		// guaranteed to succeed (any miss is a programmer error and panics).
		let policy = self.fee_policy.policy_for_chain(chain_id).clone();

		// Custom percentile: alloy's `estimate_eip1559_fees_with` hardcodes the
		// 20th percentile internally, so we fetch fee history ourselves at the
		// configured speed and feed it through our estimator.
		let percentile = policy.speed.reward_percentile();
		let history = match provider
			.get_fee_history(10, BlockNumberOrTag::Latest, &[percentile])
			.await
		{
			Ok(h) => h,
			Err(e) => {
				// feeHistory RPC failed. Degrade to legacy `eth_gasPrice` so
				// quotes keep flowing, but DO NOT cache — we want the next
				// quote to retry the EIP-1559 path.
				let gp = provider.get_gas_price().await.map_err(|gas_err| {
					DeliveryError::Network(format!(
						"Failed to get fee history ({e}) and legacy gas price fallback ({gas_err})"
					))
				})?;
				tracing::warn!(
					chain_id,
					error = %e,
					gas_price = gp,
					"Falling back to legacy gas price after feeHistory failure"
				);
				return Ok(FeeParams::legacy(chain_id, gp));
			},
		};

		// Resolve base fee with the same fallback ladder alloy's
		// `estimate_eip1559_fees_with` uses: prefer the value from the
		// fee-history response; if it's missing or zero, fetch the latest
		// block directly and read its `base_fee_per_gas`; only if THAT also
		// has no base_fee do we conclude the chain is pre-1559 and downgrade
		// to legacy. Without the intermediate step, an EIP-1559 chain whose
		// feeHistory response happens to omit the base-fee column gets
		// mispriced as legacy.
		let base_fee: u128 = match history.latest_block_base_fee() {
			Some(b) if b != 0 => b,
			_ => {
				let block = provider
					.get_block_by_number(BlockNumberOrTag::Latest)
					.await
					.map_err(|e| {
						DeliveryError::Network(format!("Failed to get latest block: {e}"))
					})?;

				let block_base_fee: Option<u128> =
					block.and_then(|b| b.header().base_fee_per_gas().map(u128::from));

				match block_base_fee {
					Some(b) if b != 0 => b,
					_ => {
						// Genuinely pre-EIP-1559 chain (or no base_fee field).
						let gp = provider.get_gas_price().await.map_err(|e| {
							DeliveryError::Network(format!("Failed to get legacy gas price: {e}"))
						})?;
						let params = FeeParams::legacy(chain_id, gp);
						tracing::debug!(chain_id, gas_price = gp, "Resolved legacy fee params");
						self.fee_params_cache
							.insert(chain_id, params.clone(), now)
							.await;
						return Ok(params);
					},
				}
			},
		};

		let rewards = history.reward.unwrap_or_default();
		let estimator = SolverEip1559Estimator {
			policy: policy.clone(),
		};
		let est = estimator.estimate(base_fee, &rewards);

		let params = FeeParams::eip1559_with_strategy(
			chain_id,
			est.max_fee_per_gas,
			est.max_priority_fee_per_gas,
			base_fee,
			policy.quote_cost_strategy,
		);

		tracing::debug!(
			chain_id,
			max_fee_per_gas = ?params.max_fee_per_gas,
			max_priority_fee_per_gas = ?params.max_priority_fee_per_gas,
			cost_per_gas = params.cost_per_gas,
			"Resolved EIP-1559 fee params"
		);

		self.fee_params_cache
			.insert(chain_id, params.clone(), now)
			.await;
		Ok(params)
	}

	async fn get_balance(
		&self,
		address: &str,
		token: Option<&str>,
		chain_id: u64,
	) -> Result<String, DeliveryError> {
		let address: Address = address
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid address: {e}")))?;

		let provider = self.get_provider(chain_id)?;

		match token {
			None => {
				// Get native token balance
				let balance = provider
					.get_balance(address)
					.await
					.map_err(|e| DeliveryError::Network(format!("Failed to get balance: {e}")))?;

				Ok(balance.to_string())
			},
			Some(token_address) => {
				// Get ERC-20 token balance
				let token_addr: Address = token_address
					.parse()
					.map_err(|e| DeliveryError::Network(format!("Invalid token address: {e}")))?;

				// Create the balanceOf call data
				// balanceOf(address) selector is 0x70a08231
				let selector = [0x70, 0xa0, 0x82, 0x31];
				let mut call_data = Vec::new();
				call_data.extend_from_slice(&selector);
				call_data.extend_from_slice(&[0; 12]); // Pad to 32 bytes
				call_data.extend_from_slice(address.as_slice());

				let call_result = provider
					.call(
						TransactionRequest::default()
							.to(token_addr)
							.input(call_data.into()),
					)
					.await
					.map_err(|e| {
						DeliveryError::Network(format!("Failed to call balanceOf: {e}"))
					})?;

				if call_result.len() < 32 {
					return Err(DeliveryError::Network(
						"Invalid balanceOf response".to_string(),
					));
				}

				let balance = U256::from_be_slice(&call_result[..32]);
				Ok(balance.to_string())
			},
		}
	}

	async fn get_allowance(
		&self,
		owner: &str,
		spender: &str,
		token_address: &str,
		chain_id: u64,
	) -> Result<String, DeliveryError> {
		let owner_addr: Address = owner
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid owner address: {e}")))?;

		let spender_addr: Address = spender
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid spender address: {e}")))?;

		let token_addr: Address = token_address
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid token address: {e}")))?;

		let provider = self.get_provider(chain_id)?;

		// Create the allowance call data
		// allowance(address,address) selector is 0xdd62ed3e
		let selector = [0xdd, 0x62, 0xed, 0x3e];
		let mut call_data = Vec::new();
		call_data.extend_from_slice(&selector);
		call_data.extend_from_slice(&[0; 12]); // Pad owner address to 32 bytes
		call_data.extend_from_slice(owner_addr.as_slice());
		call_data.extend_from_slice(&[0; 12]); // Pad spender address to 32 bytes
		call_data.extend_from_slice(spender_addr.as_slice());

		let call_request = TransactionRequest::default()
			.to(token_addr)
			.input(call_data.into());

		let call_result = provider
			.call(call_request)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to call allowance: {e}")))?;

		if call_result.len() < 32 {
			return Err(DeliveryError::Network(
				"Invalid allowance response".to_string(),
			));
		}

		let allowance = U256::from_be_slice(&call_result[..32]);
		Ok(allowance.to_string())
	}

	async fn get_nonce(&self, address: &str, chain_id: u64) -> Result<u64, DeliveryError> {
		let address: Address = address
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid address: {e}")))?;

		let provider = self.get_provider(chain_id)?;

		provider
			.get_transaction_count(address)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to get nonce: {e}")))
	}

	async fn get_block_number(&self, chain_id: u64) -> Result<u64, DeliveryError> {
		let provider = self.get_provider(chain_id)?;

		provider
			.get_block_number()
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to get block number: {e}")))
	}
	async fn estimate_gas(&self, tx: SolverTransaction) -> Result<u64, DeliveryError> {
		// Get the chain ID from the transaction
		let chain_id = tx.chain_id;

		// Get the appropriate provider for this chain
		let provider = self.get_provider(chain_id)?;

		// Convert to TransactionRequest
		let request: TransactionRequest = tx.into();

		// The provider with wallet will automatically handle setting the `from` field
		// when needed for gas estimation
		let gas = provider
			.estimate_gas(request)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to estimate gas: {e}")))?;
		Ok(gas)
	}

	async fn estimate_gas_with_overrides(
		&self,
		tx: SolverTransaction,
		state_override: alloy_rpc_types::state::StateOverride,
	) -> Result<u64, DeliveryError> {
		// Mirror the existing estimate_gas impl: derive chain_id from
		// tx.chain_id and route via self.get_provider(chain_id). Per
		// the DeliveryInterface contract, this method is per-chain at
		// the trait level but the impl multiplexes via the chain_id
		// carried on the Transaction itself.
		let chain_id = tx.chain_id;
		let provider = self.get_provider(chain_id)?;

		let request: TransactionRequest = tx.into();

		// alloy 1.0.37 EthCall::overrides takes `impl Into<StateOverride>`,
		// NOT `&StateOverride` — pass the value owned. The state_override
		// arg isn't used after this point in the method, so consuming is
		// fine. If a future alloy version changes the signature, swap to
		// `.overrides_opt(Some(state_override))`.
		let gas = provider
			.estimate_gas(request)
			.overrides(state_override)
			.await
			.map_err(|e| {
				DeliveryError::Network(format!("Failed to estimate gas with overrides: {e}"))
			})?;
		Ok(gas)
	}

	async fn eth_call(&self, tx: SolverTransaction) -> Result<Bytes, DeliveryError> {
		// Get the chain ID from the transaction
		let chain_id = tx.chain_id;

		// Get the appropriate provider for this chain
		let provider = self.get_provider(chain_id)?;

		// Convert to TransactionRequest
		let request: TransactionRequest = tx.into();

		// Execute the call without submitting a transaction
		let result = provider
			.call(request)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to execute eth_call: {e}")))?;

		Ok(result)
	}

	async fn tx_exists(
		&self,
		hash: &solver_types::TransactionHash,
		chain_id: u64,
	) -> Result<bool, DeliveryError> {
		let provider = self.get_provider(chain_id)?;
		let tx_hash = alloy_primitives::FixedBytes::<32>::from_slice(&hash.0);

		match provider.get_transaction_by_hash(tx_hash).await {
			Ok(Some(_)) => Ok(true),
			Ok(None) => Ok(false),
			Err(e) => Err(DeliveryError::Network(format!(
				"Failed to check transaction on chain {chain_id}: {e}"
			))),
		}
	}

	async fn get_logs(
		&self,
		chain_id: u64,
		filter: solver_types::LogFilter,
	) -> Result<Vec<solver_types::Log>, DeliveryError> {
		let provider = self.get_provider(chain_id)?;

		let mut alloy_filter = alloy_rpc_types::Filter::new()
			.address(alloy_primitives::Address::from_slice(&filter.address.0))
			.from_block(filter.from_block);

		if let Some(to) = filter.to_block {
			alloy_filter = alloy_filter.to_block(to);
		}

		// Apply topic filters for precise event matching
		for (i, topic) in filter.topics().iter().enumerate() {
			if let Some(t) = topic {
				let topic_hash = alloy_primitives::FixedBytes::<32>::from(t.0);
				match i {
					0 => alloy_filter = alloy_filter.event_signature(topic_hash),
					1 => alloy_filter = alloy_filter.topic1(topic_hash),
					2 => alloy_filter = alloy_filter.topic2(topic_hash),
					3 => alloy_filter = alloy_filter.topic3(topic_hash),
					_ => {},
				}
			}
		}

		let logs = provider
			.get_logs(&alloy_filter)
			.await
			.map_err(|e| DeliveryError::Network(format!("get_logs failed: {e}")))?;

		Ok(logs
			.into_iter()
			.map(|l| solver_types::Log {
				address: solver_types::Address(l.address().as_slice().to_vec()),
				topics: l.topics().iter().map(|t| solver_types::H256(t.0)).collect(),
				data: l.data().data.to_vec(),
			})
			.collect())
	}
}

/// Alias for the Ethereum-flavored transaction receipt returned by
/// `provider.get_transaction_receipt(...)`. Used in the `ConfirmationProbe`
/// trait so production and test impls share the exact type the provider
/// already returns at the existing receipt-check call site.
type AlloyReceipt = alloy_rpc_types::TransactionReceipt;

/// Probe abstraction over the two RPC calls the polling monitor needs.
/// Production impl wraps a real `DynProvider`; tests provide a `MockProbe`
/// with controllable response queues so the polling loop can be exercised
/// deterministically without anvil.
#[async_trait]
trait ConfirmationProbe: Send + Sync {
	async fn get_receipt(&self, tx_hash: B256) -> Result<Option<AlloyReceipt>, TransportError>;
	async fn get_block_number(&self) -> Result<u64, TransportError>;
}

/// Production `ConfirmationProbe` that defers to a `DynProvider`.
struct ProviderProbe(DynProvider);

#[async_trait]
impl ConfirmationProbe for ProviderProbe {
	async fn get_receipt(&self, tx_hash: B256) -> Result<Option<AlloyReceipt>, TransportError> {
		self.0.get_transaction_receipt(tx_hash).await
	}

	async fn get_block_number(&self) -> Result<u64, TransportError> {
		self.0.get_block_number().await
	}
}

/// Polling loop that drives a transaction from "submitted" to one of
/// `Confirmed` / `Reverted` / `Indeterminate`.
///
/// - Transient RPC errors (failures from `get_receipt` or `get_block_number`)
///   are logged at `warn` and the loop continues until the deadline. A single
///   transient error must not fail the order.
/// - A receipt with `status() == false` returns `Reverted` immediately, no
///   further polling.
/// - When confirmations >= `min_confirmations`, returns `Confirmed`.
/// - When `confirmation_timeout` elapses without sufficient confirmations,
///   returns `Indeterminate`. The caller MUST map this to a non-terminal
///   event; see `PollOutcome` doc.
async fn poll_for_confirmation(
	probe: &dyn ConfirmationProbe,
	tx_hash: B256,
	min_confirmations: u64,
	confirmation_timeout: Duration,
	poll_interval: Duration,
) -> PollOutcome {
	let deadline = Instant::now() + confirmation_timeout;
	let mut last_logged_confirmations: Option<u64> = None;

	tracing::debug!(?tx_hash, min_confirmations, "Starting tx confirmation poll");

	loop {
		if Instant::now() >= deadline {
			tracing::warn!(?tx_hash, "Tx confirmation deadline reached → Indeterminate");
			return PollOutcome::Indeterminate(format!(
				"Tx {tx_hash:?} did not reach {min_confirmations} confirmations within timeout"
			));
		}

		match probe.get_receipt(tx_hash).await {
			Ok(Some(receipt)) => {
				if !receipt.status() {
					tracing::warn!(?tx_hash, "Tx reverted on chain");
					return PollOutcome::Reverted("Transaction reverted".to_string());
				}
				let receipt_block = match receipt.block_number {
					Some(b) => b,
					None => {
						// Mined into pending block but no number yet — keep polling.
						tokio::time::sleep(poll_interval).await;
						continue;
					},
				};
				match probe.get_block_number().await {
					Ok(current_block) => {
						let confirmations = current_block.saturating_sub(receipt_block);
						if last_logged_confirmations != Some(confirmations) {
							tracing::debug!(
								?tx_hash,
								receipt_block,
								current_block,
								confirmations,
								"Tx mined; tracking confirmations"
							);
							last_logged_confirmations = Some(confirmations);
						}
						if confirmations >= min_confirmations {
							return PollOutcome::Confirmed(TransactionReceipt::from(&receipt));
						}
					},
					Err(e) => {
						tracing::warn!(
							?tx_hash,
							error = %e,
							"get_block_number transient error; will retry"
						);
					},
				}
			},
			Ok(None) => {
				// Receipt not yet available — normal pending state.
			},
			Err(e) => {
				tracing::warn!(
					?tx_hash,
					error = %e,
					"get_transaction_receipt transient error; will retry"
				);
			},
		}

		tokio::time::sleep(poll_interval).await;
	}
}

/// Monitors a submitted transaction for confirmation, revert, or timeout.
///
/// Thin wrapper around `poll_for_confirmation` that wraps the provider in a
/// `ProviderProbe` and supplies the module-level poll interval. Returns a
/// `PollOutcome` so the caller can map a deadline expiry to a non-terminal
/// `TransactionMonitoringEvent::Indeterminate` rather than the terminal
/// `Failed` event (which would leave the order permanently `OrderStatus::Failed`
/// even if the tx later confirms; recovery skips Failed orders).
async fn monitor_transaction(
	provider: DynProvider,
	tx_hash: B256,
	min_confirmations: u64,
	confirmation_timeout: Duration,
) -> PollOutcome {
	poll_for_confirmation(
		&ProviderProbe(provider),
		tx_hash,
		min_confirmations,
		confirmation_timeout,
		TX_CONFIRMATION_POLL_INTERVAL,
	)
	.await
}

/// Factory function to create an HTTP-based delivery provider from configuration.
///
/// This function reads the delivery configuration and creates an AlloyDelivery
/// instance.
///
/// # Parameters
/// - `config`: TOML configuration containing:
///   - `network_ids` (required): Array of network IDs to support
///   - `accounts` (optional): Map of network IDs to account names for per-network signing
/// - `networks`: Network configuration containing RPC URLs and contract addresses
/// - `default_signer`: Default signer for signing transactions
/// - `network_signers`: Map of network IDs to signers for per-network signing
///
/// # Returns
/// A boxed implementation of DeliveryInterface configured for the specified networks
pub fn create_http_delivery(
	config: &serde_json::Value,
	networks: &NetworksConfig,
	default_signer: &AccountSigner,
	network_signers: &HashMap<u64, AccountSigner>,
) -> Result<Box<dyn DeliveryInterface>, DeliveryError> {
	// Validate configuration first
	AlloyDeliverySchema::validate_config(config)
		.map_err(|e| DeliveryError::Network(format!("Invalid configuration: {e}")))?;

	// Parse network_ids (required field)
	let network_ids = config
		.get("network_ids")
		.and_then(|v| v.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| v.as_i64().map(|i| i as u64))
				.collect::<Vec<_>>()
		})
		.ok_or_else(|| DeliveryError::Network("network_ids is required".to_string()))?;

	if network_ids.is_empty() {
		return Err(DeliveryError::Network(
			"network_ids cannot be empty".to_string(),
		));
	}

	// Parse the required `fee_policy` block. Schema validation already
	// rejected configs without it, but full deserialization here gives
	// the constructor a typed `FeePolicyConfig` to hand to the registry.
	let fee_policy_value = config.get("fee_policy").ok_or_else(|| {
		DeliveryError::Network(
			"fee_policy is required for evm_alloy delivery configuration".to_string(),
		)
	})?;
	let fee_policy_config: FeePolicyConfig = serde_json::from_value(fee_policy_value.clone())
		.map_err(|e| DeliveryError::Network(format!("Invalid fee_policy: {e}")))?;

	// Clone the signers for use in the async block
	let default_signer = default_signer.clone();
	let network_signers = network_signers.clone();

	// Create delivery service synchronously, but the actual connection happens async
	let delivery = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(async {
			AlloyDelivery::new(
				network_ids,
				networks,
				network_signers,
				default_signer,
				&fee_policy_config,
			)
			.await
		})
	})?;

	Ok(Box::new(delivery))
}

/// Registry for the HTTP/Alloy delivery implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "evm_alloy";
	type Factory = crate::DeliveryFactory;

	fn factory() -> Self::Factory {
		create_http_delivery
	}
}

impl crate::DeliveryRegistry for Registry {}

#[cfg(test)]
mod fee_params_cache_tests {
	//! Direct tests for the per-chain `FeeParamsCache`. These exercise the
	//! freshness/expiry contract with explicit `Instant` values — no provider
	//! mock or async sleep is needed because both `get` and `insert` accept
	//! the clock reading from the caller.
	use super::*;

	#[tokio::test]
	async fn fee_params_cache_returns_fresh_entry() {
		let cache = FeeParamsCache::default();
		let params = FeeParams::legacy(1, 1_000_000_000);
		let now = Instant::now();

		cache.insert(1, params.clone(), now).await;
		let cached = cache.get(1, Duration::from_secs(3), now).await;

		assert_eq!(cached, Some(params));
	}

	#[tokio::test]
	async fn fee_params_cache_expires_stale_entry() {
		let cache = FeeParamsCache::default();
		let params = FeeParams::legacy(1, 1_000_000_000);
		let now = Instant::now();

		cache.insert(1, params, now - Duration::from_secs(10)).await;
		let cached = cache.get(1, Duration::from_secs(3), now).await;

		assert_eq!(cached, None);
	}

	#[tokio::test]
	async fn fee_params_cache_miss_when_chain_absent() {
		// Sanity: looking up a chain we never inserted yields None even at t=0.
		let cache = FeeParamsCache::default();
		let now = Instant::now();
		assert_eq!(cache.get(42, Duration::from_secs(3), now).await, None);
	}

	#[tokio::test]
	async fn fee_params_cache_overwrites_existing_entry() {
		// Confirms `insert` is overwrite, not append-with-staleness — the
		// `get_fee_params` happy path relies on this so a fresh resolve
		// always shadows any prior cached value.
		let cache = FeeParamsCache::default();
		let now = Instant::now();
		let stale = FeeParams::legacy(1, 1);
		let fresh = FeeParams::legacy(1, 2_000_000_000);

		cache.insert(1, stale, now - Duration::from_secs(10)).await;
		cache.insert(1, fresh.clone(), now).await;

		assert_eq!(cache.get(1, Duration::from_secs(3), now).await, Some(fresh));
	}

	#[test]
	fn fee_params_cache_ttl_per_chain() {
		// Defaults documented in the plan (Task 4 Step 2).
		assert_eq!(fee_params_cache_ttl(1), Duration::from_secs(3));
		assert_eq!(fee_params_cache_ttl(747474), Duration::from_secs(1));
		assert_eq!(fee_params_cache_ttl(137), Duration::from_secs(2));
		assert_eq!(fee_params_cache_ttl(42161), Duration::from_secs(2));
	}
}

#[cfg(test)]
mod tests {
	// Note: unit-level coverage of `estimate_gas_with_overrides` is deferred to
	// Task 6's live integration test — this crate has no `wiremock` or
	// `alloy-node-bindings` dev-dependency, so a mock RPC harness isn't
	// available here.
	use super::*;
	use alloy_signer_local::PrivateKeySigner;
	use solver_types::utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder};
	use std::collections::HashMap;

	// Test private key split to avoid triggering secret scanners in CI
	// This is Anvil's default test account #0 - DO NOT use in production
	const TEST_PRIVATE_KEY: &str = concat!(
		"0xac0974bec39a17e3",
		"6ba4a6b4d238ff94",
		"4bacb478cbed5efc",
		"ae784d7bf4f2ff80",
	);

	fn create_test_networks() -> NetworksConfig {
		NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.add_network(137, NetworkConfigBuilder::new().build())
			.build()
	}

	fn create_test_signer() -> AccountSigner {
		let private_key_signer: PrivateKeySigner = TEST_PRIVATE_KEY.parse().unwrap();
		AccountSigner::Local(private_key_signer)
	}

	/// Test helper: build a `FeePolicyConfig` covering chain 1 (with a
	/// mainnet-style priority floor) and 137 (the only other chain id any
	/// existing test requests). Mirrors the production schema so tests
	/// exercise the same deserialization path as real configs.
	fn test_fee_policy() -> FeePolicyConfig {
		serde_json::from_value(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"1": {
					"min_priority_fee_per_gas": "2000000000",
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125"
				},
				"137": {
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125"
				}
			}
		}))
		.expect("test fee policy must be valid")
	}

	#[tokio::test]
	async fn test_alloy_delivery_new_success() {
		let networks = create_test_networks();
		let signer = create_test_signer();

		let result = AlloyDelivery::new(
			vec![1],
			&networks,
			HashMap::new(),
			signer,
			&test_fee_policy(),
		)
		.await;

		assert!(result.is_ok());
		let delivery = result.unwrap();
		assert!(delivery.providers.contains_key(&1));
	}

	#[tokio::test]
	async fn test_alloy_delivery_new_empty_networks() {
		let networks = NetworksConfigBuilder::new().build();
		let signer = create_test_signer();

		let result = AlloyDelivery::new(
			vec![],
			&networks,
			HashMap::new(),
			signer,
			&test_fee_policy(),
		)
		.await;

		assert!(matches!(result, Err(DeliveryError::Network(_))));
		if let Err(DeliveryError::Network(msg)) = result {
			assert!(msg.contains("At least one network_id must be specified"));
		}
	}

	/// JSON shape of a `fee_policy` block that satisfies schema validation
	/// for chain id 1. Mirrors the production schema documented in the
	/// plan so the schema tests exercise a realistic config.
	fn schema_fee_policy_value() -> serde_json::Value {
		serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"1": {
					"min_priority_fee_per_gas": "2000000000",
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125"
				}
			}
		})
	}

	#[test]
	fn test_config_schema_validation_valid() {
		let schema = AlloyDeliverySchema;
		let config = serde_json::Value::Object({
			let mut table = serde_json::Map::new();
			table.insert(
				"network_ids".to_string(),
				serde_json::Value::Array(vec![serde_json::Value::from(1)]),
			);
			table.insert("fee_policy".to_string(), schema_fee_policy_value());
			table
		});

		let result = schema.validate(&config);
		assert!(result.is_ok(), "expected ok, got {result:?}");
	}

	#[test]
	fn test_config_schema_validation_empty_network_ids() {
		let schema = AlloyDeliverySchema;
		let config = serde_json::Value::Object({
			let mut table = serde_json::Map::new();
			table.insert("network_ids".to_string(), serde_json::Value::Array(vec![]));
			table.insert("fee_policy".to_string(), schema_fee_policy_value());
			table
		});

		let result = schema.validate(&config);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("network_ids cannot be empty"));
	}

	#[test]
	fn test_config_schema_validation_missing_fee_policy_fails() {
		// Per Task 8: configs without `fee_policy` MUST fail validation.
		let schema = AlloyDeliverySchema;
		let config = serde_json::json!({
			"network_ids": [1],
		});
		let err = schema.validate(&config).expect_err("missing fee_policy");
		assert!(
			err.to_string().contains("fee_policy"),
			"expected error mentioning fee_policy, got: {err}"
		);
	}

	#[test]
	fn test_config_schema_validation_invalid_fee_policy_decimal_fails() {
		// Schema validation delegates fee_policy parsing to the deserializer,
		// so a bad wei string surfaces with the offending field name.
		let schema = AlloyDeliverySchema;
		let config = serde_json::json!({
			"network_ids": [1],
			"fee_policy": {
				"default_speed": "fast",
				"chains": {
					"1": {
						"min_priority_fee_per_gas": "2000000000",
						"priority_fee_fallback": "not-a-number",
						"quote_cost_strategy": "buffered_effective_125"
					}
				}
			}
		});
		let err = schema.validate(&config).expect_err("invalid wei string");
		assert!(err.to_string().contains("fee_policy"));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_create_http_delivery_success() {
		let config = serde_json::Value::Object({
			let mut table = serde_json::Map::new();
			table.insert(
				"network_ids".to_string(),
				serde_json::Value::Array(vec![serde_json::Value::from(1)]),
			);
			table.insert("fee_policy".to_string(), schema_fee_policy_value());
			table
		});

		let networks = create_test_networks();
		let default_signer = create_test_signer();
		let network_signers = HashMap::new();

		let result = create_http_delivery(&config, &networks, &default_signer, &network_signers);
		assert!(result.is_ok(), "expected ok, got {:?}", result.err());
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_create_http_delivery_fails_without_fee_policy() {
		// The factory MUST reject configs that omit `fee_policy`, even if
		// `network_ids` is present and valid. Production invariant from
		// the plan (line ~53) — no default fallback.
		let config = serde_json::json!({
			"network_ids": [1],
		});
		let networks = create_test_networks();
		let default_signer = create_test_signer();
		let network_signers = HashMap::new();

		let result = create_http_delivery(&config, &networks, &default_signer, &network_signers);
		let err = result.err().expect("missing fee_policy must fail");
		assert!(
			err.to_string().contains("fee_policy"),
			"error must mention fee_policy: {err}"
		);
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_create_http_delivery_fails_when_chain_missing_in_fee_policy() {
		// Configured network 137 has no entry in fee_policy.chains — the
		// registry must refuse to start.
		let config = serde_json::json!({
			"network_ids": [1, 137],
			"fee_policy": {
				"default_speed": "fast",
				"chains": {
					"1": {
						"priority_fee_fallback": "100000000",
						"quote_cost_strategy": "buffered_effective_125"
					}
				}
			}
		});
		let networks = create_test_networks();
		let default_signer = create_test_signer();
		let network_signers = HashMap::new();

		let result = create_http_delivery(&config, &networks, &default_signer, &network_signers);
		let err = result.err().expect("missing chain entry must fail");
		assert!(
			err.to_string().contains("137"),
			"error must mention the missing chain id: {err}"
		);
	}

	#[test]
	fn test_registry_name() {
		assert_eq!(
			<Registry as solver_types::ImplementationRegistry>::NAME,
			"evm_alloy"
		);
	}

	// ========================================================================
	// Transaction Monitoring Tests
	// ========================================================================
	//
	// These tests cover the monitor_transaction function which handles:
	// 1. Fast-mining race condition (tx already mined before subscription starts)
	// 2. Normal subscription-based monitoring
	// 3. Confirmation counting
	// 4. Reverted transaction handling
	//
	// Note: Full integration tests require a running blockchain (anvil/hardhat).
	// The tests below focus on the logic paths using real RPCs where possible.
	// ========================================================================

	#[test]
	fn nonce_action_for_outcome_maps_correctly() {
		use NonceCacheAction::*;
		use SubmissionOutcome::*;
		assert_eq!(
			nonce_action_for_outcome(DefinitelyRejected),
			AttemptRollback
		);
		assert_eq!(nonce_action_for_outcome(Replacement), Keep);
		assert_eq!(nonce_action_for_outcome(Ambiguous), Keep);
		assert_eq!(nonce_action_for_outcome(NonceTooLow), NonceTooLowRetry);
	}

	#[test]
	fn apply_nonce_cache_action_rollback_with_pending_resets_cache() {
		use NonceCacheAction::*;
		let mgr = ResettableNonceManager::new();
		let signer = Address::ZERO;
		mgr.reset_next_nonce(signer, 101);
		assert_eq!(mgr.peek(signer), Some(101));

		let after = apply_nonce_cache_action(&mgr, signer, AttemptRollback, Some(100));
		assert_eq!(
			after,
			Some(100),
			"cache must reset to authoritative pending"
		);
		assert_eq!(mgr.peek(signer), Some(100));
	}

	#[test]
	fn apply_nonce_cache_action_rollback_without_pending_keeps_cache() {
		use NonceCacheAction::*;
		let mgr = ResettableNonceManager::new();
		let signer = Address::ZERO;
		mgr.reset_next_nonce(signer, 101);

		let after = apply_nonce_cache_action(&mgr, signer, AttemptRollback, None);
		assert_eq!(
			after,
			Some(101),
			"no authoritative chain state → cache must NOT be reset"
		);
		assert_eq!(mgr.peek(signer), Some(101));
	}

	#[test]
	fn apply_nonce_cache_action_keep_does_not_mutate() {
		use NonceCacheAction::*;
		let mgr = ResettableNonceManager::new();
		let signer = Address::ZERO;
		mgr.reset_next_nonce(signer, 101);

		let after = apply_nonce_cache_action(&mgr, signer, Keep, Some(95));
		assert_eq!(after, Some(101));
		assert_eq!(mgr.peek(signer), Some(101), "Keep must not touch the cache");
	}

	#[test]
	fn apply_nonce_cache_action_nonce_too_low_is_noop() {
		use NonceCacheAction::*;
		let mgr = ResettableNonceManager::new();
		let signer = Address::ZERO;
		mgr.reset_next_nonce(signer, 101);

		// The NonceTooLow path is handled by the existing retry branch; the
		// helper must not double-handle it.
		let after = apply_nonce_cache_action(&mgr, signer, NonceTooLowRetry, Some(50));
		assert_eq!(after, Some(101));
		assert_eq!(mgr.peek(signer), Some(101));
	}

	#[test]
	fn drift_severity_escalates_with_sustained_ticks() {
		use DriftSeverity::*;
		assert_eq!(drift_severity_for_ticks(0), Normal);
		assert_eq!(drift_severity_for_ticks(1), Normal);
		assert_eq!(drift_severity_for_ticks(4), Normal);
		assert_eq!(drift_severity_for_ticks(5), Warn);
		assert_eq!(drift_severity_for_ticks(14), Warn);
		assert_eq!(drift_severity_for_ticks(15), Error);
		assert_eq!(drift_severity_for_ticks(100), Error);
	}

	mod monitor_transaction_tests {
		use super::*;

		/// Test that TransactionReceipt conversion works correctly
		#[test]
		fn test_transaction_receipt_from_alloy_receipt() {
			// This tests the From implementation used in monitor_transaction
			// The actual conversion is tested implicitly through integration tests
			// but we verify the TransactionReceipt struct has expected fields
			let receipt = TransactionReceipt {
				hash: TransactionHash(vec![0x12; 32]),
				block_number: 12345,
				success: true,
				block_timestamp: Some(1234567890),
				logs: vec![],
			};

			assert_eq!(receipt.block_number, 12345);
			assert!(receipt.success);
			assert_eq!(receipt.block_timestamp, Some(1234567890));
		}

		/// Test DeliveryError variants used in monitor_transaction
		#[test]
		fn test_delivery_error_transaction_failed() {
			let error = DeliveryError::TransactionFailed("Transaction reverted".to_string());
			assert!(matches!(error, DeliveryError::TransactionFailed(_)));
			assert!(error.to_string().contains("Transaction reverted"));
		}

		/// Test DeliveryError for timeout
		#[test]
		fn test_delivery_error_timeout() {
			let error =
				DeliveryError::TransactionFailed("Transaction monitoring timed out".to_string());
			assert!(error.to_string().contains("timed out"));
		}

		/// Test that confirmation calculation is correct
		#[test]
		fn test_confirmation_calculation() {
			// Simulates the confirmation logic in monitor_transaction
			let block_number: u64 = 100;
			let current_block: u64 = 105;
			let min_confirmations: u64 = 3;

			let confirmations = current_block.saturating_sub(block_number);
			assert_eq!(confirmations, 5);
			assert!(confirmations >= min_confirmations);

			// Test case where not enough confirmations
			let current_block_low: u64 = 101;
			let confirmations_low = current_block_low.saturating_sub(block_number);
			assert_eq!(confirmations_low, 1);
			assert!(confirmations_low < min_confirmations);
		}

		/// Test saturating subtraction for edge case
		#[test]
		fn test_confirmation_saturating_sub() {
			// Edge case: current block somehow less than tx block
			let block_number: u64 = 100;
			let current_block: u64 = 50;

			let confirmations = current_block.saturating_sub(block_number);
			assert_eq!(confirmations, 0); // Should not underflow
		}

		/// Integration test helper: create a delivery instance for testing
		async fn create_test_delivery() -> Result<AlloyDelivery, DeliveryError> {
			let networks = NetworksConfigBuilder::new()
				.add_network(1, NetworkConfigBuilder::new().build())
				.build();
			let signer = create_test_signer();
			AlloyDelivery::new(
				vec![1],
				&networks,
				HashMap::new(),
				signer,
				&test_fee_policy(),
			)
			.await
		}

		/// Test that get_provider returns correct provider for configured chain
		#[tokio::test]
		async fn test_get_provider_configured_chain() {
			let delivery = create_test_delivery().await.unwrap();
			let result = delivery.get_provider(1);
			assert!(result.is_ok());
		}

		/// Test that get_provider fails for unconfigured chain
		#[tokio::test]
		async fn test_get_provider_unconfigured_chain() {
			let delivery = create_test_delivery().await.unwrap();
			let result = delivery.get_provider(999);
			assert!(matches!(result, Err(DeliveryError::Network(_))));
			if let Err(DeliveryError::Network(msg)) = result {
				assert!(msg.contains("No provider configured for chain ID 999"));
			}
		}

		/// Test multiple networks configuration
		#[tokio::test]
		async fn test_multiple_networks() {
			let networks = NetworksConfigBuilder::new()
				.add_network(1, NetworkConfigBuilder::new().build())
				.add_network(137, NetworkConfigBuilder::new().build())
				.build();
			let signer = create_test_signer();

			let delivery = AlloyDelivery::new(
				vec![1, 137],
				&networks,
				HashMap::new(),
				signer,
				&test_fee_policy(),
			)
			.await;

			assert!(delivery.is_ok());
			let delivery = delivery.unwrap();
			assert!(delivery.providers.contains_key(&1));
			assert!(delivery.providers.contains_key(&137));
		}

		/// Test network-specific signers
		#[tokio::test]
		async fn test_network_specific_signers() {
			let networks = NetworksConfigBuilder::new()
				.add_network(1, NetworkConfigBuilder::new().build())
				.add_network(137, NetworkConfigBuilder::new().build())
				.build();

			let default_signer = create_test_signer();
			let network_signer_key: PrivateKeySigner =
				"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
					.parse()
					.unwrap();
			let network_signer = AccountSigner::Local(network_signer_key);

			let mut network_signers = HashMap::new();
			network_signers.insert(137u64, network_signer);

			let delivery = AlloyDelivery::new(
				vec![1, 137],
				&networks,
				network_signers,
				default_signer,
				&test_fee_policy(),
			)
			.await;

			assert!(delivery.is_ok());
		}

		// ====================================================================
		// poll_for_confirmation tests (Task 5 of polling-fallback plan)
		// ====================================================================

		use std::sync::Mutex as StdMutex;

		/// In-memory probe for the polling tests. Each call to `get_receipt` /
		/// `get_block_number` pops the next queued response. If a queue empties,
		/// subsequent calls return the LAST response indefinitely (so a single
		/// "stuck" value can simulate the chain not advancing).
		struct MockProbe {
			receipts: StdMutex<Vec<Result<Option<AlloyReceipt>, TransportError>>>,
			blocks: StdMutex<Vec<Result<u64, TransportError>>>,
		}

		impl MockProbe {
			fn new(
				receipts: Vec<Result<Option<AlloyReceipt>, TransportError>>,
				blocks: Vec<Result<u64, TransportError>>,
			) -> Self {
				// Reverse so we can pop from the end.
				let mut r = receipts;
				r.reverse();
				let mut b = blocks;
				b.reverse();
				Self {
					receipts: StdMutex::new(r),
					blocks: StdMutex::new(b),
				}
			}

			fn pop_or_last_receipt(&self) -> Result<Option<AlloyReceipt>, TransportError> {
				let mut q = self.receipts.lock().unwrap();
				if q.len() > 1 {
					q.pop().unwrap()
				} else if let Some(last) = q.last() {
					match last {
						Ok(Some(r)) => Ok(Some(r.clone())),
						Ok(None) => Ok(None),
						Err(_) => Err(TransportError::local_usage_str("transient")),
					}
				} else {
					Ok(None)
				}
			}

			fn pop_or_last_block(&self) -> Result<u64, TransportError> {
				let mut q = self.blocks.lock().unwrap();
				if q.len() > 1 {
					q.pop().unwrap()
				} else if let Some(last) = q.last() {
					match last {
						Ok(n) => Ok(*n),
						Err(_) => Err(TransportError::local_usage_str("transient")),
					}
				} else {
					Err(TransportError::local_usage_str("queue empty"))
				}
			}
		}

		#[async_trait]
		impl ConfirmationProbe for MockProbe {
			async fn get_receipt(
				&self,
				_tx_hash: B256,
			) -> Result<Option<AlloyReceipt>, TransportError> {
				self.pop_or_last_receipt()
			}

			async fn get_block_number(&self) -> Result<u64, TransportError> {
				self.pop_or_last_block()
			}
		}

		/// Build an `AlloyReceipt` with a chosen `status` and `block_number` for
		/// these unit tests. We construct via JSON deserialization because the
		/// public `TransactionReceipt` struct has many fields we don't care
		/// about and serde gives us defaults for free.
		fn make_receipt(success: bool, block_number: u64) -> AlloyReceipt {
			let status_hex = if success { "0x1" } else { "0x0" };
			let json = serde_json::json!({
				"transactionHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
				"transactionIndex": "0x0",
				"blockHash": "0x0000000000000000000000000000000000000000000000000000000000000002",
				"blockNumber": format!("0x{:x}", block_number),
				"from": "0x0000000000000000000000000000000000000003",
				"to": "0x0000000000000000000000000000000000000004",
				"cumulativeGasUsed": "0x0",
				"gasUsed": "0x0",
				"effectiveGasPrice": "0x0",
				"logs": [],
				"logsBloom": format!("0x{}", "0".repeat(512)),
				"status": status_hex,
				"type": "0x2",
			});
			serde_json::from_value(json).expect("AlloyReceipt fixture should deserialize")
		}

		const POLL: Duration = Duration::from_millis(10);
		const TIMEOUT_LONG: Duration = Duration::from_secs(5);
		const TIMEOUT_SHORT: Duration = Duration::from_millis(200);

		#[tokio::test]
		async fn confirms_when_receipt_appears_after_n_polls() {
			// Receipt: None, None, Some(success at block 100); blocks: 100, 100, 103.
			let probe = MockProbe::new(
				vec![
					Ok(None),
					Ok(None),
					Ok(Some(make_receipt(true, 100))),
					Ok(Some(make_receipt(true, 100))),
				],
				vec![Ok(100), Ok(100), Ok(103)],
			);
			let outcome = poll_for_confirmation(&probe, B256::ZERO, 3, TIMEOUT_LONG, POLL).await;
			assert!(
				matches!(outcome, PollOutcome::Confirmed(_)),
				"expected Confirmed, got {outcome:?}",
			);
		}

		#[tokio::test]
		async fn waits_when_receipt_exists_but_confirmations_insufficient() {
			// Receipt is mined at block 100 from the start; chain head climbs 100→103.
			let probe = MockProbe::new(
				vec![
					Ok(Some(make_receipt(true, 100))),
					Ok(Some(make_receipt(true, 100))),
					Ok(Some(make_receipt(true, 100))),
					Ok(Some(make_receipt(true, 100))),
				],
				vec![Ok(100), Ok(101), Ok(103)],
			);
			let outcome = poll_for_confirmation(&probe, B256::ZERO, 3, TIMEOUT_LONG, POLL).await;
			assert!(matches!(outcome, PollOutcome::Confirmed(_)));
		}

		#[tokio::test]
		async fn fails_immediately_on_reverted_receipt() {
			// First poll returns a reverted receipt — should NOT keep polling.
			let probe = MockProbe::new(vec![Ok(Some(make_receipt(false, 100)))], vec![Ok(100)]);
			let outcome = poll_for_confirmation(&probe, B256::ZERO, 3, TIMEOUT_LONG, POLL).await;
			assert!(matches!(outcome, PollOutcome::Reverted(_)));
		}

		#[tokio::test]
		async fn tolerates_transient_rpc_errors_then_confirms() {
			// First two receipt calls error; third sees None; fourth sees the
			// receipt. Block-number queue: error, then 99, 100, 103.
			let probe = MockProbe::new(
				vec![
					Err(TransportError::local_usage_str("transient")),
					Err(TransportError::local_usage_str("transient")),
					Ok(None),
					Ok(Some(make_receipt(true, 100))),
					Ok(Some(make_receipt(true, 100))),
				],
				vec![
					Err(TransportError::local_usage_str("transient")),
					Ok(99),
					Ok(100),
					Ok(103),
				],
			);
			let outcome = poll_for_confirmation(&probe, B256::ZERO, 3, TIMEOUT_LONG, POLL).await;
			assert!(
				matches!(outcome, PollOutcome::Confirmed(_)),
				"expected Confirmed after transient errors; got {outcome:?}",
			);
		}

		#[tokio::test]
		async fn returns_indeterminate_when_receipt_never_appears() {
			// Receipt: None forever. Blocks: 99 forever.
			// Confirmation timeout is short; expect Indeterminate within ~200ms.
			let probe = MockProbe::new(vec![Ok(None)], vec![Ok(99)]);
			let outcome = poll_for_confirmation(&probe, B256::ZERO, 3, TIMEOUT_SHORT, POLL).await;
			assert!(
				matches!(outcome, PollOutcome::Indeterminate(_)),
				"expected Indeterminate on deadline; got {outcome:?}",
			);
		}

		// Allow {outcome:?} formatting in the assertions above.
		impl std::fmt::Debug for PollOutcome {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				match self {
					PollOutcome::Confirmed(_) => write!(f, "Confirmed(<receipt>)"),
					PollOutcome::Reverted(s) => write!(f, "Reverted({s:?})"),
					PollOutcome::Indeterminate(s) => write!(f, "Indeterminate({s:?})"),
				}
			}
		}
	}

	// ========================================================================
	// Transaction Callback Tests
	// ========================================================================

	mod callback_tests {
		use super::*;
		use crate::TransactionMonitoringEvent;
		use solver_types::TransactionType;
		use std::sync::atomic::{AtomicBool, Ordering};
		use std::sync::Arc;

		/// Test that callback is invoked with Confirmed event
		#[test]
		fn test_monitoring_event_confirmed() {
			let called = Arc::new(AtomicBool::new(false));
			let called_clone = called.clone();

			let callback = Box::new(move |event: TransactionMonitoringEvent| {
				if let TransactionMonitoringEvent::Confirmed { .. } = event {
					called_clone.store(true, Ordering::SeqCst);
				}
			});

			// Simulate callback invocation
			callback(TransactionMonitoringEvent::Confirmed {
				id: "test-order".to_string(),
				tx_hash: TransactionHash(vec![0x12; 32]),
				tx_type: TransactionType::Fill,
				receipt: TransactionReceipt {
					hash: TransactionHash(vec![0x12; 32]),
					block_number: 12345,
					success: true,
					block_timestamp: Some(1234567890),
					logs: vec![],
				},
			});

			assert!(called.load(Ordering::SeqCst));
		}

		/// Test that callback is invoked with Failed event
		#[test]
		fn test_monitoring_event_failed() {
			let called = Arc::new(AtomicBool::new(false));
			let error_msg = Arc::new(std::sync::Mutex::new(String::new()));
			let called_clone = called.clone();
			let error_msg_clone = error_msg.clone();

			let callback = Box::new(move |event: TransactionMonitoringEvent| {
				if let TransactionMonitoringEvent::Failed { error, .. } = event {
					called_clone.store(true, Ordering::SeqCst);
					*error_msg_clone.lock().unwrap() = error;
				}
			});

			// Simulate callback invocation
			callback(TransactionMonitoringEvent::Failed {
				id: "test-order".to_string(),
				tx_hash: TransactionHash(vec![0x12; 32]),
				tx_type: TransactionType::PostFill,
				error: "Transaction reverted".to_string(),
			});

			assert!(called.load(Ordering::SeqCst));
			assert_eq!(*error_msg.lock().unwrap(), "Transaction reverted");
		}

		/// Test TransactionType variants used in monitoring
		#[test]
		fn test_transaction_types() {
			// Ensure all transaction types can be used in monitoring events
			let types = vec![
				TransactionType::Prepare,
				TransactionType::Fill,
				TransactionType::PostFill,
				TransactionType::PreClaim,
				TransactionType::Claim,
			];

			for tx_type in types {
				let event = TransactionMonitoringEvent::Confirmed {
					id: "test".to_string(),
					tx_hash: TransactionHash(vec![0; 32]),
					tx_type,
					receipt: TransactionReceipt {
						hash: TransactionHash(vec![0; 32]),
						block_number: 1,
						success: true,
						block_timestamp: None,
						logs: vec![],
					},
				};

				// Just verify it can be constructed
				if let TransactionMonitoringEvent::Confirmed { tx_type: t, .. } = event {
					assert!(matches!(
						t,
						TransactionType::Prepare
							| TransactionType::Fill
							| TransactionType::PostFill
							| TransactionType::PreClaim
							| TransactionType::Claim
					));
				}
			}
		}
	}

	// ========================================================================
	// Config Validation Tests
	// ========================================================================

	mod config_validation_tests {
		use super::*;

		#[test]
		fn test_config_missing_network_ids() {
			let schema = AlloyDeliverySchema;
			let config = serde_json::Value::Object(serde_json::Map::new());

			let result = schema.validate(&config);
			assert!(result.is_err());
		}

		#[test]
		fn test_config_network_ids_wrong_type() {
			let schema = AlloyDeliverySchema;
			let config = serde_json::Value::Object({
				let mut table = serde_json::Map::new();
				table.insert(
					"network_ids".to_string(),
					serde_json::Value::String("not an array".to_string()),
				);
				table
			});

			let result = schema.validate(&config);
			assert!(result.is_err());
		}

		#[test]
		fn test_config_multiple_network_ids() {
			let schema = AlloyDeliverySchema;
			// Schema validation only checks shape, not fee_policy chain
			// completeness — that's a startup invariant enforced by
			// `FeePolicyRegistry::from_config`. The single-chain
			// `schema_fee_policy_value` is therefore enough here.
			let config = serde_json::Value::Object({
				let mut table = serde_json::Map::new();
				table.insert(
					"network_ids".to_string(),
					serde_json::Value::Array(vec![
						serde_json::Value::from(1),
						serde_json::Value::from(137),
						serde_json::Value::from(42161),
					]),
				);
				table.insert("fee_policy".to_string(), schema_fee_policy_value());
				table
			});

			let result = schema.validate(&config);
			assert!(result.is_ok(), "expected ok, got {result:?}");
		}

		#[test]
		fn test_schema_validation_works() {
			let schema = AlloyDeliverySchema;

			// Valid config should pass
			let valid_config = serde_json::Value::Object({
				let mut table = serde_json::Map::new();
				table.insert(
					"network_ids".to_string(),
					serde_json::Value::Array(vec![serde_json::Value::from(1)]),
				);
				table.insert("fee_policy".to_string(), schema_fee_policy_value());
				table
			});
			assert!(
				schema.validate(&valid_config).is_ok(),
				"expected ok, got {:?}",
				schema.validate(&valid_config)
			);

			// Invalid config (empty array) should fail
			let invalid_config = serde_json::Value::Object({
				let mut table = serde_json::Map::new();
				table.insert("network_ids".to_string(), serde_json::Value::Array(vec![]));
				table.insert("fee_policy".to_string(), schema_fee_policy_value());
				table
			});
			assert!(schema.validate(&invalid_config).is_err());
		}
	}

	// ========================================================================
	// Error Handling Tests
	// ========================================================================

	mod error_handling_tests {
		use super::*;

		#[test]
		fn test_delivery_error_display() {
			let errors = vec![
				DeliveryError::Network("connection failed".to_string()),
				DeliveryError::TransactionFailed("reverted".to_string()),
				DeliveryError::NoImplementationAvailable,
			];

			for error in errors {
				// Ensure Display is implemented and doesn't panic
				let _ = format!("{error}");
			}
		}

		#[test]
		fn test_delivery_error_debug() {
			let error = DeliveryError::TransactionFailed("test error".to_string());
			// Ensure Debug is implemented
			let debug_str = format!("{error:?}");
			assert!(debug_str.contains("TransactionFailed"));
		}
	}

	// ========================================================================
	// Transaction Request Conversion Tests
	// ========================================================================

	mod transaction_conversion_tests {
		use super::*;
		use alloy_primitives::U256;

		#[test]
		fn native_gas_budget_uses_eip1559_max_fee_plus_value() {
			let tx = SolverTransaction {
				chain_id: 1,
				to: None,
				data: vec![],
				value: U256::from(10_884_382_513_223u128),
				gas_limit: Some(1_319_423),
				gas_price: None,
				max_fee_per_gas: Some(4_332_712_539),
				max_priority_fee_per_gas: Some(2_000_000_000),
				nonce: None,
			};

			let budget = native_gas_budget_wei(&tx).expect("budget should be calculable");

			assert_eq!(budget.gas_budget_wei.to_string(), "5716680576344997");
			assert_eq!(budget.required_wei.to_string(), "5727564958858220");
		}

		#[test]
		fn native_gas_budget_uses_legacy_gas_price_plus_value() {
			let tx = SolverTransaction {
				chain_id: 1,
				to: None,
				data: vec![],
				value: U256::from(1_000u64),
				gas_limit: Some(21_000),
				gas_price: Some(2_000_000_000),
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
				nonce: None,
			};

			let budget = native_gas_budget_wei(&tx).expect("budget should be calculable");

			assert_eq!(budget.required_wei.to_string(), "42000000001000");
		}

		#[test]
		fn native_gas_budget_prefers_eip1559_max_fee_over_legacy_gas_price() {
			let tx = SolverTransaction {
				chain_id: 1,
				to: None,
				data: vec![],
				value: U256::ZERO,
				gas_limit: Some(21_000),
				gas_price: Some(1_000_000_000),
				max_fee_per_gas: Some(2_000_000_000),
				max_priority_fee_per_gas: Some(1_000_000_000),
				nonce: None,
			};

			let budget = native_gas_budget_wei(&tx).expect("budget should be calculable");

			assert_eq!(budget.required_wei.to_string(), "42000000000000");
		}

		#[test]
		fn native_gas_budget_is_none_without_gas_limit_or_fee() {
			let tx = SolverTransaction {
				chain_id: 1,
				to: None,
				data: vec![],
				value: U256::ZERO,
				gas_limit: None,
				gas_price: None,
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
				nonce: None,
			};

			assert!(native_gas_budget_wei(&tx).is_none());
		}

		#[test]
		fn insufficient_native_gas_shortfall_is_calculated_before_submit() {
			let balance = U256::from(2_049_950_990_035_729u128);
			let required = U256::from(5_727_564_958_858_220u128);

			let shortfall = native_gas_shortfall(balance, required);

			assert_eq!(shortfall.unwrap().to_string(), "3677613968822491");
		}

		/// Test Transaction to TransactionRequest conversion
		#[test]
		fn test_transaction_to_request_basic() {
			let tx = SolverTransaction {
				to: Some(solver_types::Address(vec![0x12; 20])),
				data: vec![0xab, 0xcd],
				value: U256::from(1000u64),
				chain_id: 1,
				nonce: Some(5),
				gas_limit: Some(21000),
				gas_price: None,
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
			};

			let request: TransactionRequest = tx.into();
			assert!(request.to.is_some());
			assert_eq!(request.nonce, Some(5));
			assert_eq!(request.gas, Some(21000));
		}

		/// Test Transaction with EIP-1559 gas parameters
		#[test]
		fn test_transaction_eip1559() {
			let tx = SolverTransaction {
				to: Some(solver_types::Address(vec![0x12; 20])),
				data: vec![],
				value: U256::from(0u64),
				chain_id: 1,
				nonce: None,
				gas_limit: Some(100000),
				gas_price: None,
				max_fee_per_gas: Some(50_000_000_000),         // 50 gwei
				max_priority_fee_per_gas: Some(2_000_000_000), // 2 gwei
			};

			let request: TransactionRequest = tx.into();
			assert_eq!(request.max_fee_per_gas, Some(50_000_000_000));
			assert_eq!(request.max_priority_fee_per_gas, Some(2_000_000_000));
		}

		/// Test Transaction with legacy gas price
		#[test]
		fn test_transaction_legacy_gas() {
			let tx = SolverTransaction {
				to: Some(solver_types::Address(vec![0x12; 20])),
				data: vec![],
				value: U256::from(0u64),
				chain_id: 1,
				nonce: None,
				gas_limit: Some(21000),
				gas_price: Some(20_000_000_000), // 20 gwei
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
			};

			let request: TransactionRequest = tx.into();
			assert_eq!(request.gas_price, Some(20_000_000_000));
		}

		/// Test Transaction for contract deployment (no 'to' address)
		#[test]
		fn test_transaction_contract_deployment() {
			let tx = SolverTransaction {
				to: None,                           // Contract creation
				data: vec![0x60, 0x80, 0x60, 0x40], // Some bytecode
				value: U256::from(0u64),
				chain_id: 1,
				nonce: Some(0),
				gas_limit: Some(1000000),
				gas_price: None,
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
			};

			let request: TransactionRequest = tx.into();
			assert!(request.to.is_none());
		}
	}

	// ========================================================================
	// TransactionHash Tests
	// ========================================================================

	mod transaction_hash_tests {
		use super::*;

		#[test]
		fn test_transaction_hash_clone() {
			let hash = TransactionHash(vec![0x12; 32]);
			let cloned = hash.clone();
			assert_eq!(hash.0, cloned.0);
		}

		#[test]
		fn test_transaction_hash_partial_eq() {
			let hash1 = TransactionHash(vec![0x12; 32]);
			let hash2 = TransactionHash(vec![0x12; 32]);
			let hash3 = TransactionHash(vec![0x34; 32]);

			assert_eq!(hash1, hash2);
			assert_ne!(hash1, hash3);
		}
	}

	// ========================================================================
	// TrackingConfig Tests
	// ========================================================================

	mod tracking_config_tests {
		use crate::{TransactionTracking, TransactionTrackingWithConfig};
		use solver_types::TransactionType;

		#[test]
		fn test_tracking_with_config_creation() {
			let callback = Box::new(|_: crate::TransactionMonitoringEvent| {});

			let tracking = TransactionTracking {
				id: "test-order-123".to_string(),
				tx_type: TransactionType::Fill,
				callback,
			};

			let config = TransactionTrackingWithConfig {
				tracking,
				min_confirmations: 3,
				monitoring_timeout_seconds: 300,
				tx_confirmation_timeout_seconds: 600,
			};

			assert_eq!(config.min_confirmations, 3);
			assert_eq!(config.monitoring_timeout_seconds, 300);
			assert_eq!(config.tx_confirmation_timeout_seconds, 600);
			assert_eq!(config.tracking.id, "test-order-123");
		}

		#[test]
		fn test_tracking_different_tx_types() {
			let tx_types = vec![
				TransactionType::Prepare,
				TransactionType::Fill,
				TransactionType::PostFill,
				TransactionType::PreClaim,
				TransactionType::Claim,
			];

			for tx_type in tx_types {
				let callback = Box::new(|_: crate::TransactionMonitoringEvent| {});
				let tracking = TransactionTracking {
					id: format!("order-{tx_type:?}"),
					tx_type,
					callback,
				};

				// Verify each type can be used in tracking
				assert!(!tracking.id.is_empty());
			}
		}
	}
}
