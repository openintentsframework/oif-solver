//! End-to-end test harness for the OIF solver.
//!
//! Lifecycle: spawn two Anvil processes → deploy MockERC20s, AlwaysYesOracle,
//! InputSettlerEscrow, and OutputSettlerSimple on each chain → write a typed
//! `SeedOverrides` bootstrap config → spawn the `solver` binary → expose
//! deployed addresses and signers to the test.
//!
//! Design choices are documented in `crates/solver-e2e-tests/README.md`.

use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_types::{BlockNumberOrTag, Filter, Log, TransactionReceipt, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolEvent, SolValue};
use anyhow::{anyhow, Context as _, Result};
use solver_core::state::{transaction_attempt::TransactionAttemptStore, OrderStateMachine};
use solver_storage::{
	implementations::file::{FileStorage, TtlConfig as FileTtlConfig},
	StorageService,
};
use std::{
	collections::HashMap,
	path::PathBuf,
	process::{Child, Command, Stdio},
	str::FromStr,
	sync::{Arc, OnceLock},
	time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio::sync::{Mutex, MutexGuard};

/// Serializes harness instances within a process. The harness uses fixed
/// ports (Anvil 8545/8546, solver API 3000), so concurrent boots collide.
/// Held for the lifetime of `Harness` and released on Drop.
fn harness_lock() -> &'static Mutex<()> {
	static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
	LOCK.get_or_init(|| Mutex::new(()))
}

// =============================================================================
// Public sol! types
//
// Order, output, and event types come from solver-types' canonical
// `eip7683::interfaces` module. Re-exported here under the names existing
// e2e callers use (`MandateOutput`, `IInputSettlerEscrow`). Test-only
// contract bindings (`IERC20`, `IMailboxMock`) stay local.
// =============================================================================

pub use solver_types::standards::eip7683::interfaces::{
	Finalised, IInputSettlerEscrow, Open, OutputFilled, Refunded,
	SolMandateOutput as MandateOutput, SolveParams, StandardOrder,
};

sol! {
	#[sol(rpc)]
	contract IERC20 {
		function mint(address to, uint256 value) external;
		function approve(address spender, uint256 value) external returns (bool);
		function balanceOf(address account) external view returns (uint256);
	}

	/// Read-only view onto `MockMailboxV2.dispatchCounter`. Bumps once per
	/// successful `dispatch(...)` call from `HyperlaneOracle.submit()`.
	#[sol(rpc)]
	contract IMailboxMock {
		function dispatchCounter() external view returns (uint256);
	}

	#[sol(rpc)]
	contract ITheCompactE2e {
		function DOMAIN_SEPARATOR() external view returns (bytes32);
		function __registerAllocator(address allocator, bytes calldata proof) external;
		function depositERC20(address token, bytes12 lockTag, uint256 amount, address recipient) external returns (uint256);
	}
}

/// Test-only ABI wrappers. `IOutputSettlerSimple` in solver-types lacks
/// `#[sol(rpc)]` so the typed contract wrapper isn't generated; we declare an
/// rpc-tagged copy here. `InputSettlerEscrow.refund(...)` is missing from the
/// production binding entirely; we add a minimal rpc-tagged interface for it.
///
/// `sol!` only resolves struct names within its own block, so we redeclare
/// `SolMandateOutput` and `StandardOrder` here with the SAME layout as
/// solver-types (verify against `solver-types/src/standards/eip7683.rs:305`).
/// Tests convert between layouts via ABI roundtrip
/// (`solver_types_value.abi_encode()` -> `ext_bindings::Type::abi_decode(&bytes, true)`).
pub mod ext_bindings {
	use alloy_sol_types::sol;

	sol! {
		#[derive(Debug)]
		struct SolMandateOutput {
			bytes32 oracle;
			bytes32 settler;
			uint256 chainId;
			bytes32 token;
			uint256 amount;
			bytes32 recipient;
			bytes callbackData;
			bytes context;
		}

		#[derive(Debug)]
		struct StandardOrder {
			address user;
			uint256 nonce;
			uint256 originChainId;
			uint32 expires;
			uint32 fillDeadline;
			address inputOracle;
			uint256[2][] inputs;
			SolMandateOutput[] outputs;
		}

		#[sol(rpc)]
		interface IOutputSettlerSimpleRpc {
			function fill(
				bytes32 orderId,
				SolMandateOutput calldata output,
				uint48 fillDeadline,
				bytes calldata fillerData
			) external returns (bytes32);
		}

		#[sol(rpc)]
		interface IInputSettlerEscrowRefund {
			function refund(StandardOrder calldata order) external;
		}
	}
}

// =============================================================================
// Anvil dev accounts (deterministic across all anvil instances)
// =============================================================================

/// Anvil's first dev account. Used as the solver signer because solver-config's
/// `local` account default expects this private key (see `config/demo.json`).
pub const SOLVER_PRIVATE_KEY: &str =
	"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub const SOLVER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// Anvil's second dev account. The "user" who signs the open() transaction.
pub const USER_PRIVATE_KEY: &str =
	"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
pub const USER_ADDRESS: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

/// Anvil's third dev account. Receives the output token on the destination chain.
pub const RECIPIENT_ADDRESS: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

pub const E2E_SOLVER_ID: &str = "oif-solver-e2e";

/// Canonical Permit2 deployment address — same on every EVM chain. The
/// `InputSettlerEscrow` hardcodes this address when handling Permit2-flavored
/// `openFor` calls, so the harness must plant Permit2's runtime bytecode
/// here (via `anvil_setCode`) when `HarnessOptions::enable_permit2` is set.
pub const PERMIT2_ADDRESS: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

// Re-exports so test files can build EIP-712 payloads + POST `/api/v1/orders`
// without each one taking a direct `solver-types` dependency.
pub use solver_types::api::{
	OifOrder, OrderPayload, PostOrderRequest, PostOrderResponse, PostOrderResponseStatus,
	SignatureType,
};
pub use solver_types::utils::eip712::{reconstruct_eip3009_digest, reconstruct_permit2_digest};
pub use solver_types::InteropAddress;

// =============================================================================
// Chain layout — hardcoded to match config/demo.json conventions
// =============================================================================

pub const ORIGIN_CHAIN_ID: u64 = 31337;
pub const ORIGIN_RPC_PORT: u16 = 8545;
pub const DEST_CHAIN_ID: u64 = 31338;
pub const DEST_RPC_PORT: u16 = 8546;
pub const SOLVER_API_PORT: u16 = 3000;

const SOLVER_HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
const ANVIL_HEALTH_TIMEOUT: Duration = Duration::from_secs(15);

/// Default budget for the destination-chain `OutputFilled` event after
/// submitting an order. Matches direct + Permit2 + EIP-3009 happy paths.
pub const FILL_TIMEOUT: Duration = Duration::from_secs(60);

/// Default budget for the origin-chain `Finalised` event after `OutputFilled`.
/// Hyperlane settlement may need more — that test defines its own.
pub const SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Budget for `await_no_event` calls — long enough for the solver to have
/// definitely tried and failed, short enough that a passing test stays fast.
pub const NO_EVENT_TIMEOUT: Duration = Duration::from_secs(15);

// =============================================================================
// Public Harness
// =============================================================================

/// Per-chain on-chain footprint deployed by the harness.
#[derive(Debug, Clone)]
pub struct ChainDeployment {
	pub chain_id: u64,
	pub rpc_http: String,
	pub token_a: Address,
	pub token_b: Address,
	pub input_oracle: Address,
	pub output_oracle: Address,
	pub input_settler: Address,
	pub output_settler: Address,
	pub input_settler_compact: Option<Address>,
	pub the_compact: Option<Address>,
	pub allocator: Option<Address>,
	/// `MockMailboxV2` address when `HarnessOptions::use_hyperlane_settlement`
	/// is set. `None` for the default `Direct`-settlement layout.
	/// Tests can read its `dispatchCounter` to assert the solver actually
	/// called `HyperlaneOracle.submit()` during PostFill.
	pub mock_mailbox: Option<Address>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompactResetPeriod {
	OneSecond = 0,
	OneDay = 5,
}

pub fn compact_lock_tag_for_allocator(
	allocator: Address,
	reset_period: CompactResetPeriod,
) -> FixedBytes<12> {
	let mut lock_tag = [0u8; 12];
	lock_tag[0] = ((reset_period as u8) << 4) | compact_allocator_flag(allocator);
	lock_tag[1..].copy_from_slice(&allocator.as_slice()[9..]);
	FixedBytes::from(lock_tag)
}

fn compact_allocator_flag(allocator: Address) -> u8 {
	let leading_zero_nibbles = allocator
		.as_slice()
		.iter()
		.take(9)
		.flat_map(|byte| [byte >> 4, byte & 0x0f])
		.take_while(|nibble| *nibble == 0)
		.count();

	match leading_zero_nibbles {
		0..=3 => 0,
		4..=17 => (leading_zero_nibbles - 3) as u8,
		_ => 15,
	}
}

/// Owns every resource the test needs. Drop tears everything down in reverse.
pub struct Harness {
	pub origin: ChainDeployment,
	pub destination: ChainDeployment,

	pub origin_provider: DynProvider,
	pub destination_provider: DynProvider,

	pub user_signer: PrivateKeySigner,

	anvils: Vec<Child>,
	solver: Option<Child>,
	solver_stderr_path: PathBuf,
	bootstrap_path: PathBuf,
	options: HarnessOptions,
	_tempdir: TempDir,
	/// Held to serialize concurrent `Harness` constructions in the same
	/// process. Released when the guard is dropped (via the `Drop` impl).
	_lock: MutexGuard<'static, ()>,
}

#[derive(Debug, Clone)]
pub struct HarnessOptions {
	pub user_token_a_mint: U256,
	pub solver_token_b_mint: U256,
	pub use_false_oracle: bool,
	pub use_reverting_output_settler: bool,
	pub enable_admin_api: bool,
	pub admin_redis_url: Option<String>,
	/// Switch settlement type from `Direct` (default) to `Hyperlane`. When set,
	/// the harness deploys `MockMailboxV2` on both chains plus a real
	/// `HyperlaneOracle` on the destination, and the solver's PostFill step
	/// dispatches a `submit()` call against that oracle. Tests can read the
	/// destination's `MockMailboxV2.dispatchCounter` (via
	/// `Harness::destination_mailbox_dispatch_count`) to assert the call
	/// actually happened.
	pub use_hyperlane_settlement: bool,
	/// Plant the canonical Permit2 contract on the origin chain via
	/// `anvil_setCode` and have the user pre-approve Permit2 for unlimited
	/// TOKA spending. Required for any test that submits Permit2-signed
	/// orders through the off-chain HTTP API (`OifOrder::OifEscrowV0`).
	pub enable_permit2: bool,
	/// Deploy TheCompact, InputSettlerCompact, and SimpleAllocator on the origin
	/// chain, register the allocator, and write those addresses into the solver
	/// bootstrap config. Used by ResourceLock/Compact e2e scenarios.
	pub enable_compact_simple_allocator: bool,
	/// Addresses (`"0x..."` strings, any case) to write into a deny list
	/// JSON file in the harness's tempdir. The harness sets
	/// `SeedOverrides.deny_list` to that file's path so the solver loads it
	/// at startup. None / empty = feature off.
	///
	/// Mirrors the on-disk file format the solver expects (`Vec<String>`).
	/// The list is matched against `order.user` and every output recipient,
	/// case-insensitively. See PR #308 / `IntentHandler::load_deny_list`.
	pub deny_list_addresses: Option<Vec<String>>,
	/// When false, `boot_with` skips the entire solver-service path:
	/// `ensure_solver_binary_built()`, `spawn_solver(...)`, and the following
	/// `wait_for_tcp_ready(SOLVER_API_PORT, ...)` health check. Direct-call
	/// tests (chain-aware recovery, custom event drivers) set this to false so
	/// the solver loop doesn't race with manually emitted events — and so the
	/// test doesn't trigger a `cargo build -p solver-service --bin solver` it
	/// doesn't need. Defaults to true.
	pub run_solver: bool,
	/// Optional transaction bumping configuration for tests that need the
	/// sweeper enabled. Passed through to `SeedOverrides` unchanged.
	pub tx_bump: Option<solver_types::OperatorTxBumpConfig>,
	/// Optional existing broadcaster default finality depth to carry into
	/// discovery config even when the active settlement priority is direct or
	/// Hyperlane.
	pub broadcaster_default_finality_blocks: Option<u64>,
}

async fn read_order_from_storage_root(
	root: &std::path::Path,
	order_id: &str,
) -> Result<solver_types::Order> {
	use solver_storage::{
		implementations::file::{FileStorage, TtlConfig},
		StorageService,
	};

	let storage_root = root.join("data/storage").join(E2E_SOLVER_ID);
	let storage = StorageService::new(Box::new(FileStorage::new(
		storage_root,
		TtlConfig::default(),
	)));
	storage
		.retrieve(solver_types::StorageKey::Orders.as_str(), order_id)
		.await
		.with_context(|| format!("read order {order_id} from file storage"))
}

async fn scan_attempt_files(
	storage_root: &std::path::Path,
	storage: Arc<StorageService>,
	order_id: &str,
	alternate_order_id: &str,
) -> Result<Vec<solver_types::TransactionAttempt>> {
	let entries = match std::fs::read_dir(storage_root) {
		Ok(entries) => entries,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
		Err(e) => return Err(e).with_context(|| format!("scan {}", storage_root.display())),
	};

	let mut attempts = Vec::new();
	for entry in entries {
		let entry = entry.with_context(|| format!("read entry in {}", storage_root.display()))?;
		let file_name = entry.file_name();
		let Some(file_name) = file_name.to_str() else {
			continue;
		};
		let Some(id) = file_name
			.strip_prefix("transaction_attempts_")
			.and_then(|name| name.strip_suffix(".bin"))
		else {
			continue;
		};
		let attempt = storage
			.retrieve::<solver_types::TransactionAttempt>(
				solver_types::StorageKey::TransactionAttempts.as_str(),
				id,
			)
			.await
			.with_context(|| format!("read transaction attempt {id}"))?;
		attempts.push(attempt);
	}

	Ok(attempts
		.into_iter()
		.filter(|attempt| {
			matches!(
				attempt.order_id(),
				Some(attempt_order_id)
					if attempt_order_id == order_id || attempt_order_id == alternate_order_id
			)
		})
		.collect())
}

fn log_file_contains(path: &std::path::Path, needle: &str) -> Result<bool> {
	let contents = std::fs::read_to_string(path)
		.with_context(|| format!("read solver log {}", path.display()))?;
	Ok(contents.contains(needle) || strip_ansi_codes(&contents).contains(needle))
}

fn strip_ansi_codes(input: &str) -> String {
	let mut output = String::with_capacity(input.len());
	let mut chars = input.chars().peekable();

	while let Some(ch) = chars.next() {
		if ch == '\u{1b}' && chars.peek() == Some(&'[') {
			chars.next();
			for next in chars.by_ref() {
				if next.is_ascii_alphabetic() {
					break;
				}
			}
			continue;
		}
		output.push(ch);
	}

	output
}

impl Default for HarnessOptions {
	fn default() -> Self {
		Self {
			user_token_a_mint: amount_with_decimals(1_000_000),
			solver_token_b_mint: amount_with_decimals(1_000_000),
			use_false_oracle: false,
			use_reverting_output_settler: false,
			enable_admin_api: false,
			admin_redis_url: None,
			use_hyperlane_settlement: false,
			enable_permit2: false,
			enable_compact_simple_allocator: false,
			deny_list_addresses: None,
			run_solver: true,
			tx_bump: None,
			broadcaster_default_finality_blocks: None,
		}
	}
}

impl Harness {
	pub async fn boot() -> Result<Self> {
		Self::boot_with(HarnessOptions::default()).await
	}

	pub async fn boot_with(options: HarnessOptions) -> Result<Self> {
		init_tracing();

		let lock_guard = harness_lock().lock().await;

		// solver-demo's AnvilManager `mem::forget`s child handles, so previous
		// crashed runs may have left listeners on our fixed ports.
		kill_listeners_on_ports(&[ORIGIN_RPC_PORT, DEST_RPC_PORT, SOLVER_API_PORT]);

		let tempdir = TempDir::new().context("create tempdir")?;
		if options.run_solver {
			ensure_solver_binary_built()?;
		}

		let anvils = vec![
			spawn_anvil(ORIGIN_CHAIN_ID, ORIGIN_RPC_PORT)?,
			spawn_anvil(DEST_CHAIN_ID, DEST_RPC_PORT)?,
		];

		let origin_rpc = format!("http://127.0.0.1:{ORIGIN_RPC_PORT}");
		let dest_rpc = format!("http://127.0.0.1:{DEST_RPC_PORT}");
		wait_for_rpc_ready(&origin_rpc, ANVIL_HEALTH_TIMEOUT).await?;
		wait_for_rpc_ready(&dest_rpc, ANVIL_HEALTH_TIMEOUT).await?;

		let solver_signer = parse_signer(SOLVER_PRIVATE_KEY)?;
		let user_signer = parse_signer(USER_PRIVATE_KEY)?;

		// One provider per chain, signed by the SOLVER key. We use this for
		// deploys, mints, and any other "test driver" txs. The user-side
		// open() call is signed separately with the user key.
		let origin_provider = build_provider(&origin_rpc, solver_signer.clone()).await?;
		let destination_provider = build_provider(&dest_rpc, solver_signer.clone()).await?;

		// Deploy contracts on each chain in dependency-free order. AlwaysYes
		// oracle is reused for both input + output roles since it always
		// returns proven=true and has no per-direction state.
		tracing::info!("Deploying contracts to origin chain {ORIGIN_CHAIN_ID}");
		let mut origin = deploy_chain(&origin_provider, ORIGIN_CHAIN_ID, &origin_rpc).await?;
		tracing::info!("Deploying contracts to destination chain {DEST_CHAIN_ID}");
		let mut destination = deploy_chain(&destination_provider, DEST_CHAIN_ID, &dest_rpc).await?;

		if options.use_false_oracle {
			origin.input_oracle = deploy_no_args(&origin_provider, "FalseOracle")
				.await
				.context("deploy FalseOracle")?;
		}
		if options.use_reverting_output_settler {
			destination.output_settler =
				deploy_no_args(&destination_provider, "RevertingOutputSettler")
					.await
					.context("deploy RevertingOutputSettler")?;
		}

		// Hyperlane settlement scenario: deploy a mock mailbox on each chain
		// (validate_seedless_settlement_requirements demands a mailbox entry
		// per chain, even chains we never dispatch from), and a real
		// HyperlaneOracle on the destination using its mailbox. The
		// HyperlaneOracle replaces AlwaysYesOracle in the destination's
		// output-oracle role so the solver's PostFill `submit()` call lands
		// somewhere with the right interface. The origin-chain output role
		// stays AlwaysYesOracle (unexercised; only required by validation).
		if options.use_hyperlane_settlement {
			origin.mock_mailbox = Some(
				deploy_mock_mailbox_v2(&origin_provider)
					.await
					.context("deploy MockMailboxV2 (origin)")?,
			);
			let dest_mailbox = deploy_mock_mailbox_v2(&destination_provider)
				.await
				.context("deploy MockMailboxV2 (destination)")?;
			destination.mock_mailbox = Some(dest_mailbox);
			destination.output_oracle =
				deploy_hyperlane_oracle(&destination_provider, dest_mailbox)
					.await
					.context("deploy HyperlaneOracle (destination)")?;
		}

		// Permit2 scenario: plant the canonical Permit2 runtime bytecode on
		// the origin chain. The InputSettlerEscrow hardcodes the canonical
		// address, so we must `anvil_setCode` there. The user-side ERC20
		// `approve(Permit2, MAX)` happens after the TOKA mint below — needs
		// the user to actually have a positive balance first.
		if options.enable_permit2 {
			install_permit2_at_canonical(&origin_provider)
				.await
				.context("install Permit2 (origin)")?;
		}

		if options.enable_compact_simple_allocator {
			let (the_compact, input_settler_compact, allocator) =
				deploy_compact_stack(&origin_provider, parse_address(SOLVER_ADDRESS)?)
					.await
					.context("deploy Compact stack (origin)")?;
			origin.the_compact = Some(the_compact);
			origin.input_settler_compact = Some(input_settler_compact);
			origin.allocator = Some(allocator);
		}

		// Mint TOKA to user on origin (for the input leg) and TOKB to solver
		// on destination (for the fill leg). Solver self-funds the fill —
		// they bring their own inventory, exactly like production.
		mint_erc20(
			&origin_provider,
			origin.token_a,
			parse_address(USER_ADDRESS)?,
			options.user_token_a_mint,
		)
		.await
		.context("mint TOKA to user")?;
		mint_erc20(
			&destination_provider,
			destination.token_b,
			parse_address(SOLVER_ADDRESS)?,
			options.solver_token_b_mint,
		)
		.await
		.context("mint TOKB to solver")?;

		// User-side ERC20 approve to Permit2 for unlimited TOKA spending.
		// Permit2-signed orders authorize InputSettlerEscrow to invoke
		// `Permit2.permitWitnessTransferFrom` on the user's behalf — that
		// internal call needs an upstream allowance from the user to Permit2.
		// One-time per (user, token), MAX value.
		if options.enable_permit2 {
			user_approve_max(
				&origin_rpc,
				&user_signer,
				origin.token_a,
				parse_address(PERMIT2_ADDRESS)?,
			)
			.await
			.context("user approve(Permit2, MAX) on TOKA")?;
		}

		// Materialize the deny list file when configured. The solver loads
		// this at startup via `IntentHandler::load_deny_list` and matches
		// against `order.user` and every output recipient. We write into the
		// per-test tempdir so the file is auto-cleaned with the rest of the
		// test state.
		let deny_list_path = if let Some(addrs) = &options.deny_list_addresses {
			let path = tempdir.path().join("deny_list.json");
			std::fs::write(
				&path,
				serde_json::to_vec_pretty(addrs).context("serialize deny list")?,
			)
			.context("write deny list file")?;
			Some(path.to_string_lossy().into_owned())
		} else {
			None
		};

		// Write the bootstrap config. SeedOverrides shape — see notes at
		// build_seed_overrides for why this is what `solver --bootstrap-config`
		// expects (vs. the runtime Config schema in demo.json).
		let seed_overrides = build_seed_overrides(&origin, &destination, &options, deny_list_path)?;
		let bootstrap_path = tempdir.path().join("bootstrap.json");
		std::fs::write(
			&bootstrap_path,
			serde_json::to_vec_pretty(&seed_overrides).context("serialize SeedOverrides")?,
		)
		.context("write bootstrap config")?;

		// Capture solver stderr to a file so we can dump it on failure
		// regardless of how cargo test buffers its own stderr.
		let solver_stderr_path = tempdir.path().join("solver.stderr.log");
		let solver = if options.run_solver {
			let child = spawn_solver(
				&bootstrap_path,
				tempdir.path(),
				&solver_stderr_path,
				&options,
			)?;
			wait_for_tcp_ready(SOLVER_API_PORT, SOLVER_HEALTH_TIMEOUT).await?;
			Some(child)
		} else {
			None
		};

		Ok(Self {
			origin,
			destination,
			origin_provider,
			destination_provider,
			user_signer,
			anvils,
			solver,
			solver_stderr_path,
			bootstrap_path,
			options,
			_tempdir: tempdir,
			_lock: lock_guard,
		})
	}

	/// Print the solver subprocess's combined stdout+stderr (last ~300 lines)
	/// to test stderr. Called automatically on `await_event` timeout; tests
	/// can also call it manually.
	pub fn dump_solver_stderr(&self) {
		eprintln!(
			"\n========== solver logs ({}) ==========",
			self.solver_stderr_path.display()
		);
		match std::fs::read_to_string(&self.solver_stderr_path) {
			Ok(contents) => {
				let lines: Vec<&str> = contents.lines().collect();
				let start = lines.len().saturating_sub(300);
				for line in &lines[start..] {
					eprintln!("{line}");
				}
			},
			Err(e) => eprintln!("(could not read log file: {e})"),
		}
		eprintln!("========== end solver logs ==========\n");
	}

	/// Read an order directly from the solver subprocess file-storage root.
	///
	/// The solver child is spawned with `STORAGE_PATH=<harness-tempdir>/data/storage`,
	/// so this helper can assert subprocess outcomes without EventBus access.
	pub async fn read_order_from_storage(&self, order_id: &str) -> Result<solver_types::Order> {
		read_order_from_storage_root(self._tempdir.path(), order_id).await
	}

	/// Return true if the captured solver stdout/stderr log contains `needle`.
	pub fn solver_log_contains(&self, needle: &str) -> Result<bool> {
		log_file_contains(&self.solver_stderr_path, needle)
	}

	/// Print the bootstrap config that was passed to the solver. Useful when
	/// diagnosing config-driven discovery / settlement issues.
	pub fn dump_bootstrap_config(&self) {
		eprintln!(
			"\n========== bootstrap config ({}) ==========",
			self.bootstrap_path.display()
		);
		match std::fs::read_to_string(&self.bootstrap_path) {
			Ok(s) => eprintln!("{s}"),
			Err(e) => eprintln!("(could not read: {e})"),
		}
		eprintln!("========== end bootstrap config ==========\n");
	}

	pub fn solver_address(&self) -> Address {
		parse_address(SOLVER_ADDRESS).expect("static address")
	}

	pub fn user_address(&self) -> Address {
		parse_address(USER_ADDRESS).expect("static address")
	}

	pub fn recipient_address(&self) -> Address {
		parse_address(RECIPIENT_ADDRESS).expect("static address")
	}

	pub fn api_base_url(&self) -> String {
		format!("http://127.0.0.1:{SOLVER_API_PORT}/api/v1")
	}

	fn loopback_http_client() -> Result<reqwest::Client> {
		reqwest::Client::builder()
			.no_proxy()
			.timeout(Duration::from_secs(15))
			.build()
			.context("build loopback HTTP client")
	}

	/// Compute the on-chain orderId for a `StandardOrder` by calling the
	/// origin input settler's `orderIdentifier(order)` view. Off-chain
	/// submission tests need this *before* the `Open` event fires so we can
	/// build a log filter — the HTTP API's response may or may not echo the
	/// orderId synchronously, and even when it does, computing it locally
	/// gives a deterministic value to assert against.
	pub async fn compute_order_id(&self, order: StandardOrder) -> Result<B256> {
		let contract = IInputSettlerEscrow::new(self.origin.input_settler, &self.origin_provider);
		contract
			.orderIdentifier(order)
			.call()
			.await
			.context("orderIdentifier view call")
	}

	/// POST a signed off-chain order to `/api/v1/orders`. Returns the
	/// `PostOrderResponse` for inspection (status, optional orderId).
	pub async fn submit_post_order(&self, request: &PostOrderRequest) -> Result<PostOrderResponse> {
		let url = format!("{}/orders", self.api_base_url());
		let resp = Self::loopback_http_client()?
			.post(&url)
			.json(request)
			.send()
			.await
			.context("POST /orders")?;
		let status = resp.status();
		let body = resp.bytes().await.context("read /orders response body")?;
		if !status.is_success() {
			return Err(anyhow!(
				"POST /orders status {status}, body: {}",
				String::from_utf8_lossy(&body)
			));
		}
		serde_json::from_slice::<PostOrderResponse>(&body).with_context(|| {
			format!(
				"decode PostOrderResponse from {} bytes (status {status})",
				body.len()
			)
		})
	}

	pub fn compact_lock_tag(&self) -> Result<FixedBytes<12>> {
		self.compact_lock_tag_with_reset_period(CompactResetPeriod::OneDay)
	}

	pub fn compact_lock_tag_with_reset_period(
		&self,
		reset_period: CompactResetPeriod,
	) -> Result<FixedBytes<12>> {
		let allocator = self
			.origin
			.allocator
			.ok_or_else(|| anyhow!("Compact allocator not deployed"))?;
		Ok(compact_lock_tag_for_allocator(allocator, reset_period))
	}

	pub fn compact_token_id(&self) -> Result<U256> {
		let lock_tag = self.compact_lock_tag()?;
		let mut bytes = [0u8; 32];
		bytes[..12].copy_from_slice(lock_tag.as_slice());
		bytes[12..].copy_from_slice(self.origin.token_a.as_slice());
		Ok(U256::from_be_bytes(bytes))
	}

	pub async fn compact_deposit_user_token_a(&self, amount: U256) -> Result<U256> {
		self.compact_deposit_user_token_a_with_reset_period(amount, CompactResetPeriod::OneDay)
			.await
	}

	pub async fn compact_deposit_user_token_a_with_reset_period(
		&self,
		amount: U256,
		reset_period: CompactResetPeriod,
	) -> Result<U256> {
		let the_compact = self
			.origin
			.the_compact
			.ok_or_else(|| anyhow!("TheCompact not deployed"))?;
		let lock_tag = self.compact_lock_tag_with_reset_period(reset_period)?;
		user_approve_max(
			&self.origin.rpc_http,
			&self.user_signer,
			self.origin.token_a,
			the_compact,
		)
		.await
		.context("user approve(TheCompact, MAX) on TOKA")?;

		let user_provider = build_provider(&self.origin.rpc_http, self.user_signer.clone()).await?;
		let pending = ITheCompactE2e::new(the_compact, user_provider)
			.depositERC20(self.origin.token_a, lock_tag, amount, self.user_address())
			.send()
			.await
			.context("send TheCompact.depositERC20")?;
		let receipt = pending
			.get_receipt()
			.await
			.context("depositERC20 receipt")?;
		if !receipt.status() {
			return Err(anyhow!(
				"depositERC20 reverted (tx {:?})",
				receipt.transaction_hash
			));
		}

		self.compact_token_id()
	}

	pub async fn compact_domain_separator(&self) -> Result<B256> {
		let the_compact = self
			.origin
			.the_compact
			.ok_or_else(|| anyhow!("TheCompact not deployed"))?;
		ITheCompactE2e::new(the_compact, &self.origin_provider)
			.DOMAIN_SEPARATOR()
			.call()
			.await
			.context("TheCompact.DOMAIN_SEPARATOR")
	}

	/// Read the destination chain's `MockMailboxV2.dispatchCounter`. Returns
	/// `Ok(0)` if no mock mailbox was deployed (Direct settlement, the
	/// default). A counter > 0 after a flow finishes is durable proof that
	/// the solver actually called `HyperlaneOracle.submit()` during PostFill
	/// — there's no oracle-local event we could correlate to the orderId, so
	/// this is the cleanest assertion.
	pub async fn destination_mailbox_dispatch_count(&self) -> Result<U256> {
		let Some(addr) = self.destination.mock_mailbox else {
			return Ok(U256::ZERO);
		};
		let contract = IMailboxMock::new(addr, &self.destination_provider);
		let count = contract
			.dispatchCounter()
			.call()
			.await
			.context("read MockMailboxV2.dispatchCounter")?;
		Ok(count)
	}

	/// Override an account's native (ETH) balance on the given chain via
	/// `anvil_setBalance`. Used by failure tests that need to starve the
	/// solver of gas after the harness's bootstrap approvals have run.
	///
	/// Anvil dev chains expose this RPC; mainnet/testnet providers don't —
	/// don't call this against anything else.
	pub async fn set_native_balance(
		&self,
		chain_id: u64,
		account: Address,
		wei: U256,
	) -> Result<()> {
		let provider = self.provider_for(chain_id)?;
		provider
			.client()
			.request::<_, ()>("anvil_setBalance", (account, wei))
			.await
			.with_context(|| format!("anvil_setBalance({account}, {wei}) on chain {chain_id}"))?;
		Ok(())
	}

	/// Enable or disable Anvil automining on one harness chain.
	pub async fn set_automine(&self, chain_id: u64, enabled: bool) -> Result<()> {
		let provider = self.provider_for(chain_id)?;
		provider
			.client()
			.request::<_, serde_json::Value>("evm_setAutomine", (enabled,))
			.await
			.with_context(|| format!("evm_setAutomine({enabled}) on chain {chain_id}"))?;
		Ok(())
	}

	/// Set Anvil interval mining in seconds on one harness chain.
	///
	/// The harness starts Anvil with `--block-time 1`; disabling automine alone
	/// does not keep transactions pending because interval mining can still
	/// produce blocks. Use `0` with `set_automine(false)` when a test needs a
	/// deterministic pending transaction window.
	pub async fn set_interval_mining(&self, chain_id: u64, seconds: u64) -> Result<()> {
		let provider = self.provider_for(chain_id)?;
		provider
			.client()
			.request::<_, serde_json::Value>("evm_setIntervalMining", (seconds,))
			.await
			.with_context(|| format!("evm_setIntervalMining({seconds}) on chain {chain_id}"))?;
		Ok(())
	}

	/// Mine `count` blocks on one harness chain.
	pub async fn mine_blocks(&self, chain_id: u64, count: u64) -> Result<()> {
		let provider = self.provider_for(chain_id)?;
		for _ in 0..count {
			provider
				.client()
				.request::<_, serde_json::Value>("evm_mine", ())
				.await
				.with_context(|| format!("evm_mine on chain {chain_id}"))?;
		}
		Ok(())
	}

	/// Set the base fee for the next Anvil block on one harness chain.
	pub async fn set_next_block_base_fee_per_gas(&self, chain_id: u64, fee: U256) -> Result<()> {
		let provider = self.provider_for(chain_id)?;
		provider
			.client()
			.request::<_, serde_json::Value>("anvil_setNextBlockBaseFeePerGas", (fee,))
			.await
			.with_context(|| {
				format!("anvil_setNextBlockBaseFeePerGas({fee}) on chain {chain_id}")
			})?;
		Ok(())
	}

	/// Drop a pending transaction from one harness chain's Anvil mempool.
	pub async fn drop_transaction(
		&self,
		chain_id: u64,
		tx_hash: &solver_types::TransactionHash,
	) -> Result<()> {
		let provider = self.provider_for(chain_id)?;
		let hash = format!("0x{}", hex::encode(&tx_hash.0));
		provider
			.client()
			.request::<_, serde_json::Value>("anvil_dropTransaction", (hash.clone(),))
			.await
			.with_context(|| format!("anvil_dropTransaction({hash}) on chain {chain_id}"))?;
		Ok(())
	}

	/// Stop the solver subprocess while keeping Anvil chains and storage alive.
	pub async fn stop_solver(&mut self) -> Result<()> {
		if let Some(mut solver) = self.solver.take() {
			solver.kill().context("kill solver subprocess")?;
			solver.wait().context("wait for solver subprocess exit")?;
		}
		Ok(())
	}

	/// Restart the solver subprocess with the same bootstrap config and storage.
	pub async fn restart_solver(&mut self) -> Result<()> {
		self.stop_solver().await?;
		let child = spawn_solver(
			&self.bootstrap_path,
			self._tempdir.path(),
			&self.solver_stderr_path,
			&self.options,
		)?;
		wait_for_tcp_ready(SOLVER_API_PORT, SOLVER_HEALTH_TIMEOUT).await?;
		self.solver = Some(child);
		Ok(())
	}

	fn storage_service(&self) -> Arc<StorageService> {
		Arc::new(StorageService::new(Box::new(FileStorage::new(
			self._tempdir
				.path()
				.join("data/storage")
				.join(E2E_SOLVER_ID),
			FileTtlConfig::default(),
		))))
	}

	/// Read an order directly from the solver's file-backed storage.
	pub async fn stored_order(&self, order_id: &str) -> Result<solver_types::Order> {
		let state = OrderStateMachine::new(self.storage_service());
		state
			.get_order(order_id)
			.await
			.with_context(|| format!("read stored order {order_id}"))
	}

	/// Read all transaction attempts for an order directly from storage.
	pub async fn stored_attempts(
		&self,
		order_id: &str,
	) -> Result<Vec<solver_types::TransactionAttempt>> {
		let store = TransactionAttemptStore::new(self.storage_service());
		let attempts = store
			.attempts_for_order(order_id)
			.await
			.with_context(|| format!("read attempts for order {order_id}"))?;
		if !attempts.is_empty() {
			return Ok(attempts);
		}

		let alternate_order_id = order_id
			.strip_prefix("0x")
			.map(str::to_owned)
			.unwrap_or_else(|| solver_types::with_0x_prefix(order_id));
		let attempts = store
			.attempts_for_order(&alternate_order_id)
			.await
			.with_context(|| format!("read attempts for order {alternate_order_id}"))?;
		if !attempts.is_empty() {
			return Ok(attempts);
		}

		let storage = self.storage_service();
		let storage_root = self
			._tempdir
			.path()
			.join("data/storage")
			.join(E2E_SOLVER_ID);
		scan_attempt_files(&storage_root, storage, order_id, &alternate_order_id).await
	}

	/// Read transaction attempts for an order and transaction type.
	pub async fn stored_attempts_by_type(
		&self,
		order_id: &str,
		tx_type: solver_types::TransactionType,
	) -> Result<Vec<solver_types::TransactionAttempt>> {
		let attempts = self.stored_attempts(order_id).await?;
		Ok(attempts
			.into_iter()
			.filter(|attempt| attempt.tx_type == tx_type)
			.collect())
	}

	/// Overwrite a transaction attempt directly in the solver's file-backed
	/// storage. Used by resilience tests to simulate crash-window ledger
	/// states that are hard to produce deterministically through public APIs.
	pub async fn save_stored_attempt(
		&self,
		attempt: &solver_types::TransactionAttempt,
	) -> Result<()> {
		let store = TransactionAttemptStore::new(self.storage_service());
		store
			.save_attempt(attempt)
			.await
			.with_context(|| format!("save attempt {}", attempt.id))
	}

	/// Read the solver subprocess log captured since the latest boot.
	pub fn solver_log_contents(&self) -> Result<String> {
		std::fs::read_to_string(&self.solver_stderr_path)
			.with_context(|| format!("read solver log {}", self.solver_stderr_path.display()))
	}

	/// Read native (ETH) balance.
	pub async fn native_balance(&self, chain_id: u64, account: Address) -> Result<U256> {
		let provider = self.provider_for(chain_id)?;
		provider
			.get_balance(account)
			.await
			.with_context(|| format!("get_balance({account}) on chain {chain_id}"))
	}

	/// Read raw token balance.
	pub async fn balance(&self, chain_id: u64, token: Address, owner: Address) -> Result<U256> {
		let provider = self.provider_for(chain_id)?;
		let contract = IERC20::new(token, provider);
		let result = contract
			.balanceOf(owner)
			.call()
			.await
			.with_context(|| format!("balanceOf({owner}) on chain {chain_id}"))?;
		Ok(result)
	}

	/// User approves `spender` for `amount` of TOKA on the origin chain.
	pub async fn user_approve(
		&self,
		token: Address,
		spender: Address,
		amount: U256,
	) -> Result<TransactionReceipt> {
		let provider = build_provider(&self.origin.rpc_http, self.user_signer.clone()).await?;
		let contract = IERC20::new(token, provider);
		let pending = contract
			.approve(spender, amount)
			.send()
			.await
			.context("send approve")?;
		pending.get_receipt().await.context("approve receipt")
	}

	/// User submits `open(order)` on the origin input settler. Returns the
	/// orderId emitted by the `Open` event.
	pub async fn user_open(&self, order: StandardOrder) -> Result<B256> {
		let receipt = self.user_open_result(order).await?;

		extract_order_id_from_receipt(&receipt).ok_or_else(|| {
			anyhow!(
				"Open event not found in receipt {:?}",
				receipt.transaction_hash
			)
		})
	}

	/// User submits `open(order)` on the origin input settler. Unlike
	/// `user_open`, this returns the raw receipt result so negative tests can
	/// assert expected reverts.
	pub async fn user_open_result(&self, order: StandardOrder) -> Result<TransactionReceipt> {
		let provider = build_provider(&self.origin.rpc_http, self.user_signer.clone()).await?;
		let contract = IInputSettlerEscrow::new(self.origin.input_settler, provider);
		let pending = contract.open(order).send().await.context("send open")?;
		pending.get_receipt().await.context("open receipt")
	}

	/// Poll for the next log on `chain_id` matching the given event signature
	/// and (optional) orderId topic. Polls every `POLL_INTERVAL` until either
	/// match or `timeout`.
	pub async fn await_event<E: SolEvent>(
		&self,
		chain_id: u64,
		address: Address,
		order_id: B256,
		timeout: Duration,
	) -> Result<(E, Log)> {
		const POLL_INTERVAL: Duration = Duration::from_millis(500);

		let deadline = Instant::now() + timeout;
		let mut from_block: u64 = 0;

		loop {
			let (event, next_from_block) = self
				.poll_event_once::<E>(chain_id, address, order_id, from_block)
				.await?;
			if let Some((event, log)) = event {
				return Ok((event, log));
			}
			if Instant::now() >= deadline {
				// Self-diagnostic: dump solver stderr + bootstrap config so the
				// timeout message isn't the only thing the user has to chase.
				self.dump_solver_stderr();
				self.dump_bootstrap_config();
				return Err(anyhow!(
					"timeout waiting for {} on chain {chain_id} address {address} \
					 orderId {order_id} within {timeout:?}",
					E::SIGNATURE
				));
			}
			from_block = next_from_block;
			tokio::time::sleep(POLL_INTERVAL).await;
		}
	}

	/// Assert that no matching event appears within `timeout`.
	pub async fn await_no_event<E: SolEvent>(
		&self,
		chain_id: u64,
		address: Address,
		order_id: B256,
		timeout: Duration,
	) -> Result<()> {
		const POLL_INTERVAL: Duration = Duration::from_millis(500);

		let deadline = Instant::now() + timeout;
		let mut from_block: u64 = 0;

		loop {
			let (event, next_from_block) = self
				.poll_event_once::<E>(chain_id, address, order_id, from_block)
				.await?;
			if event.is_some() {
				self.dump_solver_stderr();
				self.dump_bootstrap_config();
				return Err(anyhow!(
					"unexpected {} observed on chain {chain_id} address {address} \
					 orderId {order_id}",
					E::SIGNATURE
				));
			}
			if Instant::now() >= deadline {
				return Ok(());
			}
			from_block = next_from_block;
			tokio::time::sleep(POLL_INTERVAL).await;
		}
	}

	async fn poll_event_once<E: SolEvent>(
		&self,
		chain_id: u64,
		address: Address,
		order_id: B256,
		from_block: u64,
	) -> Result<(Option<(E, Log)>, u64)> {
		let provider = self.provider_for(chain_id)?;
		let head = provider
			.get_block_number()
			.await
			.context("get_block_number")?;
		let filter = Filter::new()
			.address(address)
			.event_signature(E::SIGNATURE_HASH)
			.topic1(order_id)
			.from_block(from_block)
			.to_block(BlockNumberOrTag::Number(head));

		let logs = provider.get_logs(&filter).await.context("get_logs")?;
		let event = if let Some(log) = logs.into_iter().next() {
			let decoded = E::decode_log(&log.inner).context("decode event")?;
			Some((decoded.data, log))
		} else {
			None
		};

		Ok((event, head.saturating_add(1)))
	}

	fn provider_for(&self, chain_id: u64) -> Result<&DynProvider> {
		match chain_id {
			ORIGIN_CHAIN_ID => Ok(&self.origin_provider),
			DEST_CHAIN_ID => Ok(&self.destination_provider),
			other => Err(anyhow!("no provider for chain {other}")),
		}
	}

	/// Read the destination block's timestamp by number. Used by tests that
	/// need a real fill timestamp to pass into `direct_finalise(...)`.
	pub async fn destination_block_timestamp(&self, block_number: u64) -> Result<u64> {
		let block = self
			.destination_provider
			.get_block_by_number(BlockNumberOrTag::Number(block_number))
			.await
			.context("destination get_block_by_number")?
			.ok_or_else(|| anyhow!("destination block {block_number} not found"))?;
		Ok(block.header.timestamp)
	}

	/// Approve the output token from the solver, then call
	/// `OutputSettlerSimple.fill(orderId, output, fillDeadline, fillerData)`
	/// on the destination chain as the solver. Emits `OutputFilled`.
	///
	/// `fillerData` is encoded as `bytes32(solver_address)` per
	/// `FillerDataLib.sol:23`; empty bytes would revert.
	pub async fn direct_fill_on_destination(
		&self,
		order_id: B256,
		output: MandateOutput,
		fill_deadline: u32,
	) -> Result<TransactionReceipt> {
		let output_settler = self.destination.output_settler;

		// 1. Solver approves output_settler to pull `output.amount` of token_b.
		let token_addr = Address::from_slice(&output.token.0[12..]);
		let approve_pending = IERC20::new(token_addr, &self.destination_provider)
			.approve(output_settler, output.amount)
			.send()
			.await
			.context("solver approve(output_settler, amount)")?;
		let _ = approve_pending
			.get_receipt()
			.await
			.context("solver approve receipt")?;

		// 2. ABI roundtrip the typed value into ext_bindings' identical layout.
		let encoded = output.abi_encode();
		let local_output = <ext_bindings::SolMandateOutput as SolValue>::abi_decode(&encoded)
			.context("re-decode MandateOutput into ext_bindings layout")?;

		// 3. fillerData = bytes32(solver_address) (left-padded 32 bytes).
		let filler_data = Bytes::from(self.solver_address().into_word().0.to_vec());

		// 4. uint48 conversion for fillDeadline.
		let fill_deadline_u48 = alloy_primitives::aliases::U48::from(fill_deadline);

		// 5. Call fill(...) via the rpc-tagged local binding.
		let pending =
			ext_bindings::IOutputSettlerSimpleRpc::new(output_settler, &self.destination_provider)
				.fill(order_id, local_output, fill_deadline_u48, filler_data)
				.send()
				.await
				.context("send OutputSettlerSimple.fill")?;
		pending.get_receipt().await.context("fill receipt")
	}

	/// Call `InputSettlerEscrow.finalise(order, solveParams, destination, [])`
	/// on the origin chain as the solver. Emits `Finalised`.
	///
	/// Default `Harness::boot()` deploys `AlwaysYesOracle`, so this does NOT
	/// require any oracle attestation setup — `efficientRequireProven` is a
	/// no-op there.
	pub async fn direct_finalise(
		&self,
		order: StandardOrder,
		fill_timestamp: u32,
	) -> Result<TransactionReceipt> {
		let solver_word = self.solver_address().into_word();
		let solve_params = SolveParams {
			timestamp: fill_timestamp,
			solver: solver_word,
		};
		let pending = IInputSettlerEscrow::new(self.origin.input_settler, &self.origin_provider)
			.finalise(order, vec![solve_params], solver_word, Bytes::new())
			.send()
			.await
			.context("send InputSettlerEscrow.finalise")?;
		pending.get_receipt().await.context("finalise receipt")
	}

	/// Advance the origin chain past `order.expires`, then call
	/// `InputSettlerEscrow.refund(order)`. Emits `Refunded`.
	pub async fn direct_refund(&self, order: StandardOrder) -> Result<TransactionReceipt> {
		// 1. Jump time past expires + buffer. Anvil's `evm_setNextBlockTimestamp`
		//    returns the new timestamp as a hex string and `evm_mine` returns
		//    the mined block number as a hex string — model the response as
		//    `serde_json::Value` to ignore the body without a type mismatch.
		let new_ts: u64 = u64::from(order.expires) + 60;
		self.origin_provider
			.client()
			.request::<_, serde_json::Value>("evm_setNextBlockTimestamp", (new_ts,))
			.await
			.context("evm_setNextBlockTimestamp")?;
		self.origin_provider
			.client()
			.request::<_, serde_json::Value>("evm_mine", ())
			.await
			.context("evm_mine")?;

		// 2. Roundtrip order into ext_bindings layout for the local rpc-tagged
		//    interface.
		let encoded = order.abi_encode();
		let local_order = <ext_bindings::StandardOrder as SolValue>::abi_decode(&encoded)
			.context("re-decode StandardOrder into ext_bindings layout")?;

		// 3. Call refund(...) as the user (refund is unrestricted in the
		//    contract; using the solver-signed provider is fine but mirrors the
		//    common pattern of "anyone can trigger after expiry").
		let pending = ext_bindings::IInputSettlerEscrowRefund::new(
			self.origin.input_settler,
			&self.origin_provider,
		)
		.refund(local_order)
		.send()
		.await
		.context("send InputSettlerEscrow.refund")?;
		pending.get_receipt().await.context("refund receipt")
	}
}

impl Drop for Harness {
	fn drop(&mut self) {
		if let Some(mut s) = self.solver.take() {
			let _ = s.kill();
			let _ = s.wait();
		}
		for mut a in self.anvils.drain(..) {
			let _ = a.kill();
			let _ = a.wait();
		}
		// Catch any orphans from a child handle lost to a panic.
		kill_listeners_on_ports(&[ORIGIN_RPC_PORT, DEST_RPC_PORT, SOLVER_API_PORT]);
	}
}

// =============================================================================
// Tracing
// =============================================================================

fn init_tracing() {
	use std::sync::OnceLock;
	static ONCE: OnceLock<()> = OnceLock::new();
	ONCE.get_or_init(|| {
		let _ = tracing_subscriber::fmt()
			.with_env_filter(
				tracing_subscriber::EnvFilter::try_from_default_env()
					.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,solver=info")),
			)
			.with_test_writer()
			.try_init();
	});
}

// =============================================================================
// Anvil orchestration
// =============================================================================

fn spawn_anvil(chain_id: u64, port: u16) -> Result<Child> {
	tracing::info!("Spawning anvil chain_id={chain_id} port={port}");
	let child = Command::new("anvil")
		.args([
			"--chain-id",
			&chain_id.to_string(),
			"--port",
			&port.to_string(),
			"--accounts",
			"10",
			"--block-time",
			"1", // 1s block-time keeps block.timestamp moving so settlement's
			     // dispute period actually elapses. Auto-mine breaks this:
			     // origin chain produces no blocks while the solver waits, so
			     // dispute_period_seconds never appears to pass.
		])
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.context("spawn anvil — is foundry installed and on PATH?")?;
	Ok(child)
}

async fn wait_for_rpc_ready(rpc_url: &str, timeout: Duration) -> Result<()> {
	let deadline = Instant::now() + timeout;
	loop {
		// Just probe the JSON-RPC by issuing eth_chainId via a fresh provider.
		// Avoids extra deps for HTTP probing.
		let signer = parse_signer(SOLVER_PRIVATE_KEY)?;
		if let Ok(p) = build_provider(rpc_url, signer).await {
			if p.get_chain_id().await.is_ok() {
				return Ok(());
			}
		}
		if Instant::now() >= deadline {
			return Err(anyhow!("anvil at {rpc_url} not ready within {timeout:?}"));
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

async fn wait_for_tcp_ready(port: u16, timeout: Duration) -> Result<()> {
	let deadline = Instant::now() + timeout;
	loop {
		if tokio::net::TcpStream::connect(("127.0.0.1", port))
			.await
			.is_ok()
		{
			return Ok(());
		}
		if Instant::now() >= deadline {
			return Err(anyhow!("port {port} not ready within {timeout:?}"));
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
}

fn kill_listeners_on_ports(ports: &[u16]) {
	for port in ports {
		let out = Command::new("lsof")
			.args(["-t", &format!("-i:{port}"), "-sTCP:LISTEN"])
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.output();
		let Ok(out) = out else { continue };
		if !out.status.success() {
			continue;
		}
		for line in String::from_utf8_lossy(&out.stdout).lines() {
			if let Ok(pid) = line.trim().parse::<i32>() {
				let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
			}
		}
	}
}

// =============================================================================
// Provider + signer helpers
// =============================================================================

fn parse_signer(hex_key: &str) -> Result<PrivateKeySigner> {
	hex_key
		.parse::<PrivateKeySigner>()
		.with_context(|| format!("parse private key {hex_key:.10}…"))
}

fn parse_address(s: &str) -> Result<Address> {
	Address::from_str(s).with_context(|| format!("parse address {s}"))
}

async fn build_provider(rpc_url: &str, signer: PrivateKeySigner) -> Result<DynProvider> {
	let wallet = EthereumWallet::from(signer);
	let provider = ProviderBuilder::new()
		.wallet(wallet)
		.connect(rpc_url)
		.await
		.with_context(|| format!("connect provider {rpc_url}"))?
		.erased();
	Ok(provider)
}

/// `whole * 10^18`, the standard 18-decimal token amount. Used for both
/// input and output token sides — all mock ERC20s in the harness use 18 decimals.
pub fn amount_with_decimals(whole: u64) -> U256 {
	U256::from(whole) * U256::from(10u64).pow(U256::from(18u64))
}

pub fn assert_open_failed(result: Result<TransactionReceipt>, context: &str) {
	match result {
		Ok(receipt) => {
			assert!(
				!receipt.status(),
				"{context}: expected open transaction to revert"
			);
		},
		Err(error) => {
			// Alloy may surface expected reverts during gas estimation/preflight instead of
			// returning a mined receipt, depending on provider/version behavior.
			// TODO: tighten this to typed Alloy/revm error matching once variants stabilize.
			let message = error
				.chain()
				.map(ToString::to_string)
				.collect::<Vec<_>>()
				.join(": ");
			let debug = format!("{error:?}");
			assert!(
				message.contains("revert")
					|| message.contains("execution reverted")
					|| message.contains("insufficient")
					|| message.contains("allowance")
					|| message.contains("transfer amount exceeds")
					|| debug.contains("revert")
					|| debug.contains("execution reverted")
					|| debug.contains("insufficient")
					|| debug.contains("allowance")
					|| debug.contains("transfer amount exceeds"),
				"{context}: expected revert/preflight failure, got {message}; debug: {debug}"
			);
		},
	}
}

pub fn redis_url_or_skip() -> Option<String> {
	std::env::var("REDIS_URL")
		.ok()
		.filter(|value| !value.trim().is_empty())
}

// =============================================================================
// Contract deploy
// =============================================================================

/// Path to the user's `oif-contracts/out/`. `OIF_CONTRACTS_PATH` overrides;
/// default is the canonical sibling layout `<workspace>/../oif-contracts`.
fn oif_contracts_out() -> Result<PathBuf> {
	let path = if let Ok(env_path) = std::env::var("OIF_CONTRACTS_PATH") {
		PathBuf::from(env_path)
	} else {
		let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		let workspace = manifest
			.parent()
			.and_then(|p| p.parent())
			.ok_or_else(|| anyhow!("workspace root resolution failed"))?;
		workspace
			.parent()
			.ok_or_else(|| anyhow!("workspace has no parent"))?
			.join("oif-contracts")
	};
	let out = path.join("out");
	if !out.exists() {
		return Err(anyhow!(
			"oif-contracts/out not found at {}.\n\nSet up once with:\n  \
			 git clone https://github.com/openintentsframework/oif-contracts.git <path>\n  \
			 cd <path> && forge build\n\nThen point the harness at it via \
			 OIF_CONTRACTS_PATH=<path>, or place it as a sibling of oif-solver.",
			out.display()
		));
	}
	Ok(out)
}

/// Loads creation bytecode from a Foundry artifact JSON.
fn load_bytecode(contract_name: &str) -> Result<Bytes> {
	let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	let pinned_path = manifest
		.join("artifacts")
		.join(format!("{contract_name}.json"));
	if pinned_path.exists() {
		return load_bytecode_from_artifact(&pinned_path, contract_name);
	}

	let out = oif_contracts_out()?;
	let path = out.join(format!("{contract_name}.sol/{contract_name}.json"));
	load_bytecode_from_artifact(&path, contract_name)
}

fn load_bytecode_from_artifact(path: &std::path::Path, contract_name: &str) -> Result<Bytes> {
	let raw = std::fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
	let json: serde_json::Value = serde_json::from_slice(&raw)
		.with_context(|| format!("parse artifact {}", path.display()))?;
	let hex = json
		.get("bytecode")
		.and_then(|b| b.get("object"))
		.and_then(|o| o.as_str())
		.ok_or_else(|| anyhow!("artifact {} missing bytecode.object", path.display()))?;
	let trimmed = hex.trim_start_matches("0x");
	let bytes =
		hex::decode(trimmed).with_context(|| format!("decode hex bytecode for {contract_name}"))?;
	Ok(Bytes::from(bytes))
}

/// CREATE-deploys raw `bytecode || ctor_args`. Returns the deployed address.
async fn deploy_raw(provider: &DynProvider, bytecode: Bytes, ctor_args: Bytes) -> Result<Address> {
	let mut data = bytecode.to_vec();
	data.extend_from_slice(&ctor_args);

	let tx = TransactionRequest::default()
		.with_deploy_code(data)
		.with_value(U256::ZERO);
	let pending = provider
		.send_transaction(tx)
		.await
		.context("send deploy transaction")?;
	let receipt = pending.get_receipt().await.context("deploy receipt")?;
	if !receipt.status() {
		return Err(anyhow!(
			"deploy reverted (tx {:?})",
			receipt.transaction_hash
		));
	}
	receipt
		.contract_address
		.ok_or_else(|| anyhow!("deploy receipt missing contract_address"))
}

async fn deploy_mock_erc20(
	provider: &DynProvider,
	name: &str,
	symbol: &str,
	decimals: u8,
) -> Result<Address> {
	let bytecode = load_bytecode("MockERC20")?;
	// MockERC20(string name, string symbol, uint8 decimals).
	// `u8` doesn't implement SolValue directly; widen to U256. ABI encoding
	// for any fixed uint is a 32-byte left-padded slot, so this is identical
	// on the wire.
	let args = (name.to_string(), symbol.to_string(), U256::from(decimals)).abi_encode_params();
	deploy_raw(provider, bytecode, Bytes::from(args)).await
}

async fn deploy_no_args(provider: &DynProvider, name: &str) -> Result<Address> {
	let bytecode = load_bytecode(name)?;
	deploy_raw(provider, bytecode, Bytes::new()).await
}

async fn deploy_with_args(provider: &DynProvider, name: &str, ctor_args: Bytes) -> Result<Address> {
	let bytecode = load_bytecode(name)?;
	deploy_raw(provider, bytecode, ctor_args).await
}

async fn deploy_compact_stack(
	provider: &DynProvider,
	allocator_signer: Address,
) -> Result<(Address, Address, Address)> {
	let the_compact = deploy_no_args(provider, "TheCompact")
		.await
		.context("deploy TheCompact")?;
	let input_settler_compact = deploy_with_args(
		provider,
		"InputSettlerCompact",
		Bytes::from((the_compact,).abi_encode_params()),
	)
	.await
	.context("deploy InputSettlerCompact")?;
	let allocator = deploy_with_args(
		provider,
		"SimpleAllocator",
		Bytes::from((allocator_signer, the_compact).abi_encode_params()),
	)
	.await
	.context("deploy SimpleAllocator")?;

	let pending = ITheCompactE2e::new(the_compact, provider)
		.__registerAllocator(allocator, Bytes::new())
		.send()
		.await
		.context("send TheCompact.__registerAllocator")?;
	let receipt = pending
		.get_receipt()
		.await
		.context("register allocator receipt")?;
	if !receipt.status() {
		return Err(anyhow!(
			"register allocator reverted (tx {:?})",
			receipt.transaction_hash
		));
	}

	tracing::info!(
		the_compact = %the_compact,
		input_settler_compact = %input_settler_compact,
		allocator = %allocator,
		"Deployed Compact stack"
	);

	Ok((the_compact, input_settler_compact, allocator))
}

async fn deploy_chain(
	provider: &DynProvider,
	chain_id: u64,
	rpc_http: &str,
) -> Result<ChainDeployment> {
	let token_a = deploy_mock_erc20(provider, "Token A", "TOKA", 18)
		.await
		.context("deploy MockERC20 TOKA")?;
	let token_b = deploy_mock_erc20(provider, "Token B", "TOKB", 18)
		.await
		.context("deploy MockERC20 TOKB")?;
	let always_yes = deploy_no_args(provider, "AlwaysYesOracle")
		.await
		.context("deploy AlwaysYesOracle")?;
	let input_settler = deploy_no_args(provider, "InputSettlerEscrow")
		.await
		.context("deploy InputSettlerEscrow")?;
	let output_settler = deploy_no_args(provider, "OutputSettlerSimple")
		.await
		.context("deploy OutputSettlerSimple")?;

	tracing::info!(
		chain_id,
		token_a = %token_a,
		token_b = %token_b,
		oracle = %always_yes,
		input_settler = %input_settler,
		output_settler = %output_settler,
		"Deployed chain"
	);

	Ok(ChainDeployment {
		chain_id,
		rpc_http: rpc_http.to_string(),
		token_a,
		token_b,
		input_oracle: always_yes,
		output_oracle: always_yes,
		input_settler,
		output_settler,
		input_settler_compact: None,
		the_compact: None,
		allocator: None,
		mock_mailbox: None,
	})
}

/// Deploy `MockMailboxV2` from the pinned artifact. Used only when
/// `HarnessOptions::use_hyperlane_settlement` is set.
async fn deploy_mock_mailbox_v2(provider: &DynProvider) -> Result<Address> {
	let bytecode = load_bytecode("MockMailboxV2")?;
	deploy_raw(provider, bytecode, Bytes::new()).await
}

/// Deploy `HyperlaneOracle(mailbox, customHook, ism)`. We use non-zero
/// placeholder addresses for `customHook` and `ism`; `MailboxClient`'s
/// constructor only requires non-zero, and the mock mailbox never delegates
/// to the hook. Bytecode comes from `oif-contracts/out/`, same as the other
/// oracle deploys.
async fn deploy_hyperlane_oracle(provider: &DynProvider, mailbox: Address) -> Result<Address> {
	let bytecode = load_bytecode("HyperlaneOracle")?;
	let custom_hook: Address = "0x000000000000000000000000000000000000DEAD"
		.parse()
		.expect("static address");
	let ism: Address = "0x000000000000000000000000000000000000bEEF"
		.parse()
		.expect("static address");
	let args = (mailbox, custom_hook, ism).abi_encode_params();
	deploy_raw(provider, bytecode, Bytes::from(args)).await
}

/// Plant Permit2's runtime bytecode at its canonical address via
/// `anvil_setCode`. Reads `deployedBytecode.object` (NOT `bytecode.object`)
/// from `artifacts/Permit2.json` — the canonical Permit2 address holds
/// already-deployed code, never the CREATE initcode. After this, the
/// `InputSettlerEscrow`'s hardcoded references to `0x...22D473` resolve to a
/// working Permit2 instance.
async fn install_permit2_at_canonical(provider: &DynProvider) -> Result<()> {
	let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	let path = manifest.join("artifacts/Permit2.json");
	let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
	let json: serde_json::Value =
		serde_json::from_slice(&raw).with_context(|| format!("parse {}", path.display()))?;
	let hex = json
		.get("deployedBytecode")
		.and_then(|d| d.get("object"))
		.and_then(|o| o.as_str())
		.ok_or_else(|| anyhow!("Permit2 artifact missing deployedBytecode.object"))?;
	let addr = parse_address(PERMIT2_ADDRESS)?;
	provider
		.client()
		.request::<_, ()>("anvil_setCode", (addr, hex.to_string()))
		.await
		.context("anvil_setCode for Permit2")?;
	Ok(())
}

/// User-signed ERC20 `approve(spender, MAX_UINT256)`. Used to grant Permit2
/// (or any other contract) unlimited spending authority over the user's
/// tokens — Permit2's own typed-data signatures are downstream of this
/// allowance.
async fn user_approve_max(
	rpc_url: &str,
	user_signer: &PrivateKeySigner,
	token: Address,
	spender: Address,
) -> Result<()> {
	let provider = build_provider(rpc_url, user_signer.clone()).await?;
	let contract = IERC20::new(token, provider);
	let pending = contract
		.approve(spender, U256::MAX)
		.send()
		.await
		.context("send approve(MAX)")?;
	let receipt = pending.get_receipt().await.context("approve receipt")?;
	if !receipt.status() {
		return Err(anyhow!(
			"approve(MAX) reverted (tx {:?})",
			receipt.transaction_hash
		));
	}
	Ok(())
}

async fn mint_erc20(
	provider: &DynProvider,
	token: Address,
	to: Address,
	amount: U256,
) -> Result<()> {
	let contract = IERC20::new(token, provider);
	let pending = contract
		.mint(to, amount)
		.send()
		.await
		.context("send mint")?;
	let receipt = pending.get_receipt().await.context("mint receipt")?;
	if !receipt.status() {
		return Err(anyhow!("mint reverted (tx {:?})", receipt.transaction_hash));
	}
	Ok(())
}

// =============================================================================
// Bootstrap config
// =============================================================================
//
// We build a `solver_types::SeedOverrides` programmatically and feed it to
// the solver via `--bootstrap-config <path>`. The solver's main.rs calls
// `parse_seed_overrides` then `merge_to_operator_config_seedless` then
// `build_runtime_config`; we don't need to mirror any of that ourselves.
//
// Critical schema note: SeedOverrides uses `Vec<NetworkOverride>` (sequence)
// keyed by `chain_id` — NOT a HashMap. Hand-writing JSON in the runtime
// `Config` shape (a map) is what was breaking the previous run.

fn build_seed_overrides(
	origin: &ChainDeployment,
	destination: &ChainDeployment,
	options: &HarnessOptions,
	deny_list_path: Option<String>,
) -> Result<solver_types::SeedOverrides> {
	use solver_types::networks::NetworkType;
	use solver_types::seed_overrides::{
		AdminOverride, BroadcasterSettlementOverride, DirectSettlementOverride,
		HyperlaneSettlementOverride, NetworkOverride, OracleOverrides, SettlementOverride,
		SettlementTypeOverride, Token,
	};

	fn token(symbol: &str, address: Address) -> Token {
		Token {
			symbol: symbol.to_string(),
			name: Some(symbol.to_string()),
			address,
			decimals: 18,
		}
	}

	fn network(d: &ChainDeployment) -> NetworkOverride {
		NetworkOverride {
			chain_id: d.chain_id,
			name: Some(format!("anvil-{}", d.chain_id)),
			// Required by validate_network_for_seedless_mode. We treat both
			// test chains as `Parent` — the variant doesn't affect the
			// settlement flow we exercise here.
			network_type: Some(NetworkType::Parent),
			tokens: vec![
				token("ETH", Address::ZERO),
				token("TOKA", d.token_a),
				token("TOKB", d.token_b),
			],
			rpc_urls: Some(vec![d.rpc_http.clone()]),
			input_settler_address: Some(d.input_settler),
			output_settler_address: Some(d.output_settler),
			input_settler_compact_address: d.input_settler_compact,
			the_compact_address: d.the_compact,
			allocator_address: d.allocator,
		}
	}

	let mut input_oracles = HashMap::new();
	input_oracles.insert(origin.chain_id, vec![origin.input_oracle]);
	input_oracles.insert(destination.chain_id, vec![destination.input_oracle]);
	let mut output_oracles = HashMap::new();
	output_oracles.insert(origin.chain_id, vec![origin.output_oracle]);
	output_oracles.insert(destination.chain_id, vec![destination.output_oracle]);

	let mut routes = HashMap::new();
	routes.insert(origin.chain_id, vec![destination.chain_id]);
	routes.insert(destination.chain_id, vec![origin.chain_id]);

	let mut settlement = if options.use_hyperlane_settlement {
		// Hyperlane settlement requires per-chain mailbox + IGP entries
		// (`validate_seedless_settlement_requirements` enforces presence,
		// not connectivity). Origin's mailbox is unexercised since our flow
		// only dispatches FROM the destination; we still wire it up because
		// the validator demands an entry per chain.
		let origin_mailbox = origin
			.mock_mailbox
			.ok_or_else(|| anyhow!("origin mock_mailbox missing — set use_hyperlane_settlement"))?;
		let dest_mailbox = destination.mock_mailbox.ok_or_else(|| {
			anyhow!("destination mock_mailbox missing — set use_hyperlane_settlement")
		})?;
		let mut mailboxes = HashMap::new();
		mailboxes.insert(origin.chain_id, origin_mailbox);
		mailboxes.insert(destination.chain_id, dest_mailbox);
		// IGP addresses are only validated for presence; the on-chain gas
		// quote goes through `mailbox.quoteDispatch` (which our mock returns
		// 0 for). Reuse the mailbox address as the IGP placeholder.
		let mut igp_addresses = HashMap::new();
		igp_addresses.insert(origin.chain_id, origin_mailbox);
		igp_addresses.insert(destination.chain_id, dest_mailbox);

		let hyperlane = HyperlaneSettlementOverride {
			mailboxes,
			igp_addresses,
			domains: HashMap::from([
				(origin.chain_id, origin.chain_id as u32),
				(destination.chain_id, destination.chain_id as u32),
			]),
			oracles: OracleOverrides {
				input: input_oracles.clone(),
				output: output_oracles.clone(),
			},
			routes: routes.clone(),
			default_gas_limit: None,
			message_timeout_seconds: None,
			finalization_required: None,
			intent_min_expiry_seconds: None,
		};
		SettlementOverride {
			settlement_type: SettlementTypeOverride::Hyperlane,
			priority: Some(vec![SettlementTypeOverride::Hyperlane]),
			hyperlane: Some(hyperlane),
			direct: None,
			broadcaster: None,
		}
	} else {
		let direct = DirectSettlementOverride {
			oracles: OracleOverrides {
				input: input_oracles.clone(),
				output: output_oracles.clone(),
			},
			routes: routes.clone(),
			// AlwaysYesOracle short-circuits dispute logic; 1s keeps the test fast.
			dispute_period_seconds: Some(1),
			oracle_selection_strategy: None,
			intent_min_expiry_seconds: None,
		};
		SettlementOverride {
			settlement_type: SettlementTypeOverride::Direct,
			priority: Some(vec![SettlementTypeOverride::Direct]),
			hyperlane: None,
			direct: Some(direct),
			broadcaster: None,
		}
	};
	if let Some(broadcaster_default_finality_blocks) = options.broadcaster_default_finality_blocks {
		settlement.broadcaster = Some(BroadcasterSettlementOverride {
			oracles: OracleOverrides {
				input: input_oracles.clone(),
				output: output_oracles.clone(),
			},
			routes: routes.clone(),
			broadcaster_addresses: HashMap::from([
				(origin.chain_id, origin.output_settler),
				(destination.chain_id, destination.output_settler),
			]),
			receiver_addresses: HashMap::from([
				(origin.chain_id, origin.input_settler),
				(destination.chain_id, destination.input_settler),
			]),
			broadcaster_ids: HashMap::from([
				(origin.chain_id, B256::ZERO),
				(destination.chain_id, B256::ZERO),
			]),
			proof_service_url: Some("http://127.0.0.1:9".to_string()),
			default_finality_blocks: Some(broadcaster_default_finality_blocks),
			..Default::default()
		});
	}

	let admin = if options.enable_admin_api {
		Some(AdminOverride {
			enabled: true,
			domain: "localhost".to_string(),
			chain_id: Some(ORIGIN_CHAIN_ID),
			admin_addresses: vec![parse_address(SOLVER_ADDRESS)?],
			whitelist: Vec::new(),
			nonce_ttl_seconds: None,
			withdrawals: Default::default(),
		})
	} else {
		None
	};

	Ok(solver_types::SeedOverrides {
		solver_id: Some(E2E_SOLVER_ID.to_string()),
		solver_name: Some("E2E test solver".to_string()),
		networks: vec![network(origin), network(destination)],
		settlement: Some(settlement),
		routing_defaults: None,
		account: None,
		admin,
		orders_auth_enabled: Some(options.enable_admin_api),
		min_profitability_pct: None,
		gas_buffer_bps: None,
		settlement_fee_buffer_bps: None,
		commission_bps: None,
		rate_buffer_bps: None,
		monitoring_timeout_seconds: None,
		deny_list: deny_list_path,
		resource_lock_enabled: Some(options.enable_compact_simple_allocator),
		rebalance: None,
		live_fill_estimate_enabled: None,
		live_post_fill_estimate_chain_ids: None,
		fee_policy: None,
		tx_bump: options.tx_bump.clone(),
		source_finality: None,
	})
}

// =============================================================================
// Solver subprocess
// =============================================================================

fn workspace_root() -> Result<PathBuf> {
	let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	manifest
		.parent()
		.and_then(|p| p.parent())
		.map(|p| p.to_path_buf())
		.ok_or_else(|| anyhow!("workspace root resolution failed"))
}

fn solver_binary_path() -> Result<PathBuf> {
	#[cfg(windows)]
	let exe = "solver.exe";
	#[cfg(not(windows))]
	let exe = "solver";

	let bin = workspace_root()?.join("target").join("debug").join(exe);
	if !bin.exists() {
		return Err(anyhow!(
			"solver binary missing at {} — ensure_solver_binary_built must run first",
			bin.display()
		));
	}
	Ok(bin)
}

fn ensure_solver_binary_built() -> Result<()> {
	let manifest = workspace_root()?.join("Cargo.toml");
	let status = Command::new(env!("CARGO"))
		.args([
			"build",
			"--manifest-path",
			manifest
				.to_str()
				.ok_or_else(|| anyhow!("non-utf8 manifest"))?,
			"-p",
			"solver-service",
			"--bin",
			"solver",
		])
		.status()
		.context("invoke cargo build for solver")?;
	if !status.success() {
		return Err(anyhow!("cargo build -p solver-service failed: {status}"));
	}
	Ok(())
}

fn spawn_solver(
	bootstrap_path: &std::path::Path,
	working_dir: &std::path::Path,
	log_path: &std::path::Path,
	options: &HarnessOptions,
) -> Result<Child> {
	let bin = solver_binary_path()?;
	tracing::info!(
		"Spawning solver {bin:?} --bootstrap-config {bootstrap_path:?} (logs → {log_path:?})"
	);

	// `tracing_subscriber::fmt()` writes to STDOUT by default, not stderr.
	// We pipe both stdout and stderr into the same file so logs land
	// regardless of which channel a layer chooses. Two distinct file handles
	// pointing at the same path; the OS interleaves writes per-line.
	let stdout_file =
		std::fs::File::create(log_path).with_context(|| format!("create log {log_path:?}"))?;
	let stderr_file = stdout_file
		.try_clone()
		.with_context(|| format!("clone log handle {log_path:?}"))?;

	// Honor the user's RUST_LOG if they set one — useful for cranking
	// `solver=trace,solver_core=trace,solver_discovery=trace` to chase
	// discovery wiring issues. Default to a verbose-but-readable level.
	let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| {
		"info,solver=debug,solver_core=debug,solver_discovery=debug,solver_delivery=debug,solver_settlement=debug,solver_order=debug"
			.to_string()
	});

	let mut command = Command::new(&bin);
	command
		.arg("--bootstrap-config")
		.arg(bootstrap_path)
		.arg("--force-seed")
		.current_dir(working_dir)
		.env("STORAGE_BACKEND", "file")
		.env("STORAGE_PATH", working_dir.join("data/storage"))
		.env("SOLVER_PRIVATE_KEY", SOLVER_PRIVATE_KEY)
		// Use mock pricing so the cost-estimation step doesn't try to reach
		// CoinGecko for our fake TOKA/TOKB. The mock impl has TOKA/USD and
		// TOKB/USD prices baked in — see `MockPricing::new`.
		.env("PRICING_PRIMARY", "mock")
		.env("RUST_LOG", rust_log)
		.stdout(stdout_file)
		.stderr(stderr_file);

	if options.enable_admin_api {
		// Must be at least JWT_SECRET_MIN_BYTES (32) bytes; see config_merge::load_jwt_secret_from_env.
		command.env(
			"JWT_SECRET",
			"solver-e2e-admin-jwt-secret-padding-0123456789",
		);
	}
	if let Some(redis_url) = &options.admin_redis_url {
		command.env("REDIS_URL", redis_url);
	}

	let child = command.spawn().with_context(|| format!("spawn {bin:?}"))?;
	Ok(child)
}

// =============================================================================
// Order-id extraction
// =============================================================================

fn extract_order_id_from_receipt(receipt: &TransactionReceipt) -> Option<B256> {
	let target_topic = Open::SIGNATURE_HASH;
	for log in receipt.inner.logs() {
		if log.topics().first() == Some(&target_topic) {
			if let Some(order_id) = log.topics().get(1) {
				return Some(*order_id);
			}
		}
	}
	None
}

// =============================================================================
// Convenience helpers for tests
// =============================================================================

/// Unix timestamp `secs` seconds in the future. Used for `expires` and
/// `fillDeadline`.
pub fn unix_now_plus(secs: u64) -> u32 {
	(SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
		+ secs)
		.try_into()
		.unwrap_or(u32::MAX)
}

/// Returns a unix timestamp `secs` seconds in the past.
pub fn unix_now_minus(secs: u64) -> u32 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
		.saturating_sub(secs)
		.try_into()
		.unwrap_or(0)
}

/// Current unix time in seconds. Use for typed-data fields that need a u64.
pub fn unix_now_secs() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("clock before unix epoch")
		.as_secs()
}

/// Current unix time in milliseconds. Permit2 nonces use this granularity to
/// stay unique within a test run.
pub fn unix_now_millis() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("clock before unix epoch")
		.as_millis() as u64
}

/// Address as bytes32 (left-padded). Required by MandateOutput's bytes32 fields.
pub fn addr_to_bytes32(addr: Address) -> B256 {
	let mut b = [0u8; 32];
	b[12..].copy_from_slice(addr.as_slice());
	B256::from(b)
}

/// Address as uint256 (left-padded). Required by StandardOrder.inputs.
pub fn addr_to_u256(addr: Address) -> U256 {
	U256::from_be_bytes::<32>(addr_to_bytes32(addr).into())
}

/// Build a deterministic nonce. Tests should vary this per submission so the
/// orderId is unique even if other fields collide.
pub fn nonce_from_seed(seed: &str) -> U256 {
	U256::from_be_bytes::<32>(keccak256(seed.as_bytes()).into())
}

#[must_use = "call .build() to produce a StandardOrder"]
pub struct StandardOrderBuilder<'a> {
	harness: &'a Harness,
	seed: String,
	amount_in: U256,
	amount_out: U256,
	expires: u32,
	fill_deadline: u32,
	input_oracle: Address,
	output_oracle: Address,
	output_settler: Address,
	output_token: Address,
	recipient: Address,
}

impl<'a> StandardOrderBuilder<'a> {
	pub fn happy_path(harness: &'a Harness, seed: impl Into<String>) -> Self {
		Self {
			harness,
			seed: seed.into(),
			amount_in: amount_with_decimals(1_000),
			amount_out: amount_with_decimals(990),
			expires: unix_now_plus(60 * 60),
			fill_deadline: unix_now_plus(30 * 60),
			input_oracle: harness.origin.input_oracle,
			output_oracle: harness.destination.output_oracle,
			output_settler: harness.destination.output_settler,
			output_token: harness.destination.token_b,
			recipient: harness.recipient_address(),
		}
	}

	pub fn amount_in(mut self, amount: U256) -> Self {
		self.amount_in = amount;
		self
	}

	pub fn amount_out(mut self, amount: U256) -> Self {
		self.amount_out = amount;
		self
	}

	pub fn expires(mut self, expires: u32) -> Self {
		self.expires = expires;
		self
	}

	pub fn fill_deadline(mut self, deadline: u32) -> Self {
		self.fill_deadline = deadline;
		self
	}

	pub fn input_oracle(mut self, oracle: Address) -> Self {
		self.input_oracle = oracle;
		self
	}

	pub fn output_oracle(mut self, oracle: Address) -> Self {
		self.output_oracle = oracle;
		self
	}

	pub fn output_settler(mut self, settler: Address) -> Self {
		self.output_settler = settler;
		self
	}

	pub fn output_token(mut self, token: Address) -> Self {
		self.output_token = token;
		self
	}

	pub fn recipient(mut self, recipient: Address) -> Self {
		self.recipient = recipient;
		self
	}

	pub fn build(self) -> StandardOrder {
		StandardOrder {
			user: self.harness.user_address(),
			nonce: nonce_from_seed(&self.seed),
			originChainId: U256::from(ORIGIN_CHAIN_ID),
			expires: self.expires,
			fillDeadline: self.fill_deadline,
			inputOracle: self.input_oracle,
			inputs: vec![[addr_to_u256(self.harness.origin.token_a), self.amount_in]],
			outputs: vec![MandateOutput {
				oracle: addr_to_bytes32(self.output_oracle),
				settler: addr_to_bytes32(self.output_settler),
				chainId: U256::from(DEST_CHAIN_ID),
				token: addr_to_bytes32(self.output_token),
				amount: self.amount_out,
				recipient: addr_to_bytes32(self.recipient),
				callbackData: Default::default(),
				context: Default::default(),
			}],
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_storage::{
		implementations::file::{FileStorage, TtlConfig},
		StorageService,
	};
	use solver_types::{utils::tests::builders::OrderBuilder, StorageKey};
	use std::sync::Arc;

	#[tokio::test]
	async fn read_order_from_storage_root_loads_file_storage_order() {
		let tmp = tempfile::TempDir::new().unwrap();
		let root = tmp.path().join("data/storage").join(E2E_SOLVER_ID);
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			root,
			TtlConfig::default(),
		))));
		let order = OrderBuilder::new().with_id("order-1").build();
		storage
			.store(StorageKey::Orders.as_str(), &order.id, &order, None)
			.await
			.unwrap();

		let loaded = read_order_from_storage_root(tmp.path(), &order.id)
			.await
			.unwrap();
		assert_eq!(loaded.id, order.id);
	}

	#[tokio::test]
	async fn scan_attempt_files_treats_missing_storage_root_as_empty() {
		let tmp = tempfile::TempDir::new().unwrap();
		let root = tmp.path().join("missing-storage-root");
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			root.clone(),
			TtlConfig::default(),
		))));

		let attempts = scan_attempt_files(&root, storage, "order-1", "0xorder-1")
			.await
			.unwrap();

		assert!(attempts.is_empty());
	}

	#[test]
	fn log_file_contains_finds_substring() {
		let tmp = tempfile::TempDir::new().unwrap();
		let path = tmp.path().join("solver.log");
		std::fs::write(
			&path,
			"alpha\nInsufficient native gas for transaction preflight\n",
		)
		.unwrap();
		assert!(log_file_contains(&path, "Insufficient native gas").unwrap());
		assert!(!log_file_contains(&path, "not present").unwrap());
	}

	#[test]
	fn log_file_contains_matches_ansi_formatted_tracing_fields() {
		let tmp = tempfile::TempDir::new().unwrap();
		let path = tmp.path().join("solver.log");
		std::fs::write(
			&path,
			"tx_bump: receipt preflight found confirmed lineage tip \u{1b}[3mevent\u{1b}[0m\u{1b}[2m=\u{1b}[0m\"BumpTipAlreadyMined\" \u{1b}[3msuccess\u{1b}[0m\u{1b}[2m=\u{1b}[0mtrue\n",
		)
		.unwrap();
		assert!(log_file_contains(&path, "event=\"BumpTipAlreadyMined\"").unwrap());
		assert!(log_file_contains(&path, "success=true").unwrap());
	}

	#[test]
	fn compact_lock_tag_encodes_reset_period_without_losing_allocator_id() {
		let allocator = parse_address("0x111111111111111111a1a2a3a4a5a6a7a8a9aaab").unwrap();
		let lock_tag = compact_lock_tag_for_allocator(allocator, CompactResetPeriod::OneDay);
		assert_eq!(lock_tag[0] >> 7, 0, "scope should be multichain");
		assert_eq!((lock_tag[0] >> 4) & 0x07, 5, "resetPeriod should be OneDay");
		assert_eq!(lock_tag[0] & 0x0f, 0, "compact flag should be preserved");
		assert_eq!(&lock_tag[1..], &allocator.as_slice()[9..]);

		let compact_allocator =
			parse_address("0x000000000000000000a1a2a3a4a5a6a7a8a9aaab").unwrap();
		let compact_lock_tag =
			compact_lock_tag_for_allocator(compact_allocator, CompactResetPeriod::OneDay);
		assert_eq!(
			compact_lock_tag[0] & 0x0f,
			15,
			"fully compact allocator flag should be preserved"
		);
	}
}
