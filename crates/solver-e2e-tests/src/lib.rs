//! End-to-end test harness for the OIF solver.
//!
//! Lifecycle: spawn two Anvil processes → deploy MockERC20s + AlwaysYesOracle
//! + InputSettlerEscrow + OutputSettlerSimple on each chain → write a typed
//! `SeedOverrides` bootstrap config → spawn the `solver` binary → expose
//! deployed addresses + signers to the test.
//!
//! Design choices are documented in `crates/solver-e2e-tests/README.md`.

use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_types::{BlockNumberOrTag, Filter, Log, TransactionReceipt, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolEvent, SolValue};
use anyhow::{anyhow, Context as _, Result};
use std::{
	collections::HashMap,
	path::PathBuf,
	process::{Child, Command, Stdio},
	str::FromStr,
	time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

// =============================================================================
// Public sol! types
// =============================================================================
//
// These mirror the on-chain types we need to encode (for `open(...)`) and
// decode (for assertion). Kept here, public, because:
//   - solver-discovery's sol! declarations are private to its impl module.
//   - solver-types defines the StandardOrder Rust struct but not the sol! event.
//   - duplicating ~30 lines of struct/event ABI is cheaper than re-exposing
//     internals across crates.

sol! {
	#[derive(Debug)]
	struct MandateOutput {
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
		MandateOutput[] outputs;
	}

	/// Emitted by InputSettlerEscrow.open(); the signal that on-chain
	/// discovery picks up.
	#[derive(Debug)]
	event Open(bytes32 indexed orderId, StandardOrder order);

	/// Emitted by OutputSettlerBase when the solver fills on the destination.
	#[derive(Debug)]
	event OutputFilled(
		bytes32 indexed orderId,
		bytes32 solver,
		uint32 timestamp,
		MandateOutput output,
		uint256 finalAmount
	);

	/// Emitted by InputSettlerBase when the order is settled (claim leg).
	#[derive(Debug)]
	event Finalised(bytes32 indexed orderId, bytes32 solver, bytes32 destination);

	#[sol(rpc)]
	contract IERC20 {
		function mint(address to, uint256 value) external;
		function approve(address spender, uint256 value) external returns (bool);
		function balanceOf(address account) external view returns (uint256);
	}

	#[sol(rpc)]
	contract IInputSettlerEscrow {
		function open(StandardOrder calldata order) external;
		function orderIdentifier(StandardOrder calldata order) external view returns (bytes32);
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
	_tempdir: TempDir,
}

#[derive(Debug, Clone)]
pub struct HarnessOptions {
	pub user_token_a_mint: U256,
	pub solver_token_b_mint: U256,
	pub use_false_oracle: bool,
	pub use_reverting_output_settler: bool,
	pub enable_permit2: bool,
	pub enable_admin_api: bool,
	pub admin_redis_url: Option<String>,
	pub enable_offchain_api: bool,
	// Phase 2 rebalance fields should plug into the RebalanceOverridesBuilder
	// added in Task 0b instead of reshaping the seed override path later:
	// pub enable_rebalance: bool,
	// pub rebalance_pairs: Vec<solver_types::OperatorRebalancePairConfig>,
	// pub rebalance_overrides: RebalanceOverridesBuilder,
}

impl Default for HarnessOptions {
	fn default() -> Self {
		Self {
			user_token_a_mint: amount_with_decimals(1_000_000),
			solver_token_b_mint: amount_with_decimals(1_000_000),
			use_false_oracle: false,
			use_reverting_output_settler: false,
			enable_permit2: false,
			enable_admin_api: false,
			admin_redis_url: None,
			enable_offchain_api: false,
		}
	}
}

impl Harness {
	pub async fn boot() -> Result<Self> {
		Self::boot_with(HarnessOptions::default()).await
	}

	pub async fn boot_with(options: HarnessOptions) -> Result<Self> {
		init_tracing();

		// Pre-flight: kill any orphans on our fixed ports. solver-demo's
		// AnvilManager intentionally `mem::forget`s child handles; previous
		// runs that crashed may have left listeners alive.
		kill_listeners_on_ports(&[ORIGIN_RPC_PORT, DEST_RPC_PORT, SOLVER_API_PORT]);

		let tempdir = TempDir::new().context("create tempdir")?;

		// Build the solver binary up front; the test should fail loudly here
		// rather than mid-flow if the workspace is broken.
		ensure_solver_binary_built()?;

		// Boot two anvil processes. We track the children so Drop can SIGKILL
		// them, even if the test panics.
		let mut anvils = Vec::new();
		anvils.push(spawn_anvil(ORIGIN_CHAIN_ID, ORIGIN_RPC_PORT)?);
		anvils.push(spawn_anvil(DEST_CHAIN_ID, DEST_RPC_PORT)?);

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

		// Write the bootstrap config. SeedOverrides shape — see notes at
		// build_seed_overrides for why this is what `solver --bootstrap-config`
		// expects (vs. the runtime Config schema in demo.json).
		let seed_overrides = build_seed_overrides(&origin, &destination, &options)?;
		let bootstrap_path = tempdir.path().join("bootstrap.json");
		std::fs::write(
			&bootstrap_path,
			serde_json::to_vec_pretty(&seed_overrides).context("serialize SeedOverrides")?,
		)
		.context("write bootstrap config")?;

		// Spawn the solver binary. We capture stderr to a file (rather than
		// `Stdio::inherit()`) so we can dump it on failure regardless of how
		// the test harness is buffering its own stderr. `dump_solver_stderr`
		// reads it.
		let solver_stderr_path = tempdir.path().join("solver.stderr.log");
		let solver = spawn_solver(
			&bootstrap_path,
			tempdir.path(),
			&solver_stderr_path,
			&options,
		)?;
		wait_for_tcp_ready(SOLVER_API_PORT, SOLVER_HEALTH_TIMEOUT).await?;

		Ok(Self {
			origin,
			destination,
			origin_provider,
			destination_provider,
			user_signer,
			anvils,
			solver: Some(solver),
			solver_stderr_path,
			bootstrap_path,
			_tempdir: tempdir,
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
		Ok(pending.get_receipt().await.context("approve receipt")?)
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
		Ok(pending.get_receipt().await.context("open receipt")?)
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

		let provider = self.provider_for(chain_id)?;
		let deadline = Instant::now() + timeout;
		let mut from_block: u64 = 0;

		loop {
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
			if let Some(log) = logs.into_iter().next() {
				let decoded = E::decode_log(&log.inner).context("decode event")?;
				return Ok((decoded.data, log));
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
			from_block = head.saturating_add(1);
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

		let provider = self.provider_for(chain_id)?;
		let deadline = Instant::now() + timeout;
		let mut from_block: u64 = 0;

		loop {
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
			if let Some(log) = logs.into_iter().next() {
				E::decode_log(&log.inner).context("decode unexpected event")?;
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
			from_block = head.saturating_add(1);
			tokio::time::sleep(POLL_INTERVAL).await;
		}
	}

	fn provider_for(&self, chain_id: u64) -> Result<&DynProvider> {
		match chain_id {
			ORIGIN_CHAIN_ID => Ok(&self.origin_provider),
			DEST_CHAIN_ID => Ok(&self.destination_provider),
			other => Err(anyhow!("no provider for chain {other}")),
		}
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
		// Belt-and-suspenders cleanup. If a child handle was lost (e.g. due to
		// a panic in a method that didn't unwind cleanly), this catches it.
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
			"1", // 1s block time keeps log indexing snappy without busy-mining
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

fn amount_with_decimals(whole: u64) -> U256 {
	U256::from(whole) * U256::from(10u64).pow(U256::from(18u64))
}

/// Public re-export of `amount_with_decimals` for tests.
pub fn amount_with_decimals_helper(whole: u64) -> U256 {
	amount_with_decimals(whole)
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

pub fn assert_reverted_receipt(receipt: &TransactionReceipt, context: &str) {
	assert!(
		!receipt.status(),
		"{context}: expected transaction to revert"
	);
}

pub fn assert_balance_delta(before: U256, after: U256, expected: U256, context: &str) {
	assert_eq!(after - before, expected, "{context}");
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
	let raw = std::fs::read(&path).with_context(|| format!("read artifact {}", path.display()))?;
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
	})
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

#[derive(Debug, Clone, Default)]
pub struct RebalanceOverridesBuilder {
	pub config: Option<solver_types::OperatorRebalanceConfig>,
}

fn build_seed_overrides(
	origin: &ChainDeployment,
	destination: &ChainDeployment,
	options: &HarnessOptions,
) -> Result<solver_types::SeedOverrides> {
	build_seed_overrides_with_rebalance(
		origin,
		destination,
		options,
		RebalanceOverridesBuilder::default(),
	)
}

fn build_seed_overrides_with_rebalance(
	origin: &ChainDeployment,
	destination: &ChainDeployment,
	options: &HarnessOptions,
	rebalance: RebalanceOverridesBuilder,
) -> Result<solver_types::SeedOverrides> {
	use solver_types::networks::NetworkType;
	use solver_types::seed_overrides::{
		AdminOverride, DirectSettlementOverride, NetworkOverride, OracleOverrides,
		SettlementOverride, SettlementTypeOverride, Token,
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
			tokens: vec![token("TOKA", d.token_a), token("TOKB", d.token_b)],
			rpc_urls: Some(vec![d.rpc_http.clone()]),
			input_settler_address: Some(d.input_settler),
			output_settler_address: Some(d.output_settler),
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
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

	let direct = DirectSettlementOverride {
		oracles: OracleOverrides {
			input: input_oracles,
			output: output_oracles,
		},
		routes,
		// AlwaysYesOracle short-circuits dispute logic; 1s keeps the test fast.
		dispute_period_seconds: Some(1),
		oracle_selection_strategy: None,
		intent_min_expiry_seconds: None,
	};

	let settlement = SettlementOverride {
		settlement_type: SettlementTypeOverride::Direct,
		priority: Some(vec![SettlementTypeOverride::Direct]),
		hyperlane: None,
		direct: Some(direct),
		broadcaster: None,
	};

	let admin = if options.enable_admin_api {
		Some(AdminOverride {
			enabled: true,
			domain: "localhost".to_string(),
			chain_id: Some(ORIGIN_CHAIN_ID),
			admin_addresses: vec![parse_address(SOLVER_ADDRESS)?],
			nonce_ttl_seconds: None,
			withdrawals: Default::default(),
		})
	} else {
		None
	};

	Ok(solver_types::SeedOverrides {
		solver_id: Some("oif-solver-e2e".to_string()),
		solver_name: Some("E2E test solver".to_string()),
		networks: vec![network(origin), network(destination)],
		settlement: Some(settlement),
		routing_defaults: None,
		account: None,
		admin,
		auth_enabled: Some(options.enable_admin_api),
		min_profitability_pct: None,
		gas_buffer_bps: None,
		commission_bps: None,
		rate_buffer_bps: None,
		monitoring_timeout_seconds: None,
		deny_list: None,
		rebalance: rebalance.config,
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
		.env("JWT_SECRET", "solver-e2e-admin-jwt-secret")
		.env("RUST_LOG", rust_log)
		.stdout(stdout_file)
		.stderr(stderr_file);

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

/// Returns a unix timestamp `secs` seconds in the future. Use this to set
/// `expires` and `fillDeadline` on test orders.
pub fn unix_now_plus(secs: u64) -> u32 {
	(SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
		+ secs)
		.try_into()
		.unwrap_or(u32::MAX)
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
