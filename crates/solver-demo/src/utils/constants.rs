/// Canonical Permit2 address (same on all chains via CREATE2)
/// This is the standard deployment address for Permit2 across all EVM chains
pub const PERMIT2_CANONICAL_ADDRESS: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

/// Default Anvil deployer account private key
/// Account #0 from Anvil's default accounts
pub const DEFAULT_ANVIL_DEPLOYER_KEY: &str =
	"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Default number of accounts to create in local Anvil instances
pub const ANVIL_ACCOUNTS: &str = "10";

/// Default balance for each account in local Anvil instances (in ETH)
pub const ANVIL_BALANCE: &str = "10000";

/// Default block time for local Anvil instances (in seconds)
pub const ANVIL_BLOCK_TIME: &str = "1";

/// Maximum attempts to wait for RPC to be ready
pub const RPC_READY_MAX_ATTEMPTS: u32 = 10;

/// Delay between RPC ready check attempts (in milliseconds)
pub const RPC_READY_CHECK_DELAY_MS: u64 = 500;
