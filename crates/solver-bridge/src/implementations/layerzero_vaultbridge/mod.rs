//! LayerZero VaultBridge implementation.
//!
//! Handles bridging USDC (Ethereum) <-> vbUSDC (Katana) via:
//! - ETH -> Katana: OVault Composer depositAndSend (vault deposit + OFT bridge)
//! - Katana -> ETH: OFT send() on Share OFT, then vault redeem() on Ethereum
//!
//! TODO: Implement bridge_asset, check_status, estimate_fee.

pub mod contracts;
pub mod types;
