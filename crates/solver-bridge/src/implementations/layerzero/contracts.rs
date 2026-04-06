//! Typed contract bindings for LayerZero OFT + ERC-20 + ERC-4626.
//!
//! These bindings provide ABI encoding/decoding for contract calls.
//! The actual calls are made through `DeliveryService`, not raw alloy providers.

use alloy_primitives::Address;
use alloy_sol_types::sol;

// --- ERC-20 ---

sol! {
	function approve(address spender, uint256 amount) external returns (bool);
	function balanceOf(address account) external view returns (uint256);
	function allowance(address owner, address spender) external view returns (uint256);
}

// --- ERC-4626 Vault ---

sol! {
	function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
	function previewRedeem(uint256 shares) external view returns (uint256 assets);
}

// --- LayerZero OFT + OVault Composer ---
// Combined into one sol! block so types are shared across interfaces.

sol! {
	struct SendParam {
		uint32 dstEid;
		bytes32 to;
		uint256 amountLD;
		uint256 minAmountLD;
		bytes extraOptions;
		bytes composeMsg;
		bytes oftCmd;
	}

	struct MessagingFee {
		uint256 nativeFee;
		uint256 lzTokenFee;
	}

	struct MessagingReceipt {
		bytes32 guid;
		uint64 nonce;
		MessagingFee fee;
	}

	struct OFTReceipt {
		uint256 amountSentLD;
		uint256 amountReceivedLD;
	}

	interface IOFT {
		function quoteSend(
			SendParam calldata sendParam,
			bool payInLzToken
		) external view returns (MessagingFee msgFee);

		function send(
			SendParam calldata sendParam,
			MessagingFee calldata fee,
			address refundAddress
		) external payable returns (MessagingReceipt msgReceipt, OFTReceipt oftReceipt);

		function token() external view returns (address);
	}

	interface IVaultComposerSync {
		function depositAndSend(
			uint256 assetAmount,
			SendParam calldata sendParam,
			address refundAddress
		) external payable returns (MessagingReceipt msgReceipt);

		function quoteSend(
			address from,
			address targetOft,
			uint256 vaultInAmount,
			SendParam calldata sendParam
		) external view returns (MessagingFee msgFee);
	}
}

/// Left-pad a 20-byte address to bytes32 for SendParam.to.
pub fn address_to_bytes32(addr: Address) -> [u8; 32] {
	let mut buf = [0u8; 32];
	buf[12..32].copy_from_slice(addr.as_slice());
	buf
}

/// Encode LayerZero V2 TYPE_3 extraOptions for lzReceive gas limit.
///
/// Format: `0x0003` (type) + `01` (worker ID) + `0011` (option length = 17)
/// + `01` (option type = lzReceive) + `gas_limit` (16 bytes big-endian)
pub fn encode_lz_receive_option(gas_limit: u128) -> Vec<u8> {
	let mut opts = Vec::with_capacity(22);
	// TYPE_3 header
	opts.extend_from_slice(&[0x00, 0x03]);
	// Worker ID = 1
	opts.push(0x01);
	// Option length = 17 bytes (1 byte type + 16 bytes gas)
	opts.extend_from_slice(&(17u16).to_be_bytes());
	// Option type = 1 (lzReceive)
	opts.push(0x01);
	// Gas limit (16 bytes, big-endian)
	opts.extend_from_slice(&gas_limit.to_be_bytes());
	opts
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_address_to_bytes32() {
		let addr = Address::from([0xABu8; 20]);
		let result = address_to_bytes32(addr);
		assert_eq!(&result[..12], &[0u8; 12]);
		assert_eq!(&result[12..], addr.as_slice());
	}

	#[test]
	fn test_address_to_bytes32_zero() {
		let addr = Address::ZERO;
		let result = address_to_bytes32(addr);
		assert_eq!(result, [0u8; 32]);
	}

	#[test]
	fn test_lz_receive_option_encoding() {
		let opts = encode_lz_receive_option(200_000);
		assert_eq!(&opts[0..2], &[0x00, 0x03]);
		assert_eq!(opts[2], 0x01);
		assert_eq!(&opts[3..5], &(17u16).to_be_bytes());
		assert_eq!(opts[5], 0x01);
		assert_eq!(&opts[6..22], &200_000u128.to_be_bytes());
		assert_eq!(opts.len(), 22);
	}
}
