//! Typed contract bindings for VaultBridge + LayerZero OFT.
//!
//! Uses alloy sol! macro for type-safe ABI encoding/decoding.

use alloy_sol_types::sol;

// --- ERC-20 ---

sol! {
	interface IERC20 {
		function approve(address spender, uint256 amount) external returns (bool);
		function allowance(address owner, address spender) external view returns (uint256);
		function balanceOf(address account) external view returns (uint256);
	}
}

// --- ERC-4626 Vault ---

sol! {
	interface IERC4626 {
		function previewDeposit(uint256 assets) external view returns (uint256 shares);
		function previewRedeem(uint256 shares) external view returns (uint256 assets);
		function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
		function balanceOf(address account) external view returns (uint256);
	}
}

// --- LayerZero OFT ---

sol! {
	/// SendParam for LayerZero OFT send/quoteSend.
	struct SendParam {
		uint32 dstEid;
		bytes32 to;
		uint256 amountLD;
		uint256 minAmountLD;
		bytes extraOptions;
		bytes composeMsg;
		bytes oftCmd;
	}

	/// MessagingFee returned by quoteSend.
	struct MessagingFee {
		uint256 nativeFee;
		uint256 lzTokenFee;
	}

	/// MessagingReceipt returned by send.
	struct MessagingReceipt {
		bytes32 guid;
		uint64 nonce;
		MessagingFee fee;
	}

	/// OFTReceipt returned by send.
	struct OFTReceipt {
		uint256 amountSentLD;
		uint256 amountReceivedLD;
	}

	interface IOFT {
		function send(
			SendParam calldata _sendParam,
			MessagingFee calldata _fee,
			address _refundAddress
		) external payable returns (MessagingReceipt memory, OFTReceipt memory);

		function quoteSend(
			SendParam calldata _sendParam,
			bool _payInLzToken
		) external view returns (MessagingFee memory);

		function token() external view returns (address);
		function approvalRequired() external view returns (bool);
	}
}

// --- OVault Composer (Ethereum -> Katana via vault deposit + OFT bridge) ---
// The exact ABI depends on the deployed Composer contract.
// Based on Katana docs, the Composer handles deposit + bridge in one call.

sol! {
	interface IOVaultComposer {
		/// Deposit underlying asset into vault and bridge shares to destination.
		/// The exact signature may differ - verify against deployed contract ABI.
		function depositAndSend(
			address token,
			uint256 amount,
			uint32 dstEid,
			bytes32 to,
			uint256 minAmountLD,
			bytes calldata extraOptions
		) external payable;
	}
}

// --- ERC-20 Transfer event (for tracking token arrivals) ---

sol! {
	event Transfer(address indexed from, address indexed to, uint256 value);
}

/// Build TYPE_3 extraOptions for lzReceive gas.
///
/// Byte layout:
///   0x0003              - TYPE_3 prefix (2 bytes)
///   0x01                - WORKER_ID = executor (1 byte)
///   0x0011              - option_size = 17 (2 bytes)
///   0x01                - OPTION_TYPE_LZRECEIVE (1 byte)
///   <uint128 gas>       - gas limit, 16 bytes big-endian
pub fn build_lz_receive_option(gas: u128) -> Vec<u8> {
	let mut opts = Vec::with_capacity(22);
	opts.extend_from_slice(&3u16.to_be_bytes()); // TYPE_3
	opts.push(1u8); // WORKER_ID (executor)
	opts.extend_from_slice(&17u16.to_be_bytes()); // option_size: 1 + 16
	opts.push(1u8); // OPTION_TYPE_LZRECEIVE
	opts.extend_from_slice(&gas.to_be_bytes()); // gas limit
	opts
}

/// Left-pad a 20-byte address to bytes32.
pub fn address_to_bytes32(addr: alloy_primitives::Address) -> alloy_primitives::FixedBytes<32> {
	let mut b = [0u8; 32];
	b[12..].copy_from_slice(addr.as_slice());
	alloy_primitives::FixedBytes(b)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_lz_receive_option_encoding() {
		let opts = build_lz_receive_option(200_000);
		assert_eq!(opts.len(), 22);
		// TYPE_3 prefix
		assert_eq!(&opts[0..2], &[0x00, 0x03]);
		// WORKER_ID
		assert_eq!(opts[2], 0x01);
		// option_size = 17
		assert_eq!(&opts[3..5], &[0x00, 0x11]);
		// OPTION_TYPE_LZRECEIVE
		assert_eq!(opts[5], 0x01);
		// gas = 200_000 in big-endian u128
		let gas_bytes = 200_000u128.to_be_bytes();
		assert_eq!(&opts[6..22], &gas_bytes);
	}

	#[test]
	fn test_address_to_bytes32() {
		let addr = alloy_primitives::Address::from([0xAB; 20]);
		let b32 = address_to_bytes32(addr);
		// First 12 bytes should be zero
		assert_eq!(&b32.0[..12], &[0u8; 12]);
		// Last 20 bytes should be the address
		assert_eq!(&b32.0[12..], &[0xAB; 20]);
	}
}
