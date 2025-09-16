use crate::costs::ProfitabilityCalculatable;
use crate::standards::eip7683::Eip7683OrderData;
use crate::{bytes32_to_address, parse_address, Address};
use alloy_primitives::U256;

/// EIP-7683 profitability calculator
pub struct Eip7683Calculator {
	pub order_data: Eip7683OrderData,
}

impl ProfitabilityCalculatable for Eip7683Calculator {
	fn input_assets(&self) -> Result<Vec<(Address, U256, u64)>, Box<dyn std::error::Error>> {
		let origin_chain_id = self.order_data.origin_chain_id.to::<u64>();
		let mut assets = Vec::new();

		for input in &self.order_data.inputs {
			let token_address_u256 = input[0];
			let amount = input[1];
			let token_u256_bytes = token_address_u256.to_be_bytes::<32>();
			let address_hex = bytes32_to_address(&token_u256_bytes);
			let token_address = parse_address(&address_hex)
				.map_err(|e| format!("Failed to parse input token address: {}", e))?;

			assets.push((token_address, amount, origin_chain_id));
		}

		Ok(assets)
	}

	fn output_assets(&self) -> Result<Vec<(Address, U256, u64)>, Box<dyn std::error::Error>> {
		let mut assets = Vec::new();

		for output in &self.order_data.outputs {
			let address_hex = bytes32_to_address(&output.token);
			let token_address = parse_address(&address_hex)
				.map_err(|e| format!("Failed to parse output token address: {}", e))?;
			let chain_id = output.chain_id.to::<u64>();

			assets.push((token_address, output.amount, chain_id));
		}

		Ok(assets)
	}
}
