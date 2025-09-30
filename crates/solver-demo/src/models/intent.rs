use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
	pub from_chain: u64,
	pub to_chain: u64,
	pub from_token: Address,
	pub to_token: Address,
	pub amount: U256,
	pub recipient: Address,
	pub swap_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResult {
	pub order_id: String,
	pub quote: Quote,
	pub intent: Intent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
	pub id: String,
	pub price: String,
	pub amount_out: U256,
	pub expires_at: u64,
}
