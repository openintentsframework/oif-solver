//! Pricing oracle implementations for the OIF solver system.
//!
//! This module provides pricing oracle implementations for converting between
//! wei amounts and fiat currencies. Currently supports mock pricing for development.

use solver_types::{
	AssetPrice, ImplementationRegistry, PricingError, PricingFactory, PricingInterface,
};

/// Re-export implementations
pub mod implementations {
	pub mod mock;
}

/// Get all registered pricing implementations.
pub fn get_all_implementations() -> Vec<(&'static str, PricingFactory)> {
	use implementations::mock;

	vec![(
		mock::MockPricingRegistry::NAME,
		mock::MockPricingRegistry::factory(),
	)]
}

/// Service that manages asset pricing across the solver system.
pub struct PricingService {
	/// The primary pricing implementation.
	implementation: Box<dyn PricingInterface>,
}

impl PricingService {
	/// Creates a new PricingService with the specified implementation.
	pub fn new(implementation: Box<dyn PricingInterface>) -> Self {
		Self { implementation }
	}

	/// Gets the current price for an asset in the specified currency.
	pub async fn get_asset_price(
		&self,
		asset: &str,
		currency: &str,
	) -> Result<AssetPrice, PricingError> {
		self.implementation.get_asset_price(asset, currency).await
	}

	/// Converts a wei amount to the specified currency using current ETH price.
	pub async fn wei_to_currency(
		&self,
		wei_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		self.implementation
			.wei_to_currency(wei_amount, currency)
			.await
	}

	/// Converts a currency amount to wei using current ETH price.
	pub async fn currency_to_wei(
		&self,
		currency_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		self.implementation
			.currency_to_wei(currency_amount, currency)
			.await
	}
}
