//! Bounded quote-time live gas estimation.
//!
//! The synthetic fill transaction embeds a near-future `fillDeadline`, so raw
//! calldata is time-variant. Do not add a cache keyed on calldata without first
//! normalizing or bucketing that deadline.

use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Default)]
pub(crate) struct LiveEstimateController {
	chains: Mutex<HashMap<u64, Arc<Semaphore>>>,
}

impl LiveEstimateController {
	pub(crate) fn new() -> Self {
		Self::default()
	}

	pub(crate) fn try_acquire(
		&self,
		chain_id: u64,
		max_concurrent: usize,
	) -> Option<OwnedSemaphorePermit> {
		if max_concurrent == 0 {
			return None;
		}

		let semaphore = {
			let mut chains = self.chains.lock().expect("live estimate limiter poisoned");
			chains
				.entry(chain_id)
				.or_insert_with(|| Arc::new(Semaphore::new(max_concurrent)))
				.clone()
		};

		semaphore.try_acquire_owned().ok()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn zero_limit_rejects_without_creating_chain_limiter() {
		let controller = LiveEstimateController::new();

		assert!(controller.try_acquire(137, 0).is_none());
		assert!(controller
			.chains
			.lock()
			.expect("live estimate limiter poisoned")
			.is_empty());
	}

	#[test]
	fn saturated_chain_rejects_immediately() {
		let controller = LiveEstimateController::new();
		let _held = controller
			.try_acquire(137, 1)
			.expect("first permit should be available");

		assert!(controller.try_acquire(137, 1).is_none());
	}
}
