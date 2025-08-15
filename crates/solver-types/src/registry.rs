//! Registry trait for self-registering implementations.
//!
//! This module provides the base trait that all solver implementations must implement
//! to register themselves with their configuration name and factory function.

/// Base trait for implementation registries.
///
/// Each implementation module (Storage, Discovery, Account, etc.) must provide
/// a Registry struct that implements this trait. This ensures that every implementation
/// declares its configuration name and provides a factory function.
pub trait ImplementationRegistry {
	/// The name used in configuration files to reference this implementation.
	///
	/// This should match the key used in the TOML configuration, for example:
	/// - "onchain_eip7683" for discovery.implementations.onchain_eip7683
	/// - "memory" for storage.implementations.memory
	/// - "local" for account.implementation = "local"
	const NAME: &'static str;

	/// The factory function type this implementation provides.
	///
	/// Each module defines its own factory type, for example:
	/// - DiscoveryFactory for discovery implementations
	/// - StorageFactory for storage implementations
	type Factory;

	/// Get the factory function for this implementation.
	///
	/// Returns the factory function that can create instances of this implementation
	/// when provided with the appropriate configuration.
	fn factory() -> Self::Factory;
}
