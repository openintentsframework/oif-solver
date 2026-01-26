//! Configuration store implementations.
//!
//! This module provides concrete implementations of the ConfigStore trait
//! for different backends.

mod redis;
pub use redis::RedisConfigStore;
