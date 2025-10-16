//! Router integrations for quote generation.
//!
//! This module provides integrations with DEX routing services to enable
//! automated swap routing for cross-chain transfers.

pub mod uniswap;
pub mod uniswap_v3_onchain;

#[cfg(test)]
mod uniswap_tests;

