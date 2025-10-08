//! CLI command definitions and argument parsing
//!
//! This module contains the command-line argument structures for each
//! major CLI subcommand including initialization, environment management,
//! token operations, account handling, intent processing, and quote generation.

mod account;
mod config;
mod env;
mod init;
mod intent;
mod quote;
mod token;

pub use account::{AccountCommand, AccountSubcommand};
pub use config::ConfigCommand;
pub use env::{EnvCommand, EnvSubcommand};
pub use init::{InitCommand, InitSubcommand};
pub use intent::{IntentCommand, IntentSubcommand};
pub use quote::{QuoteCommand, QuoteSubcommand};
pub use token::{TokenCommand, TokenSubcommand};
