//! Core application services and components
//!
//! This module contains the fundamental building blocks of the solver demo
//! including API clients, blockchain providers, configuration management,
//! contract handling, JWT services, session storage, signing services,
//! and token registries.

pub mod api;
pub mod blockchain;
pub mod config;
pub mod contracts;
pub mod jwt;
pub mod logging;
pub mod session;
pub mod signing;
pub mod storage;
pub mod tokens;

pub use api::ApiClient;
pub use blockchain::{Provider, TxBuilder};
pub use config::Config;
pub use contracts::Contracts;
pub use jwt::JwtService;
pub use session::SessionStore;
pub use signing::SigningService;
pub use storage::Storage;
pub use tokens::TokenRegistry;
