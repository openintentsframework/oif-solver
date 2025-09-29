/// Core module containing the essential components of the OIF Solver demonstration system.
///
/// This module provides the foundational infrastructure for managing cross-chain intent
/// resolution, including session management, contract interaction, deployment orchestration,
/// ABI handling, and comprehensive logging capabilities. The core module serves as the
/// central hub for coordinating all solver operations and managing the lifecycle of
/// cross-chain transactions.
///
/// The module is structured to provide clean separation of concerns, with each submodule
/// handling a specific aspect of the solver's functionality. This architecture enables
/// efficient orchestration of complex cross-chain operations while maintaining clear
/// boundaries between different system components.
/// Session management module for handling user sessions and state persistence.
///
/// Provides functionality for creating, maintaining, and managing user sessions
/// throughout the intent resolution process. This includes tracking session state,
/// managing session lifecycle, and coordinating session-related operations across
/// different components of the system.
pub mod session_manager;

/// Contract interaction and management module.
///
/// Handles all direct interactions with smart contracts across different blockchain
/// networks. This includes contract calls, state queries, transaction submission,
/// and response handling. The module abstracts away the complexities of multi-chain
/// contract interaction while providing a consistent interface for higher-level components.
pub mod contract_manager;

/// Deployment orchestration and management module.
///
/// Manages the deployment of smart contracts and related infrastructure across
/// multiple blockchain networks. This includes deployment planning, execution,
/// verification, and post-deployment configuration. The module ensures that all
/// required contracts are properly deployed and configured before intent resolution begins.
pub mod deployer_manager;

/// Application Binary Interface (ABI) management module.
///
/// Handles the loading, parsing, validation, and management of contract ABIs.
/// This module ensures that all contract interactions use the correct ABI definitions
/// and provides utilities for encoding and decoding contract calls according to
/// the appropriate interface specifications.
pub mod abi_manager;

/// Logging and progress visualization module.
///
/// Provides comprehensive logging capabilities including structured logging,
/// progress tracking, and visual feedback through tree-based displays.
/// This module enables detailed monitoring of solver operations and provides
/// rich visual feedback to users about the state of their intent resolution.
pub mod logging;

/// Re-export of the SessionManager struct for managing user sessions and state.
///
/// The SessionManager is responsible for creating and maintaining session context
/// throughout the lifecycle of intent resolution operations.
pub use session_manager::SessionManager;

/// Re-export of the ContractManager struct for handling smart contract interactions.
///
/// The ContractManager provides a unified interface for interacting with contracts
/// across multiple blockchain networks.
pub use contract_manager::ContractManager;

/// Re-export of the DeployerManager struct for orchestrating contract deployments.
///
/// The DeployerManager handles the complex process of deploying contracts across
/// multiple chains in a coordinated manner.
pub use deployer_manager::DeployerManager;

/// Re-export of the AbiManager struct for managing contract ABIs.
///
/// The AbiManager provides centralized ABI management and ensures correct
/// encoding/decoding of contract interactions.
pub use abi_manager::AbiManager;

/// Re-export of logging utilities and components.
///
/// Includes the initialization function for setting up the logging system,
/// the ProgressManager for tracking operation progress, DisplayUtils for
/// formatted output, and tree visualization components for hierarchical display.
pub use logging::{init_logging, DisplayUtils, ProgressManager, TreeItem, TreePosition};
