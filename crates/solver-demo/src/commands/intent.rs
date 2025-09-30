use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::Subcommand;
use serde_json;
use solver_types::api::{
	AuthScheme, FailureHandlingMode, GetQuoteRequest, IntentRequest, IntentType, OriginMode,
	OriginSubmission, QuoteInput, QuoteOutput, QuotePreference, SwapType,
};
use solver_types::standards::eip7683::interfaces::StandardOrder;
use solver_types::standards::eip7930::InteropAddress;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::info;

use crate::core::{DisplayUtils, TreeItem};
use crate::services::{FileIndexer, IntentService};
use crate::utils::{parse_address, parse_amount_with_decimals};

#[derive(Debug, Subcommand)]
pub enum IntentCommands {
	/// Build an intent and save to file
	Build {
		/// Source chain ID
		#[arg(long)]
		from_chain: u64,

		/// Destination chain ID
		#[arg(long)]
		to_chain: u64,

		/// Source token symbol or address
		#[arg(long)]
		from_token: String,

		/// Destination token symbol or address
		#[arg(long)]
		to_token: String,

		/// Amount to swap (in whole units)
		#[arg(long)]
		amount: String,

		/// Swap type (exact-input or exact-output)
		#[arg(long, default_value = "exact-input")]
		swap_type: String,

		/// Recipient address (defaults to user)
		#[arg(long)]
		recipient: Option<String>,

		/// Settlement type (escrow or compact)
		#[arg(long, default_value = "escrow")]
		settlement: String,

		/// Auth mechanism for escrow (permit2 or eip3009)
		#[arg(long, default_value = "permit2")]
		auth: Option<String>,

		/// Output file path
		#[arg(short, long)]
		output: Option<PathBuf>,
	},

	/// Submit a signed order from file
	Submit {
		/// PostOrderRequest JSON file (post_order.req.json from 'quote sign')
		file: PathBuf,

		/// Submit directly on-chain instead of via API
		#[arg(long)]
		onchain: bool,

		/// Chain to submit on (required for on-chain submission)
		#[arg(long)]
		chain: Option<u64>,
	},

	/// Test multiple intents from a JSON file
	Test {
		/// JSON file containing test intents
		json_file: PathBuf,

		/// Use on-chain submission
		#[arg(long)]
		onchain: bool,
	},

	/// Check order status
	Status {
		/// Order ID
		intent_id: String,
	},

	/// List all orders
	List {
		/// Filter by status
		#[arg(long)]
		status: Option<String>,
	},
}

/// Handler for intent commands
pub struct IntentHandler {
	intent_service: Arc<IntentService>,
	display: Arc<DisplayUtils>,
	file_indexer: Option<Arc<FileIndexer>>,
}

impl IntentHandler {
	pub async fn new(intent_service: Arc<IntentService>) -> Result<Self> {
		let requests_dir = intent_service.session_manager.requests_dir();
		let file_indexer = FileIndexer::new(&requests_dir).await.ok().map(Arc::new);

		Ok(Self {
			intent_service,
			display: Arc::new(DisplayUtils::new()),
			file_indexer,
		})
	}

	pub async fn handle(&self, command: IntentCommands) -> Result<()> {
		match command {
			IntentCommands::Build {
				from_chain,
				to_chain,
				from_token,
				to_token,
				amount,
				swap_type,
				recipient,
				settlement,
				auth,
				output,
			} => {
				self.handle_build(
					from_chain, to_chain, from_token, to_token, amount, swap_type, recipient,
					settlement, auth, output,
				)
				.await
			},
			IntentCommands::Submit {
				file,
				onchain,
				chain,
			} => self.handle_submit(file, onchain, chain).await,
			_ => Err(anyhow!("Other intent commands not yet implemented")),
		}
	}

	#[allow(clippy::too_many_arguments)]
	async fn handle_build(
		&self,
		from_chain: u64,
		to_chain: u64,
		from_token: String,
		to_token: String,
		amount: String,
		swap_type: String,
		recipient: Option<String>,
		settlement: String,
		auth: Option<String>,
		output: Option<PathBuf>,
	) -> Result<()> {
		info!(
			"Building intent: {} {} -> {} {}",
			amount,
			from_token,
			to_token,
			if from_chain == to_chain {
				"same chain".to_string()
			} else {
				format!("chain {} -> {}", from_chain, to_chain)
			}
		);

		// Parse swap type
		let swap_type = match swap_type.as_str() {
			"exact-input" => SwapType::ExactInput,
			"exact-output" => SwapType::ExactOutput,
			_ => {
				return Err(anyhow!(
					"Invalid swap type: {}. Use 'exact-input' or 'exact-output'",
					swap_type
				));
			},
		};

		// Parse settlement type and determine supported order types and origin submission
		let (supported_types, origin_submission) = match settlement.as_str() {
			"escrow" => {
				// For escrow, use the auth parameter to determine the auth scheme
				let auth_scheme = match auth.as_deref().unwrap_or("permit2") {
					"permit2" => AuthScheme::Permit2,
					"eip3009" => AuthScheme::Eip3009,
					invalid => {
						return Err(anyhow!(
							"Invalid auth mechanism '{}'. Use 'permit2' or 'eip3009'",
							invalid
						));
					},
				};

				let order_type = match auth_scheme {
					AuthScheme::Permit2 => "oif-escrow-v0",
					AuthScheme::Eip3009 => "oif-3009-v0",
					_ => "oif-escrow-v0", // Default fallback
				};

				let origin_submission = OriginSubmission {
					mode: OriginMode::User,
					schemes: Some(vec![auth_scheme]),
				};

				(vec![order_type.to_string()], Some(origin_submission))
			},
			"compact" => {
				// For compact/resource lock, use resource lock order type
				(vec!["oif-resource-lock-v0".to_string()], None)
			},
			invalid => {
				return Err(anyhow!(
					"Invalid settlement type '{}'. Use 'escrow' or 'compact'",
					invalid
				));
			},
		};

		// Get session manager through intent service
		let session_manager = &self.intent_service.session_manager;

		// Resolve user account
		let user_account = session_manager.get_user_account().await;
		let user_address = user_account.address;

		// Resolve recipient (default to user)
		let recipient_address = if let Some(recipient_str) = recipient {
			parse_address(&recipient_str)?
		} else {
			user_address
		};

		// Resolve token addresses and get decimals
		let from_token_info = self
			.resolve_token_info(session_manager, from_chain, &from_token)
			.await?;
		let to_token_info = self
			.resolve_token_info(session_manager, to_chain, &to_token)
			.await?;

		// Format amount with proper decimals based on swap type
		let formatted_amount = match swap_type {
			SwapType::ExactInput => {
				// Use from_token decimals for exact input
				let amount_u256 = parse_amount_with_decimals(&amount, from_token_info.decimals)?;
				amount_u256.to_string()
			},
			SwapType::ExactOutput => {
				// Use to_token decimals for exact output
				let amount_u256 = parse_amount_with_decimals(&amount, to_token_info.decimals)?;
				amount_u256.to_string()
			},
		};

		// Create InteropAddress objects
		let user_interop = InteropAddress::new_ethereum(from_chain, user_address);
		let recipient_interop = InteropAddress::new_ethereum(to_chain, recipient_address);
		let from_asset_interop =
			InteropAddress::new_ethereum(from_chain, parse_address(&from_token_info.address)?);
		let to_asset_interop =
			InteropAddress::new_ethereum(to_chain, parse_address(&to_token_info.address)?);

		// Create QuoteInput and QuoteOutput
		let input = QuoteInput {
			user: user_interop.clone(),
			asset: from_asset_interop,
			amount: if matches!(swap_type, SwapType::ExactInput) {
				Some(formatted_amount.clone())
			} else {
				None
			},
			lock: None,
		};

		let quote_output = QuoteOutput {
			receiver: recipient_interop,
			asset: to_asset_interop,
			amount: if matches!(swap_type, SwapType::ExactOutput) {
				Some(formatted_amount.clone())
			} else {
				None
			},
			calldata: None,
		};

		// Create IntentRequest
		let intent_request = IntentRequest {
			intent_type: IntentType::OifSwap,
			inputs: vec![input],
			outputs: vec![quote_output],
			swap_type: Some(swap_type.clone()),
			min_valid_until: Some((chrono::Utc::now().timestamp() as u64) + 60),
			preference: Some(QuotePreference::Speed),
			origin_submission,
			failure_handling: Some(vec![FailureHandlingMode::RefundAutomatic]),
			partial_fill: Some(false),
			metadata: None,
		};

		// Create GetQuoteRequest
		let quote_request = GetQuoteRequest {
			user: user_interop,
			intent: intent_request,
			supported_types,
		};

		// Determine output files with sequential indexing
		let requests_dir = session_manager.requests_dir();

		// Get index for the file
		let index = if let Some(indexer) = &self.file_indexer {
			indexer.next_index("intent").await?
		} else {
			Utc::now().timestamp() as u64
		};

		// Generate get_quote.req.json
		let quote_request_file = if let Some(output_path) = output {
			output_path
		} else {
			requests_dir.join(format!("{}.get_quote.req.json", index))
		};

		// Ensure directory exists
		if let Some(parent) = quote_request_file.parent() {
			fs::create_dir_all(parent).await?;
		}

		// Save the get_quote request
		let json = serde_json::to_string_pretty(&quote_request)?;
		fs::write(&quote_request_file, json).await?;

		// Display results
		self.display.header("Quote Request Built Successfully");

		self.display.tree(
			"Intent Details",
			vec![
				TreeItem::KeyValue("From Chain".to_string(), from_chain.to_string()),
				TreeItem::KeyValue("To Chain".to_string(), to_chain.to_string()),
				TreeItem::KeyValue(
					"From Token".to_string(),
					format!(
						"{} ({}, {} decimals)",
						from_token, from_token_info.address, from_token_info.decimals
					),
				),
				TreeItem::KeyValue(
					"To Token".to_string(),
					format!(
						"{} ({}, {} decimals)",
						to_token, to_token_info.address, to_token_info.decimals
					),
				),
				TreeItem::KeyValue(
					"Amount".to_string(),
					format!("{} (formatted: {})", amount, formatted_amount),
				),
				TreeItem::KeyValue("Swap Type".to_string(), format!("{:?}", swap_type)),
				TreeItem::KeyValue("Settlement".to_string(), settlement),
				TreeItem::KeyValue(
					"Auth".to_string(),
					auth.unwrap_or_else(|| "N/A".to_string()),
				),
				TreeItem::KeyValue("User".to_string(), user_account.address.to_string()),
				TreeItem::KeyValue("Recipient".to_string(), format!("{:?}", recipient_address)),
			],
		);

		self.display
			.success(&format!("Intent saved to: {:?}", quote_request_file));

		self.display.next_steps(vec![&format!(
			"Run: oif-demo quote get {:?}",
			quote_request_file
		)]);

		Ok(())
	}

	async fn handle_submit(&self, file: PathBuf, onchain: bool, chain: Option<u64>) -> Result<()> {
		info!("Submitting order from file: {:?}", file);

		if onchain {
			// For onchain submission, we submit directly to the blockchain
			return self.handle_onchain_submit(file, chain).await;
		}

		// Load the PostOrderRequest from file
		let content = fs::read_to_string(&file)
			.await
			.map_err(|e| anyhow!("Failed to read order file: {}", e))?;

		// Parse the new PostOrderRequest structure
		let post_order_json: serde_json::Value = serde_json::from_str(&content)
			.map_err(|e| anyhow!("Failed to parse PostOrderRequest JSON: {}", e))?;

		// Build PostOrderRequest from JSON
		let order_json = &post_order_json["order"];
		let signature = post_order_json["signature"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing signature in PostOrderRequest"))?;
		let quote_id = post_order_json["quoteId"].as_str().map(|s| s.to_string());
		let origin_submission = post_order_json["originSubmission"]
			.as_object()
			.and_then(|o| serde_json::from_value(serde_json::Value::Object(o.clone())).ok());

		// Parse OifOrder from the order field
		let oif_order: solver_types::api::OifOrder = serde_json::from_value(order_json.clone())
			.map_err(|e| anyhow!("Failed to parse OifOrder: {}", e))?;

		// Create PostOrderRequest with new structure
		let post_order_request = solver_types::api::PostOrderRequest {
			order: oif_order,
			signature: vec![alloy_primitives::Bytes::from(
				hex::decode(signature.trim_start_matches("0x"))
					.map_err(|e| anyhow!("Invalid signature hex: {}", e))?,
			)],
			quote_id,
			origin_submission,
		};

		// Submit to API
		info!("Submitting order to solver API");

		let response = self
			.intent_service
			.api_client
			.post_intent(post_order_request)
			.await
			.map_err(|e| anyhow!("Failed to submit order to API: {}", e))?;

		// Get current index for response file
		let current_index = if let Some(indexer) = &self.file_indexer {
			indexer.current_index("post_order").await
		} else {
			Utc::now().timestamp() as u64
		};

		// Save response
		let requests_dir = self.intent_service.session_manager.requests_dir();
		let response_file = requests_dir.join(format!("{}.post_order.res.json", current_index));

		if let Some(parent) = response_file.parent() {
			fs::create_dir_all(parent).await?;
		}
		let json = serde_json::to_string_pretty(&response)?;
		fs::write(&response_file, json).await?;

		// Display results
		self.display.header("Order Submission Result");

		// Check response status
		let status_str = match response.status {
			solver_types::api::PostOrderResponseStatus::Received => "Order received successfully",
			solver_types::api::PostOrderResponseStatus::Rejected => "Order was rejected",
			solver_types::api::PostOrderResponseStatus::Error => "Error submitting order",
		};

		if response.status == solver_types::api::PostOrderResponseStatus::Received {
			self.display.success(status_str);
		} else {
			self.display.error(status_str);
		}

		// Display order details
		let mut details = vec![
			TreeItem::KeyValue("Status".to_string(), format!("{:?}", response.status)),
			TreeItem::KeyValue(
				"Response saved".to_string(),
				response_file.display().to_string(),
			),
		];

		if let Some(order_id) = &response.order_id {
			details.insert(
				1,
				TreeItem::KeyValue("Order ID".to_string(), order_id.clone()),
			);
		}

		if let Some(message) = &response.message {
			details.push(TreeItem::KeyValue("Message".to_string(), message.clone()));
		}

		self.display.tree("Submission Details", details);

		self.display.next_steps(vec![
			"Check order status: oif-demo intent status <order_id>",
			"View balances: oif-demo balance all",
		]);

		Ok(())
	}

	async fn handle_onchain_submit(&self, file: PathBuf, chain: Option<u64>) -> Result<()> {
		info!("Submitting order onchain from file: {:?}", file);

		// Load the PostOrderRequest from file
		let content = fs::read_to_string(&file)
			.await
			.map_err(|e| anyhow!("Failed to read order file: {}", e))?;

		let post_order_json: serde_json::Value = serde_json::from_str(&content)
			.map_err(|e| anyhow!("Failed to parse PostOrderRequest: {}. Make sure this is a post_order.req.json file generated by 'quote sign'", e))?;

		// Extract order data and convert to StandardOrder
		// First parse as OifOrder, then convert to StandardOrder
		let order_json = &post_order_json["order"];
		let oif_order: solver_types::api::OifOrder = serde_json::from_value(order_json.clone())
			.map_err(|e| anyhow!("Failed to parse order as OifOrder: {}", e))?;

		// Convert OifOrder to StandardOrder
		let standard_order = StandardOrder::try_from(&oif_order)
			.map_err(|e| anyhow!("Failed to convert OifOrder to StandardOrder: {}", e))?;

		// Determine the chain to submit to
		// Convert U256 to u64
		let submit_chain = chain.unwrap_or(
			standard_order
				.originChainId
				.try_into()
				.map_err(|_| anyhow!("Chain ID too large to convert to u64"))?,
		);

		// Get user account and private key
		let user_account = self.intent_service.session_manager.get_user_account().await;
		let user_private_key = (self.intent_service.session_manager.get_user_account().await)
			.private_key
			.ok_or(anyhow!(
				"User private key not configured for onchain submission"
			))?;

		// Get the input settler address for the chain from contracts
		let contract_addresses = self
			.intent_service
			.session_manager
			.get_contract_addresses(submit_chain)
			.await
			.ok_or_else(|| anyhow!("No contract addresses found for chain {}", submit_chain))?;

		let input_settler_str = contract_addresses
			.input_settler
			.ok_or_else(|| anyhow!("InputSettler not deployed on chain {}", submit_chain))?;

		let input_settler = alloy_primitives::Address::from_slice(
			&hex::decode(input_settler_str.trim_start_matches("0x"))
				.map_err(|e| anyhow!("Invalid input settler address: {}", e))?,
		);

		// Get RPC URL for the chain
		let rpc_url = self
			.intent_service
			.session_manager
			.get_rpc_url(submit_chain)
			.await
			.ok_or_else(|| anyhow!("Failed to get RPC URL for chain {}", submit_chain))?;

		// Extract input token info from the order
		// The inputs field is an array of [U256; 2] where each element contains [token_address, amount]
		let input_data = standard_order
			.inputs
			.first()
			.ok_or_else(|| anyhow!("No input tokens in order"))?;

		// Parse the input data: first U256 is token address, second is amount
		let input_token =
			alloy_primitives::Address::from_slice(&input_data[0].to_be_bytes::<32>()[12..]);
		let input_amount = input_data[1];

		// Display submission details
		self.display.header("Onchain Order Submission");

		self.display.tree(
			"Submission Details",
			vec![
				TreeItem::KeyValue("Chain".to_string(), submit_chain.to_string()),
				TreeItem::KeyValue("User".to_string(), user_account.address.to_string()),
				TreeItem::KeyValue("Input Settler".to_string(), format!("{:?}", input_settler)),
				TreeItem::KeyValue("Input Token".to_string(), format!("{:?}", input_token)),
				TreeItem::KeyValue("Input Amount".to_string(), input_amount.to_string()),
			],
		);

		// Step 1: Approve tokens for InputSettler
		self.display
			.info("Step 1: Approving tokens for InputSettler...");

		let approve_result = self
			.intent_service
			.contract_manager
			.approve_tokens(
				input_token,
				input_settler,
				input_amount,
				&user_private_key,
				&rpc_url,
			)
			.await;

		match approve_result {
			Ok(tx_hash) => {
				self.display
					.success(&format!("Token approval submitted (tx: {})", tx_hash));
			},
			Err(e) => {
				return Err(anyhow!("Failed to approve tokens: {}", e));
			},
		}

		// Step 2: Submit intent to InputSettler
		self.display
			.info("Step 2: Submitting intent to InputSettler...");

		let submit_result = self
			.intent_service
			.contract_manager
			.submit_intent_onchain(input_settler, &standard_order, &user_private_key, &rpc_url)
			.await;

		match submit_result {
			Ok(tx_hash) => {
				self.display.success(&format!(
					"Intent submitted onchain successfully (tx: {})",
					tx_hash
				));

				// Save transaction details
				let requests_dir = self.intent_service.session_manager.requests_dir();
				let tx_file = requests_dir.join(format!("onchain_tx_{}.json", tx_hash));

				let tx_details = serde_json::json!({
					"transaction_hash": tx_hash,
					"chain_id": submit_chain,
					"user": user_account.address.to_string(),
					"input_settler": format!("{:?}", input_settler),
					"timestamp": chrono::Utc::now().to_rfc3339(),
				});

				if let Some(parent) = tx_file.parent() {
					fs::create_dir_all(parent).await?;
				}
				let json = serde_json::to_string_pretty(&tx_details)?;
				fs::write(&tx_file, json).await?;

				self.display
					.info(&format!("Transaction details saved to: {:?}", tx_file));

				self.display.next_steps(vec![
					&format!(
						"Monitor transaction: cast receipt {} --rpc-url {}",
						tx_hash, rpc_url
					),
					"View balances: oif-demo balance all",
				]);
			},
			Err(e) => {
				return Err(anyhow!("Failed to submit intent onchain: {}", e));
			},
		}

		Ok(())
	}

	async fn resolve_token_info(
		&self,
		session_manager: &crate::core::SessionManager,
		chain_id: u64,
		token: &str,
	) -> Result<crate::models::TokenInfo> {
		// Try to parse as address first
		if parse_address(token).is_ok() {
			// If it's an address, we need to query the contract for decimals
			// For now, return an error asking user to use token symbols instead
			return Err(anyhow!(
				"Token addresses not yet supported. Please use token symbols (e.g., USDC, WETH) instead of addresses for chain {}",
				chain_id
			));
		}

		// Resolve as symbol using get_token_info
		session_manager
			.get_token_info(chain_id, token)
			.await
			.map_err(|e| {
				anyhow!(
					"Failed to resolve token '{}' on chain {}: {}",
					token,
					chain_id,
					e
				)
			})
	}
}
