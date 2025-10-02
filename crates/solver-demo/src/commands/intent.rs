use anyhow::{anyhow, Result};
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
use crate::services::IntentService;
use crate::utils::{parse_address, parse_address_or_identifier, parse_amount_with_decimals};

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
		order_id: String,
	},

	/// Build multiple intents from a batch specification file
	BuildBatch {
		/// JSON file containing batch intent specifications
		input: PathBuf,

		/// Output file path (defaults to get_quotes.req.json)
		#[arg(short, long)]
		output: Option<PathBuf>,
	},
}

/// Handler for intent commands
pub struct IntentHandler {
	intent_service: Arc<IntentService>,
	display: Arc<DisplayUtils>,
}

impl IntentHandler {
	pub async fn new(intent_service: Arc<IntentService>) -> Result<Self> {
		Ok(Self {
			intent_service,
			display: Arc::new(DisplayUtils::new()),
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
			IntentCommands::Test { json_file, onchain } => {
				self.handle_test(json_file, onchain).await
			},
			IntentCommands::Status { order_id } => self.handle_status(order_id).await,
			IntentCommands::BuildBatch { input, output } => {
				self.handle_build_batch(input, output).await
			},
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
			parse_address_or_identifier(&recipient_str, session_manager).await?
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
			lock: if settlement == "compact" {
				Some(solver_types::api::AssetLockReference {
					kind: solver_types::api::LockKind::TheCompact,
					params: None,
				})
			} else {
				None
			},
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
			min_valid_until: Some((chrono::Utc::now().timestamp() as u64) + 300),
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

		// Generate get_quote.req.json - always override
		let quote_request_file = if let Some(output_path) = output {
			output_path
		} else {
			requests_dir.join("get_quote.req.json")
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

		// Handle signature - it should be a single string
		let signature = if let Some(sig_str) = post_order_json["signature"].as_str() {
			if sig_str.is_empty() {
				return Err(anyhow!(
					"Signature is empty. Please sign the quote first using 'oif-demo quote sign'"
				));
			}
			alloy_primitives::Bytes::from(
				hex::decode(sig_str.trim_start_matches("0x"))
					.map_err(|e| anyhow!("Invalid signature hex: {}", e))?,
			)
		} else {
			return Err(anyhow!(
				"Missing or invalid signature in PostOrderRequest. Please sign the quote first using 'oif-demo quote sign'"
			));
		};

		let quote_id = post_order_json["quoteId"].as_str().map(|s| s.to_string());
		let origin_submission = post_order_json["originSubmission"]
			.as_object()
			.and_then(|o| serde_json::from_value(serde_json::Value::Object(o.clone())).ok());

		// Parse OifOrder from the order field
		let oif_order: solver_types::api::OifOrder = serde_json::from_value(order_json.clone())
			.map_err(|e| anyhow!("Failed to parse OifOrder: {}", e))?;

		// Check if this is a resource lock order and deposit to TheCompact if needed
		if matches!(
			&oif_order,
			solver_types::api::OifOrder::OifResourceLockV0 { .. }
		) {
			info!("Resource lock order detected - depositing to TheCompact first");

			// Convert to StandardOrder to extract details
			let standard_order =
				solver_types::standards::eip7683::interfaces::StandardOrder::try_from(&oif_order)
					.map_err(|e| anyhow!("Failed to convert to StandardOrder: {}", e))?;

			// Get chain ID and convert U256 to u64
			let chain_id: u64 = standard_order
				.originChainId
				.try_into()
				.map_err(|_| anyhow!("Chain ID too large to convert to u64"))?;

			// Get contract addresses
			let contract_addresses = self
				.intent_service
				.session_manager
				.get_contract_addresses(chain_id)
				.await
				.ok_or_else(|| anyhow!("No contract addresses found for chain {}", chain_id))?;

			// Get TheCompact address
			let the_compact_str = contract_addresses
				.compact
				.ok_or_else(|| anyhow!("TheCompact not deployed on chain {}", chain_id))?;

			let the_compact = alloy_primitives::Address::from_slice(
				&hex::decode(the_compact_str.trim_start_matches("0x"))
					.map_err(|e| anyhow!("Invalid TheCompact address: {}", e))?,
			);

			// Extract input token and amount
			let input_data = standard_order
				.inputs
				.first()
				.ok_or_else(|| anyhow!("No input tokens in order"))?;

			let input_token =
				alloy_primitives::Address::from_slice(&input_data[0].to_be_bytes::<32>()[12..]);
			let input_amount = input_data[1];

			// Get user details
			let user_account = self.intent_service.session_manager.get_user_account().await;
			let user_private_key = user_account
				.private_key
				.ok_or(anyhow!("User private key not configured"))?;

			// Get RPC URL
			let rpc_url = self
				.intent_service
				.session_manager
				.get_rpc_url(chain_id)
				.await
				.ok_or_else(|| anyhow!("Failed to get RPC URL for chain {}", chain_id))?;

			self.display
				.info("Preparing resource lock: Approving tokens for TheCompact...");

			// Step 1: Approve tokens for TheCompact
			self.intent_service
				.contract_manager
				.approve_tokens(
					input_token,
					the_compact,
					input_amount,
					&user_private_key,
					&rpc_url,
				)
				.await
				.map_err(|e| anyhow!("Failed to approve tokens for TheCompact: {}", e))?;

			self.display.success("Token approval complete");
			self.display.info("Depositing tokens to TheCompact...");

			// Step 2: Deposit tokens to TheCompact
			// Get allocator address to derive the lock tag
			let allocator_str = contract_addresses
				.allocator
				.ok_or_else(|| anyhow!("Allocator not deployed on chain {}", chain_id))?;

			let allocator_address = alloy_primitives::Address::from_slice(
				&hex::decode(allocator_str.trim_start_matches("0x"))
					.map_err(|e| anyhow!("Invalid allocator address: {}", e))?,
			);

			// Generate allocator lock tag from allocator address
			// Lock tag = 0x00 + last 11 bytes of allocator address
			let mut allocator_lock_tag = [0u8; 12];
			allocator_lock_tag[0] = 0x00; // First byte is 0x00
								 // Copy last 11 bytes of allocator address (bytes 9-19 of the 20-byte address)
			allocator_lock_tag[1..].copy_from_slice(&allocator_address.as_slice()[9..]);

			let deposit_tx = self
				.intent_service
				.contract_manager
				.deposit_to_compact(
					the_compact,
					input_token,
					allocator_lock_tag,
					input_amount,
					user_account.address, // recipient is the user
					&user_private_key,
					&rpc_url,
				)
				.await
				.map_err(|e| anyhow!("Failed to deposit tokens to TheCompact: {}", e))?;

			self.display.success(&format!(
				"Tokens deposited to TheCompact (tx: {})",
				deposit_tx
			));
		}

		// Create PostOrderRequest with new structure
		let post_order_request = solver_types::api::PostOrderRequest {
			order: oif_order,
			signature,
			quote_id,
			origin_submission,
		};

		// Submit to API
		let response = self
			.intent_service
			.api_client
			.post_intent(post_order_request)
			.await
			.map_err(|e| anyhow!("Failed to submit order to API: {}", e))?;

		// Save response - always override
		let requests_dir = self.intent_service.session_manager.requests_dir();
		let response_file = requests_dir.join("post_order.res.json");

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
			"View balances: oif-demo balance",
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

		// Get user account first as we need it for the conversion
		let user_account = self.intent_service.session_manager.get_user_account().await;

		// Extract order data and inject user field for onchain submission
		let mut order_json = post_order_json["order"].clone();

		// For onchain submission, we need to inject the user field into the EIP-712 message
		// This is normally done by signature recovery in the API, but for onchain we do it here
		if let Some(payload) = order_json.get_mut("payload") {
			if let Some(message) = payload.get_mut("message") {
				if let Some(message_obj) = message.as_object_mut() {
					// Inject the user field that would normally come from signature recovery
					message_obj.insert(
						"user".to_string(),
						serde_json::Value::String(crate::utils::address::to_checksum_address(
							&user_account.address,
							chain,
						)),
					);
				}
			}
		}

		// Parse as OifOrder with the injected user field
		let oif_order: solver_types::api::OifOrder = serde_json::from_value(order_json)
			.map_err(|e| anyhow!("Failed to parse order as OifOrder: {}", e))?;

		// Determine the contract type based on the order type
		let contract_type = match &oif_order {
			solver_types::api::OifOrder::OifEscrowV0 { .. } => "InputSettlerEscrow",
			solver_types::api::OifOrder::Oif3009V0 { .. } => "InputSettlerEscrow", // EIP-3009 also uses escrow settler
			solver_types::api::OifOrder::OifResourceLockV0 { .. } => "InputSettlerCompact",
			_ => return Err(anyhow!("Unsupported order type for onchain submission")),
		};
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
		// Get user private key
		let user_private_key = user_account.private_key.ok_or(anyhow!(
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
			.submit_intent_onchain(
				input_settler,
				&standard_order,
				&user_private_key,
				&rpc_url,
				contract_type,
			)
			.await;

		match submit_result {
			Ok(tx_hash) => {
				self.display.success(&format!(
					"Intent submitted onchain successfully (tx: {})",
					tx_hash
				));

				// Save transaction details - always override
				let requests_dir = self.intent_service.session_manager.requests_dir();
				let tx_file = requests_dir.join("onchain_tx.json");

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
					&format!("Monitor the transaction: {}", tx_hash),
					"View balances: oif-demo balance",
				]);
			},
			Err(e) => {
				return Err(anyhow!("Failed to submit intent onchain: {}", e));
			},
		}

		Ok(())
	}

	async fn handle_test(&self, json_file: PathBuf, onchain: bool) -> Result<()> {
		info!("Testing multiple intents from file: {:?}", json_file);

		if onchain {
			return Err(anyhow!("Onchain batch testing not yet implemented"));
		}

		// Use the intent service test_batch method
		let results = match self
			.intent_service
			.test_batch(json_file.clone(), None)
			.await
		{
			Ok(results) => results,
			Err(e) => {
				// Check if this is a parsing error that might indicate wrong file type
				if e.to_string()
					.contains("Failed to parse input file as array of PostOrderRequest")
				{
					return Err(anyhow!(
						"Failed to parse '{}' as array of PostOrderRequest.\n\n\
						This command expects signed orders (post_orders.req.json).\n\n\
						If you have a batch intent specification file (batch_intents.json), use this workflow:\n\
						1. oif-demo intent build-batch batch_intents.json  # Creates get_quotes.req.json\n\
						2. oif-demo quote test get_quotes.req.json         # Creates post_orders.req.json\n\
						3. oif-demo intent test post_orders.req.json       # Submits signed orders\n\n\
						Original error: {}",
						json_file.display(),
						e
					));
				}
				return Err(e);
			},
		};

		// Display results similar to quote test
		self.display.header("Batch Intent Test Results");

		let stats = &results.statistics;
		self.display.tree(
			"Statistics",
			vec![
				TreeItem::KeyValue("Total Tests".to_string(), stats.total.to_string()),
				TreeItem::KeyValue("Successful".to_string(), stats.successful.to_string()),
				TreeItem::KeyValue("Failed".to_string(), stats.failed.to_string()),
				TreeItem::KeyValue(
					"Success Rate".to_string(),
					format!(
						"{:.1}%",
						if stats.total > 0 {
							(stats.successful as f64 / stats.total as f64) * 100.0
						} else {
							0.0
						}
					),
				),
				TreeItem::KeyValue(
					"Avg Response Time".to_string(),
					format!("{:.2}ms", stats.avg_response_time_ms),
				),
				TreeItem::KeyValue(
					"Total Duration".to_string(),
					format!("{}ms", stats.total_duration_ms),
				),
			],
		);

		// Display failed requests if any
		let failed_results: Vec<_> = results
			.results
			.iter()
			.enumerate()
			.filter(|(_, r)| matches!(r.status, crate::models::IntentTestStatus::Failed))
			.collect();

		if !failed_results.is_empty() {
			self.display.tree(
				"Failed Requests",
				failed_results
					.iter()
					.map(|(i, result)| {
						TreeItem::KeyValue(
							format!("Request {}", i + 1),
							result
								.error
								.as_ref()
								.unwrap_or(&"Unknown error".to_string())
								.clone(),
						)
					})
					.collect(),
			);
		}

		self.display
			.info(&format!("Results saved to: {:?}", results.file_path));

		Ok(())
	}

	async fn handle_status(&self, intent_id: String) -> Result<()> {
		info!("Getting status for intent: {}", intent_id);

		// Use the API client to get order status
		let status = self
			.intent_service
			.api_client
			.get_order_status(&intent_id)
			.await?;

		self.display.header("Intent Status");

		// Format timestamps
		let created_at = chrono::DateTime::from_timestamp(status.created_at as i64, 0)
			.map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
			.unwrap_or_else(|| status.created_at.to_string());

		let updated_at = chrono::DateTime::from_timestamp(status.updated_at as i64, 0)
			.map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
			.unwrap_or_else(|| status.updated_at.to_string());

		let mut status_details = vec![
			TreeItem::KeyValue("Order ID".to_string(), status.order_id),
			TreeItem::KeyValue("Status".to_string(), status.status.clone()),
			TreeItem::KeyValue("Created".to_string(), created_at),
			TreeItem::KeyValue("Updated".to_string(), updated_at),
		];

		if let Some(quote_id) = &status.quote_id {
			status_details.push(TreeItem::KeyValue("Quote ID".to_string(), quote_id.clone()));
		}

		if let Some(tx_hash) = &status.tx_hash {
			status_details.push(TreeItem::KeyValue(
				"Transaction".to_string(),
				tx_hash.clone(),
			));
		}

		self.display.tree("Order Details", status_details);

		// Show input/output amounts
		let amount_details = vec![
			TreeItem::KeyValue("Input Token".to_string(), status.input_amount.asset.clone()),
			TreeItem::KeyValue(
				"Input Amount".to_string(),
				status.input_amount.amount.to_string(),
			),
			TreeItem::KeyValue(
				"Output Token".to_string(),
				status.output_amount.asset.clone(),
			),
			TreeItem::KeyValue(
				"Output Amount".to_string(),
				status.output_amount.amount.to_string(),
			),
		];

		self.display.tree("Asset Details", amount_details);

		// Color-coded status display
		match status.status.to_lowercase().as_str() {
			"completed" | "success" | "filled" => {
				self.display.success("Order completed successfully");
			},
			"pending" | "processing" | "submitted" => {
				self.display.info("Order is being processed");
			},
			"failed" | "rejected" | "error" => {
				self.display.error("Order failed or was rejected");
			},
			_ => {
				self.display
					.info(&format!("Order status: {}", status.status));
			},
		}

		if status.tx_hash.is_some() {
			self.display.next_steps(vec![
				"Check transaction on block explorer",
				"Verify balances: oif-demo token balance",
			]);
		}

		Ok(())
	}

	async fn handle_build_batch(&self, input: PathBuf, output: Option<PathBuf>) -> Result<()> {
		info!("Building batch intents from file: {:?}", input);

		// Read and parse the batch specification file
		let content = fs::read_to_string(&input)
			.await
			.map_err(|e| anyhow!("Failed to read input file: {}", e))?;

		let batch_spec: crate::models::BatchIntentSpec = serde_json::from_str(&content)
			.map_err(|e| anyhow!("Failed to parse batch specification: {}", e))?;

		if batch_spec.intents.is_empty() {
			return Err(anyhow!("No intents found in specification file"));
		}

		let session_manager = &self.intent_service.session_manager;
		let user_account = session_manager.get_user_account().await;
		let user_address = user_account.address;

		let mut quote_requests = Vec::new();
		let mut skipped_count = 0;

		// Process each intent specification
		for (index, spec) in batch_spec.intents.iter().enumerate() {
			if !spec.enabled {
				info!(
					"Skipping disabled intent {}: {:?}",
					index + 1,
					spec.description
				);
				skipped_count += 1;
				continue;
			}

			info!("Processing intent {}: {:?}", index + 1, spec.description);

			// Determine swap type and amount
			let (swap_type, amount) =
				if spec.amounts.input.is_some() && spec.amounts.output.is_some() {
					return Err(anyhow!(
						"Intent {} specifies both input and output amounts. Please specify only one.",
						index + 1
					));
				} else if let Some(input_amount) = &spec.amounts.input {
					(
						solver_types::api::SwapType::ExactInput,
						input_amount.clone(),
					)
				} else if let Some(output_amount) = &spec.amounts.output {
					(
						solver_types::api::SwapType::ExactOutput,
						output_amount.clone(),
					)
				} else {
					return Err(anyhow!(
						"Intent {} must specify either input or output amount",
						index + 1
					));
				};

			// Resolve recipient
			let recipient_address = if let Some(recipient_str) = &spec.recipient {
				parse_address_or_identifier(recipient_str, session_manager).await?
			} else {
				user_address
			};

			// Parse settlement and auth
			let settlement = spec.settlement.as_deref().unwrap_or("escrow");
			let auth = spec.auth.as_deref().unwrap_or("permit2");

			// Determine supported types and origin submission
			let (supported_types, origin_submission) = match settlement {
				"escrow" => {
					let auth_scheme = match auth {
						"permit2" => solver_types::api::AuthScheme::Permit2,
						"eip3009" => solver_types::api::AuthScheme::Eip3009,
						invalid => {
							return Err(anyhow!(
								"Invalid auth mechanism '{}' for intent {}. Use 'permit2' or 'eip3009'",
								invalid,
								index + 1
							));
						},
					};

					let order_type = match auth_scheme {
						solver_types::api::AuthScheme::Permit2 => "oif-escrow-v0",
						solver_types::api::AuthScheme::Eip3009 => "oif-3009-v0",
						_ => "oif-escrow-v0",
					};

					let origin_submission = solver_types::api::OriginSubmission {
						mode: solver_types::api::OriginMode::User,
						schemes: Some(vec![auth_scheme]),
					};

					(vec![order_type.to_string()], Some(origin_submission))
				},
				"compact" => (vec!["oif-resource-lock-v0".to_string()], None),
				invalid => {
					return Err(anyhow!(
						"Invalid settlement type '{}' for intent {}. Use 'escrow' or 'compact'",
						invalid,
						index + 1
					));
				},
			};

			// Format amount based on decimals and swap type
			let formatted_amount = match swap_type {
				solver_types::api::SwapType::ExactInput => {
					parse_amount_with_decimals(&amount, spec.origin_token.decimals)?
				},
				solver_types::api::SwapType::ExactOutput => {
					parse_amount_with_decimals(&amount, spec.dest_token.decimals)?
				},
			}
			.to_string();

			// Create InteropAddress objects
			let user_interop = solver_types::standards::eip7930::InteropAddress::new_ethereum(
				spec.origin_chain_id,
				user_address,
			);
			let recipient_interop = solver_types::standards::eip7930::InteropAddress::new_ethereum(
				spec.dest_chain_id,
				recipient_address,
			);
			let from_asset_interop = solver_types::standards::eip7930::InteropAddress::new_ethereum(
				spec.origin_chain_id,
				parse_address(&spec.origin_token.address)?,
			);
			let to_asset_interop = solver_types::standards::eip7930::InteropAddress::new_ethereum(
				spec.dest_chain_id,
				parse_address(&spec.dest_token.address)?,
			);

			// Create QuoteInput and QuoteOutput
			let input = solver_types::api::QuoteInput {
				user: user_interop.clone(),
				asset: from_asset_interop,
				amount: if matches!(swap_type, solver_types::api::SwapType::ExactInput) {
					Some(formatted_amount.clone())
				} else {
					None
				},
				lock: if settlement == "compact" {
					Some(solver_types::api::AssetLockReference {
						kind: solver_types::api::LockKind::TheCompact,
						params: None,
					})
				} else {
					None
				},
			};

			let quote_output = solver_types::api::QuoteOutput {
				receiver: recipient_interop,
				asset: to_asset_interop,
				amount: if matches!(swap_type, solver_types::api::SwapType::ExactOutput) {
					Some(formatted_amount.clone())
				} else {
					None
				},
				calldata: None,
			};

			// Create IntentRequest
			let intent_request = solver_types::api::IntentRequest {
				intent_type: solver_types::api::IntentType::OifSwap,
				inputs: vec![input],
				outputs: vec![quote_output],
				swap_type: Some(swap_type.clone()),
				min_valid_until: Some((chrono::Utc::now().timestamp() as u64) + 600), // 10 minutes
				preference: Some(solver_types::api::QuotePreference::Speed),
				origin_submission,
				failure_handling: Some(vec![
					solver_types::api::FailureHandlingMode::RefundAutomatic,
				]),
				partial_fill: Some(false),
				metadata: None,
			};

			// Create GetQuoteRequest
			let quote_request = solver_types::api::GetQuoteRequest {
				user: user_interop,
				intent: intent_request,
				supported_types,
			};

			quote_requests.push(quote_request);
		}

		if quote_requests.is_empty() {
			return Err(anyhow!("No enabled intents found in specification file"));
		}

		// Determine output file
		let requests_dir = session_manager.requests_dir();
		let output_file = output.unwrap_or_else(|| requests_dir.join("get_quotes.req.json"));

		// Ensure directory exists
		if let Some(parent) = output_file.parent() {
			fs::create_dir_all(parent).await?;
		}

		// Save the batch quote requests
		let json = serde_json::to_string_pretty(&quote_requests)?;
		fs::write(&output_file, json).await?;

		// Display results
		self.display
			.header("Batch Quote Requests Built Successfully");

		self.display.tree(
			"Summary",
			vec![
				TreeItem::KeyValue(
					"Total Intents".to_string(),
					batch_spec.intents.len().to_string(),
				),
				TreeItem::KeyValue("Enabled".to_string(), quote_requests.len().to_string()),
				TreeItem::KeyValue("Skipped".to_string(), skipped_count.to_string()),
				TreeItem::KeyValue("Output File".to_string(), output_file.display().to_string()),
			],
		);

		// Show details of generated intents
		if quote_requests.len() <= 5 {
			let intent_details: Vec<TreeItem> = batch_spec
				.intents
				.iter()
				.enumerate()
				.filter(|(_, spec)| spec.enabled)
				.map(|(i, spec)| {
					let swap_type = if spec.amounts.input.is_some() {
						"ExactInput"
					} else {
						"ExactOutput"
					};

					TreeItem::Text(format!(
						"Intent {}: Chain {} → {} ({})",
						i + 1,
						spec.origin_chain_id,
						spec.dest_chain_id,
						swap_type
					))
				})
				.collect();

			self.display.tree("Generated Intents", intent_details);
		}

		self.display.next_steps(vec![
			&format!("Test quotes: oif-demo quote test {:?}", output_file),
			"This will create post_orders.req.json for batch submission",
		]);

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
