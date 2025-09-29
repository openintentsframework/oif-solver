use anyhow::Result;
use clap::Subcommand;
use std::sync::Arc;

use crate::core::{DisplayUtils, SessionManager};

#[derive(Debug, Subcommand)]
pub enum AccountCommands {
	/// List all configured accounts
	List,

	/// Show detailed info for a specific account
	Info {
		/// Account type (user, solver, recipient)
		account: String,
	},
}

pub struct AccountHandler {
	session_manager: Arc<SessionManager>,
	display: Arc<DisplayUtils>,
}

impl AccountHandler {
	pub fn new(session_manager: Arc<SessionManager>) -> Self {
		Self {
			session_manager,
			display: Arc::new(DisplayUtils::new()),
		}
	}

	pub async fn handle(&self, command: AccountCommands) -> Result<()> {
		match command {
			AccountCommands::List => self.list().await,
			AccountCommands::Info { account } => self.info(account).await,
		}
	}

	async fn list(&self) -> Result<()> {
		use crate::core::TreeItem;
		
		self.display.header("CONFIGURED ACCOUNTS");

		// User account
		let user = self.session_manager.get_user_account().await;
		self.display.tree("User Account", vec![
			TreeItem::KeyValue("Address".to_string(), user.address.to_string()),
			TreeItem::KeyValue(
				"Has Private Key".to_string(),
				if user.private_key.is_some() { "✓" } else { "✗" }.to_string()
			),
		]);

		// Solver account
		let solver = self.session_manager.get_solver_account().await;
		self.display.tree("Solver Account", vec![
			TreeItem::KeyValue("Address".to_string(), solver.address.to_string()),
			TreeItem::KeyValue(
				"Has Private Key".to_string(),
				if solver.private_key.is_some() { "✓" } else { "✗" }.to_string()
			),
		]);

		// Recipient account (if different from user)
		let recipient = self.session_manager.get_recipient_account().await;
		if recipient.address != user.address {
			self.display.tree("Recipient Account", vec![
				TreeItem::KeyValue("Address".to_string(), recipient.address.to_string()),
			]);
		}

		Ok(())
	}

	async fn info(&self, account: String) -> Result<()> {
		use crate::core::TreeItem;
		
		match account.to_lowercase().as_str() {
			"user" => {
				let user = self.session_manager.get_user_account().await;
				self.display.header("USER ACCOUNT DETAILS");
				self.display.tree("Account Information", vec![
					TreeItem::KeyValue("Address".to_string(), user.address.to_string()),
					TreeItem::KeyValue(
						"Has Private Key".to_string(),
						if user.private_key.is_some() { "✓" } else { "✗" }.to_string()
					),
				]);
			},
			"solver" => {
				let solver = self.session_manager.get_solver_account().await;
				self.display.header("SOLVER ACCOUNT DETAILS");
				self.display.tree("Account Information", vec![
					TreeItem::KeyValue("Address".to_string(), solver.address.to_string()),
					TreeItem::KeyValue(
						"Has Private Key".to_string(),
						if solver.private_key.is_some() { "✓" } else { "✗" }.to_string()
					),
				]);
			},
			"recipient" => {
				let recipient = self.session_manager.get_recipient_account().await;
				self.display.header("RECIPIENT ACCOUNT DETAILS");
				self.display.tree("Account Information", vec![
					TreeItem::KeyValue("Address".to_string(), recipient.address.to_string()),
				]);
			},
			_ => {
				self.display
					.error(&format!("Unknown account type: {}", account));
				self.display.line("Valid options: user, solver, recipient");
			},
		}

		Ok(())
	}
}
