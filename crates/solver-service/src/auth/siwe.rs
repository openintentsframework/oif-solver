//! SIWE (Sign-In with Ethereum) parsing and signature verification.

use alloy_primitives::Address;
use chrono::{DateTime, Utc};
use thiserror::Error;

use super::admin::recover_personal_sign;

/// Errors during SIWE parsing or verification.
#[derive(Error, Debug)]
pub enum SiweError {
	#[error("SIWE message is empty")]
	EmptyMessage,
	#[error("missing required SIWE field: {0}")]
	MissingField(&'static str),
	#[error("invalid SIWE header format")]
	InvalidHeader,
	#[error("invalid SIWE address: {0}")]
	InvalidAddress(String),
	#[error("invalid SIWE field {field}: {reason}")]
	InvalidFieldFormat { field: &'static str, reason: String },
	#[error("unsupported SIWE version: expected 1, got {0}")]
	UnsupportedVersion(String),
	#[error("SIWE message expired")]
	Expired,
	#[error("SIWE message is not yet valid")]
	NotYetValid,
	#[error("SIWE domain mismatch: expected {expected}, got {actual}")]
	DomainMismatch { expected: String, actual: String },
	#[error("SIWE chain ID mismatch: expected {expected}, got {actual}")]
	ChainIdMismatch { expected: u64, actual: u64 },
	#[error("invalid SIWE signature format: {0}")]
	InvalidSignature(String),
	#[error("SIWE signature recovery failed: {0}")]
	SignatureRecovery(String),
	#[error(
		"SIWE signer mismatch: message address {message_address}, recovered {recovered_address}"
	)]
	AddressMismatch {
		message_address: String,
		recovered_address: String,
	},
}

/// Parsed SIWE message fields used by the auth flow.
#[derive(Debug, Clone)]
pub struct SiweMessage {
	pub domain: String,
	pub address: Address,
	pub statement: Option<String>,
	pub uri: String,
	pub version: String,
	pub chain_id: u64,
	pub nonce: String,
	pub issued_at: DateTime<Utc>,
	pub expiration_time: Option<DateTime<Utc>>,
	pub not_before: Option<DateTime<Utc>>,
}

impl SiweMessage {
	/// Parse a SIWE message from its plain-text EIP-4361 representation.
	pub fn parse(message: &str) -> Result<Self, SiweError> {
		let lines: Vec<&str> = message.lines().collect();
		if lines.is_empty() {
			return Err(SiweError::EmptyMessage);
		}

		let header = lines[0];
		let domain = header
			.strip_suffix(" wants you to sign in with your Ethereum account:")
			.ok_or(SiweError::InvalidHeader)?
			.to_string();

		let address_line = lines.get(1).ok_or(SiweError::MissingField("address"))?;
		let address = parse_eth_address(address_line)?;

		let mut statement = None;
		let mut uri = None;
		let mut version = None;
		let mut chain_id = None;
		let mut nonce = None;
		let mut issued_at = None;
		let mut expiration_time = None;
		let mut not_before = None;

		for raw_line in lines.iter().skip(2) {
			let line = raw_line.trim_end();
			if line.is_empty() {
				continue;
			}

			if let Some(value) = line.strip_prefix("URI: ") {
				uri = Some(value.to_string());
			} else if let Some(value) = line.strip_prefix("Version: ") {
				version = Some(value.to_string());
			} else if let Some(value) = line.strip_prefix("Chain ID: ") {
				let parsed_chain =
					value
						.parse::<u64>()
						.map_err(|_| SiweError::InvalidFieldFormat {
							field: "Chain ID",
							reason: "not a valid u64".to_string(),
						})?;
				chain_id = Some(parsed_chain);
			} else if let Some(value) = line.strip_prefix("Nonce: ") {
				nonce = Some(value.to_string());
			} else if let Some(value) = line.strip_prefix("Issued At: ") {
				issued_at = Some(parse_datetime(value)?);
			} else if let Some(value) = line.strip_prefix("Expiration Time: ") {
				expiration_time = Some(parse_datetime(value)?);
			} else if let Some(value) = line.strip_prefix("Not Before: ") {
				not_before = Some(parse_datetime(value)?);
			} else if statement.is_none() {
				statement = Some(line.to_string());
			}
		}

		Ok(Self {
			domain,
			address,
			statement,
			uri: uri.ok_or(SiweError::MissingField("URI"))?,
			version: version.ok_or(SiweError::MissingField("Version"))?,
			chain_id: chain_id.ok_or(SiweError::MissingField("Chain ID"))?,
			nonce: nonce.ok_or(SiweError::MissingField("Nonce"))?,
			issued_at: issued_at.ok_or(SiweError::MissingField("Issued At"))?,
			expiration_time,
			not_before,
		})
	}

	#[must_use]
	pub fn is_expired(&self) -> bool {
		self.expiration_time.is_some_and(|exp| exp < Utc::now())
	}

	#[must_use]
	pub fn is_not_yet_valid(&self) -> bool {
		self.not_before.is_some_and(|nbf| nbf > Utc::now())
	}
}

/// Verifies a SIWE message and signature against expected domain/chain.
pub fn verify_siwe_signature(
	message: &str,
	signature: &str,
	expected_domain: &str,
	expected_chain_id: u64,
) -> Result<SiweMessage, SiweError> {
	let siwe = SiweMessage::parse(message)?;

	if siwe.version != "1" {
		return Err(SiweError::UnsupportedVersion(siwe.version.clone()));
	}
	if siwe.is_expired() {
		return Err(SiweError::Expired);
	}
	if siwe.is_not_yet_valid() {
		return Err(SiweError::NotYetValid);
	}
	if siwe.domain != expected_domain {
		return Err(SiweError::DomainMismatch {
			expected: expected_domain.to_string(),
			actual: siwe.domain.clone(),
		});
	}
	if siwe.chain_id != expected_chain_id {
		return Err(SiweError::ChainIdMismatch {
			expected: expected_chain_id,
			actual: siwe.chain_id,
		});
	}

	let signature_bytes = decode_signature(signature)?;
	let recovered = recover_personal_sign(message.as_bytes(), &signature_bytes)
		.map_err(|e| SiweError::SignatureRecovery(e.to_string()))?;
	if recovered != siwe.address {
		return Err(SiweError::AddressMismatch {
			message_address: siwe.address.to_string(),
			recovered_address: recovered.to_string(),
		});
	}

	Ok(siwe)
}

fn parse_eth_address(raw: &str) -> Result<Address, SiweError> {
	let trimmed = raw.trim();
	let normalized = if let Some(stripped) = trimmed
		.strip_prefix("0x")
		.or_else(|| trimmed.strip_prefix("0X"))
	{
		format!("0x{stripped}")
	} else {
		format!("0x{trimmed}")
	};

	normalized
		.parse::<Address>()
		.map_err(|e| SiweError::InvalidAddress(e.to_string()))
}

fn parse_datetime(raw: &str) -> Result<DateTime<Utc>, SiweError> {
	DateTime::parse_from_rfc3339(raw)
		.map(|dt| dt.with_timezone(&Utc))
		.map_err(|e| SiweError::InvalidFieldFormat {
			field: "datetime",
			reason: e.to_string(),
		})
}

fn decode_signature(signature: &str) -> Result<Vec<u8>, SiweError> {
	let hex_sig = signature.strip_prefix("0x").unwrap_or(signature);
	if hex_sig.len() != 130 {
		return Err(SiweError::InvalidSignature(format!(
			"expected 130 hex chars, got {}",
			hex_sig.len()
		)));
	}

	hex::decode(hex_sig).map_err(|e| SiweError::InvalidSignature(e.to_string()))
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::B256;
	use alloy_signer::SignerSync;
	use alloy_signer_local::PrivateKeySigner;
	use chrono::Duration;

	fn test_signer() -> PrivateKeySigner {
		PrivateKeySigner::from_bytes(&B256::from([0x42u8; 32])).expect("valid secret")
	}

	fn build_message(
		domain: &str,
		address: &str,
		chain_id: u64,
		nonce: &str,
		issued_at: DateTime<Utc>,
		expiration_time: Option<DateTime<Utc>>,
	) -> String {
		let mut message = format!(
			"{domain} wants you to sign in with your Ethereum account:\n\
{address}\n\n\
Sign in to OIF Solver Admin API\n\n\
URI: https://{domain}\n\
Version: 1\n\
Chain ID: {chain_id}\n\
Nonce: {nonce}\n\
Issued At: {}\n",
			issued_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
		);

		if let Some(exp) = expiration_time {
			message.push_str(&format!(
				"Expiration Time: {}\n",
				exp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
			));
		}

		message
	}

	#[test]
	fn parse_valid_siwe_message() {
		let message = build_message(
			"solver.example.com",
			"0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
			1,
			"00000000123456789012",
			Utc::now(),
			None,
		);
		let parsed = SiweMessage::parse(&message).unwrap();

		assert_eq!(parsed.domain, "solver.example.com");
		assert_eq!(parsed.chain_id, 1);
		assert_eq!(parsed.nonce, "00000000123456789012");
		assert_eq!(parsed.version, "1");
		assert_eq!(parsed.uri, "https://solver.example.com");
		assert!(parsed.statement.is_some());
	}

	#[test]
	fn verify_siwe_signature_success() {
		let signer = test_signer();
		let now = Utc::now();
		let message = build_message(
			"solver.example.com",
			&signer.address().to_string(),
			1,
			"00000000000000012345",
			now,
			Some(now + Duration::minutes(5)),
		);
		let signature = signer.sign_message_sync(message.as_bytes()).unwrap();
		let signature_hex = format!("0x{}", hex::encode(signature.as_bytes()));

		let parsed = verify_siwe_signature(&message, &signature_hex, "solver.example.com", 1)
			.expect("verification should succeed");
		assert_eq!(parsed.address, signer.address());
	}

	#[test]
	fn verify_siwe_signature_domain_mismatch() {
		let signer = test_signer();
		let now = Utc::now();
		let message = build_message(
			"solver.example.com",
			&signer.address().to_string(),
			1,
			"00000000000000012345",
			now,
			Some(now + Duration::minutes(5)),
		);
		let signature = signer.sign_message_sync(message.as_bytes()).unwrap();
		let signature_hex = format!("0x{}", hex::encode(signature.as_bytes()));

		let err = verify_siwe_signature(&message, &signature_hex, "other.example.com", 1)
			.expect_err("expected domain mismatch");
		assert!(matches!(err, SiweError::DomainMismatch { .. }));
	}

	#[test]
	fn verify_siwe_signature_chain_mismatch() {
		let signer = test_signer();
		let now = Utc::now();
		let message = build_message(
			"solver.example.com",
			&signer.address().to_string(),
			1,
			"00000000000000012345",
			now,
			Some(now + Duration::minutes(5)),
		);
		let signature = signer.sign_message_sync(message.as_bytes()).unwrap();
		let signature_hex = format!("0x{}", hex::encode(signature.as_bytes()));

		let err = verify_siwe_signature(&message, &signature_hex, "solver.example.com", 10)
			.expect_err("expected chain mismatch");
		assert!(matches!(err, SiweError::ChainIdMismatch { .. }));
	}

	#[test]
	fn verify_siwe_signature_expired_message() {
		let signer = test_signer();
		let now = Utc::now();
		let message = build_message(
			"solver.example.com",
			&signer.address().to_string(),
			1,
			"00000000000000012345",
			now - Duration::minutes(10),
			Some(now - Duration::minutes(5)),
		);
		let signature = signer.sign_message_sync(message.as_bytes()).unwrap();
		let signature_hex = format!("0x{}", hex::encode(signature.as_bytes()));

		let err = verify_siwe_signature(&message, &signature_hex, "solver.example.com", 1)
			.expect_err("expected expiry failure");
		assert!(matches!(err, SiweError::Expired));
	}
}
