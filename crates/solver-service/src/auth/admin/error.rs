//! Error types for admin authentication.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::Serialize;
use thiserror::Error;

/// Errors that can occur during admin authentication.
#[derive(Error, Debug)]
pub enum AdminAuthError {
	/// Invalid signature format or length
	#[error("Invalid signature: {0}")]
	InvalidSignature(String),

	/// Signature verification/recovery failed
	#[error("Signature verification failed: {0}")]
	SignatureVerification(String),

	/// Address is not in the admin registry
	#[error("Address {0} is not authorized as admin")]
	NotAuthorized(String),

	/// Invalid nonce format
	#[error("Invalid nonce: {0}")]
	InvalidNonce(String),

	/// Nonce not found or already consumed
	#[error("Nonce not found or already used")]
	NonceNotFound,

	/// Request has expired
	#[error("Request expired")]
	Expired,

	/// Domain in signature doesn't match expected domain
	#[error("Domain mismatch: expected {expected}, got {actual}")]
	DomainMismatch { expected: String, actual: String },

	/// Message format is invalid
	#[error("Invalid message format: {0}")]
	InvalidMessage(String),

	/// Internal server error
	#[error("Internal error: {0}")]
	Internal(String),
}

/// API error response format for admin auth errors.
#[derive(Serialize, serde::Deserialize)]
pub struct AdminAuthErrorResponse {
	/// Error code (e.g., "invalid_signature", "not_authorized")
	pub error: String,
	/// Human-readable error description
	pub error_description: String,
}

impl IntoResponse for AdminAuthError {
	fn into_response(self) -> axum::response::Response {
		let (status, error_code) = match &self {
			AdminAuthError::InvalidSignature(_) => (StatusCode::BAD_REQUEST, "invalid_signature"),
			AdminAuthError::SignatureVerification(_) => {
				(StatusCode::UNAUTHORIZED, "signature_failed")
			},
			AdminAuthError::NotAuthorized(_) => (StatusCode::FORBIDDEN, "not_authorized"),
			AdminAuthError::InvalidNonce(_) => (StatusCode::BAD_REQUEST, "invalid_nonce"),
			AdminAuthError::NonceNotFound => (StatusCode::BAD_REQUEST, "nonce_not_found"),
			AdminAuthError::Expired => (StatusCode::UNAUTHORIZED, "expired"),
			AdminAuthError::DomainMismatch { .. } => (StatusCode::UNAUTHORIZED, "domain_mismatch"),
			AdminAuthError::InvalidMessage(_) => (StatusCode::BAD_REQUEST, "invalid_message"),
			AdminAuthError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
		};

		// For internal errors, log details server-side but return generic message to client
		let error_description = match &self {
			AdminAuthError::Internal(details) => {
				tracing::error!(error = %details, "Internal admin auth error");
				"An internal error occurred".to_string()
			},
			_ => format!("{self}"),
		};

		let body = AdminAuthErrorResponse {
			error: error_code.to_string(),
			error_description,
		};

		(status, Json(body)).into_response()
	}
}

impl From<solver_storage::nonce_store::NonceError> for AdminAuthError {
	fn from(err: solver_storage::nonce_store::NonceError) -> Self {
		match err {
			solver_storage::nonce_store::NonceError::NotFound => AdminAuthError::NonceNotFound,
			solver_storage::nonce_store::NonceError::Storage(e) => {
				AdminAuthError::Internal(format!("Storage error: {e}"))
			},
			solver_storage::nonce_store::NonceError::Configuration(msg) => {
				AdminAuthError::Internal(format!("Configuration error: {msg}"))
			},
		}
	}
}

impl From<super::types::AdminActionHashError> for AdminAuthError {
	fn from(err: super::types::AdminActionHashError) -> Self {
		match err {
			super::types::AdminActionHashError::InvalidAmount(amount) => {
				AdminAuthError::InvalidMessage(format!("Invalid amount: {amount}"))
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::body::to_bytes;

	#[tokio::test]
	async fn test_error_response_status_codes() {
		// Test each error variant produces correct status code
		let cases = vec![
			(
				AdminAuthError::InvalidSignature("test".into()),
				StatusCode::BAD_REQUEST,
			),
			(
				AdminAuthError::SignatureVerification("test".into()),
				StatusCode::UNAUTHORIZED,
			),
			(
				AdminAuthError::NotAuthorized("0x123".into()),
				StatusCode::FORBIDDEN,
			),
			(
				AdminAuthError::InvalidNonce("test".into()),
				StatusCode::BAD_REQUEST,
			),
			(AdminAuthError::NonceNotFound, StatusCode::BAD_REQUEST),
			(AdminAuthError::Expired, StatusCode::UNAUTHORIZED),
			(
				AdminAuthError::DomainMismatch {
					expected: "a".into(),
					actual: "b".into(),
				},
				StatusCode::UNAUTHORIZED,
			),
			(
				AdminAuthError::InvalidMessage("test".into()),
				StatusCode::BAD_REQUEST,
			),
			(
				AdminAuthError::Internal("test".into()),
				StatusCode::INTERNAL_SERVER_ERROR,
			),
		];

		for (error, expected_status) in cases {
			let response = error.into_response();
			assert_eq!(response.status(), expected_status, "Wrong status for error");
		}
	}

	#[tokio::test]
	async fn test_error_response_body() {
		let error = AdminAuthError::NotAuthorized("0xABC".into());
		let response = error.into_response();

		let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
		let parsed: AdminAuthErrorResponse = serde_json::from_slice(&body).unwrap();

		assert_eq!(parsed.error, "not_authorized");
		assert!(parsed.error_description.contains("0xABC"));
	}

	#[tokio::test]
	async fn test_internal_error_hides_details() {
		// Internal errors should NOT leak details to clients
		let error = AdminAuthError::Internal("Redis connection failed: redis://secret@host".into());
		let response = error.into_response();

		assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

		let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
		let parsed: AdminAuthErrorResponse = serde_json::from_slice(&body).unwrap();

		assert_eq!(parsed.error, "server_error");
		// Should NOT contain internal details
		assert!(!parsed.error_description.contains("Redis"));
		assert!(!parsed.error_description.contains("secret"));
		// Should contain generic message
		assert_eq!(parsed.error_description, "An internal error occurred");
	}
}
