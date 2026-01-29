//! Health check endpoint for the solver API.
//!
//! # Endpoints
//!
//! - `GET /health` - Health check with Redis status

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use solver_storage::check_redis_health;

use crate::server::AppState;

/// Full health check response with Redis status.
#[derive(Serialize)]
pub struct HealthResponse {
	/// Overall health status: "healthy" or "unhealthy"
	pub status: String,
	/// Redis connection and persistence status
	pub redis: RedisHealth,
	/// Solver ID from configuration
	pub solver_id: String,
	/// Application version
	pub version: String,
}

/// Redis health status.
#[derive(Serialize)]
pub struct RedisHealth {
	/// Whether Redis is connected
	pub connected: bool,
	/// Whether persistence is enabled (RDB or AOF)
	pub persistence_enabled: bool,
	/// Whether RDB (snapshotting) is enabled
	pub rdb_enabled: bool,
	/// Whether AOF (append-only file) is enabled
	pub aof_enabled: bool,
	/// Error message if health check failed
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

/// GET /health - Full health check endpoint.
///
/// Returns detailed health information including Redis status.
/// Used for monitoring dashboards and alerting.
///
/// # Response
///
/// ```json
/// {
///   "status": "healthy",
///   "redis": {
///     "connected": true,
///     "persistence_enabled": true,
///     "rdb_enabled": true,
///     "aof_enabled": false
///   },
///   "solver_id": "my-solver",
///   "version": "0.1.0"
/// }
/// ```
///
/// # Status Codes
///
/// - `200 OK` - Healthy (Redis connected)
/// - `503 Service Unavailable` - Unhealthy (Redis disconnected)
pub async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
	let redis_url =
		std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

	let redis_health = match check_redis_health(&redis_url, 2000).await {
		Ok(info) => RedisHealth {
			connected: true,
			persistence_enabled: info.has_persistence(),
			rdb_enabled: info.rdb_enabled,
			aof_enabled: info.aof_enabled,
			error: None,
		},
		Err(e) => RedisHealth {
			connected: false,
			persistence_enabled: false,
			rdb_enabled: false,
			aof_enabled: false,
			error: Some(e.to_string()),
		},
	};

	let solver_id = state.config.read().await.solver.id.clone();

	let response = HealthResponse {
		status: if redis_health.connected {
			"healthy".to_string()
		} else {
			"unhealthy".to_string()
		},
		redis: redis_health,
		solver_id,
		version: env!("CARGO_PKG_VERSION").to_string(),
	};

	let status_code = if response.status == "healthy" {
		StatusCode::OK
	} else {
		StatusCode::SERVICE_UNAVAILABLE
	};

	(status_code, Json(response))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_health_response_serialization_healthy() {
		let response = HealthResponse {
			status: "healthy".to_string(),
			redis: RedisHealth {
				connected: true,
				persistence_enabled: true,
				rdb_enabled: true,
				aof_enabled: false,
				error: None,
			},
			solver_id: "test-solver".to_string(),
			version: "0.1.0".to_string(),
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"status\":\"healthy\""));
		assert!(json.contains("\"connected\":true"));
		assert!(json.contains("\"persistence_enabled\":true"));
		assert!(json.contains("\"rdb_enabled\":true"));
		assert!(json.contains("\"aof_enabled\":false"));
		assert!(json.contains("\"solver_id\":\"test-solver\""));
		// Error should be omitted when None
		assert!(!json.contains("\"error\""));
	}

	#[test]
	fn test_health_response_serialization_unhealthy() {
		let response = HealthResponse {
			status: "unhealthy".to_string(),
			redis: RedisHealth {
				connected: false,
				persistence_enabled: false,
				rdb_enabled: false,
				aof_enabled: false,
				error: Some("Connection refused".to_string()),
			},
			solver_id: "test-solver".to_string(),
			version: "0.1.0".to_string(),
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"status\":\"unhealthy\""));
		assert!(json.contains("\"connected\":false"));
		assert!(json.contains("\"error\":\"Connection refused\""));
	}

	#[test]
	fn test_redis_health_serialization_with_error() {
		let redis_health = RedisHealth {
			connected: false,
			persistence_enabled: false,
			rdb_enabled: false,
			aof_enabled: false,
			error: Some("timeout".to_string()),
		};

		let json = serde_json::to_string(&redis_health).unwrap();
		assert!(json.contains("\"error\":\"timeout\""));
	}

	#[test]
	fn test_redis_health_serialization_without_error() {
		let redis_health = RedisHealth {
			connected: true,
			persistence_enabled: true,
			rdb_enabled: true,
			aof_enabled: true,
			error: None,
		};

		let json = serde_json::to_string(&redis_health).unwrap();
		// error field should be skipped when None
		assert!(!json.contains("error"));
		assert!(json.contains("\"connected\":true"));
		assert!(json.contains("\"aof_enabled\":true"));
	}

	#[test]
	fn test_redis_health_persistence_combinations() {
		// Only RDB enabled
		let rdb_only = RedisHealth {
			connected: true,
			persistence_enabled: true,
			rdb_enabled: true,
			aof_enabled: false,
			error: None,
		};
		let json = serde_json::to_string(&rdb_only).unwrap();
		assert!(json.contains("\"rdb_enabled\":true"));
		assert!(json.contains("\"aof_enabled\":false"));

		// Only AOF enabled
		let aof_only = RedisHealth {
			connected: true,
			persistence_enabled: true,
			rdb_enabled: false,
			aof_enabled: true,
			error: None,
		};
		let json = serde_json::to_string(&aof_only).unwrap();
		assert!(json.contains("\"rdb_enabled\":false"));
		assert!(json.contains("\"aof_enabled\":true"));

		// Both enabled
		let both = RedisHealth {
			connected: true,
			persistence_enabled: true,
			rdb_enabled: true,
			aof_enabled: true,
			error: None,
		};
		let json = serde_json::to_string(&both).unwrap();
		assert!(json.contains("\"rdb_enabled\":true"));
		assert!(json.contains("\"aof_enabled\":true"));
	}
}
