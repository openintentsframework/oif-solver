//! Health check endpoint for the solver API.
//!
//! # Endpoints
//!
//! - `GET /health` - Health check with Redis status

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use solver_storage::{check_storage_readiness, PersistencePolicy, ReadinessCheck, StoreConfig};
use std::collections::HashMap;

use crate::server::AppState;

/// Full health check response with Redis status.
#[derive(Serialize)]
pub struct HealthResponse {
	/// Overall health status: "healthy" or "unhealthy"
	pub status: String,
	/// Generic storage readiness status
	pub storage: StorageHealth,
	/// Redis connection and persistence status (only for Redis backend)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redis: Option<RedisHealth>,
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

/// Generic storage health status.
#[derive(Serialize)]
pub struct StorageHealth {
	/// Backend name (e.g., "Redis", "Memory")
	pub backend: String,
	/// Whether the backend is ready for operation
	pub ready: bool,
	/// Individual readiness checks
	pub checks: Vec<ReadinessCheck>,
	/// Additional details for debugging
	pub details: HashMap<String, String>,
	/// Optional error message
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
	let store_config = match StoreConfig::from_env() {
		Ok(config) => config,
		Err(e) => {
			let response = HealthResponse {
				status: "unhealthy".to_string(),
				storage: StorageHealth {
					backend: "unknown".to_string(),
					ready: false,
					checks: Vec::new(),
					details: HashMap::new(),
					error: Some(e.to_string()),
				},
				redis: None,
				solver_id: state.config.read().await.solver.id.clone(),
				version: env!("CARGO_PKG_VERSION").to_string(),
			};

			return (StatusCode::SERVICE_UNAVAILABLE, Json(response));
		},
	};

	let policy = PersistencePolicy::from_env();
	let readiness = check_storage_readiness(&store_config, policy, 2000).await;

	let mut redis_health: Option<RedisHealth> = None;
	let storage_health = match readiness {
		Ok(status) => {
			if status.backend_name.to_lowercase() == "redis" {
				let mut connected = false;
				let mut rdb_enabled = false;
				let mut aof_enabled = false;
				for check in &status.checks {
					match check.name.as_str() {
						"connectivity" => connected = check.passed,
						"rdb_persistence" => rdb_enabled = check.passed,
						"aof_persistence" => aof_enabled = check.passed,
						_ => {},
					}
				}

				redis_health = Some(RedisHealth {
					connected,
					persistence_enabled: rdb_enabled || aof_enabled,
					rdb_enabled,
					aof_enabled,
					error: None,
				});
			}

			StorageHealth {
				backend: status.backend_name.clone(),
				ready: status.is_ready,
				checks: status.checks,
				details: status.details,
				error: None,
			}
		},
		Err(e) => StorageHealth {
			backend: match store_config {
				StoreConfig::Redis { .. } => "Redis".to_string(),
				StoreConfig::File { .. } => "File".to_string(),
				StoreConfig::Memory => "Memory".to_string(),
				StoreConfig::Storage(_) => "Storage".to_string(),
			},
			ready: false,
			checks: Vec::new(),
			details: HashMap::new(),
			error: Some(e.to_string()),
		},
	};

	let solver_id = state.config.read().await.solver.id.clone();

	let response = HealthResponse {
		status: if storage_health.ready {
			"healthy".to_string()
		} else {
			"unhealthy".to_string()
		},
		storage: storage_health,
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
			storage: StorageHealth {
				backend: "Redis".to_string(),
				ready: true,
				checks: Vec::new(),
				details: HashMap::new(),
				error: None,
			},
			redis: Some(RedisHealth {
				connected: true,
				persistence_enabled: true,
				rdb_enabled: true,
				aof_enabled: false,
				error: None,
			}),
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
			storage: StorageHealth {
				backend: "Redis".to_string(),
				ready: false,
				checks: Vec::new(),
				details: HashMap::new(),
				error: Some("Connection refused".to_string()),
			},
			redis: Some(RedisHealth {
				connected: false,
				persistence_enabled: false,
				rdb_enabled: false,
				aof_enabled: false,
				error: Some("Connection refused".to_string()),
			}),
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

	#[test]
	fn test_storage_health_with_checks() {
		let storage = StorageHealth {
			backend: "Redis".to_string(),
			ready: true,
			checks: vec![
				ReadinessCheck {
					name: "connectivity".to_string(),
					passed: true,
					status: "CONNECTED".to_string(),
					message: None,
				},
				ReadinessCheck {
					name: "persistence".to_string(),
					passed: true,
					status: "ENABLED".to_string(),
					message: Some("RDB enabled".to_string()),
				},
			],
			details: HashMap::new(),
			error: None,
		};

		let json = serde_json::to_string(&storage).unwrap();
		assert!(json.contains("\"backend\":\"Redis\""));
		assert!(json.contains("\"ready\":true"));
		assert!(json.contains("\"connectivity\""));
		assert!(json.contains("\"persistence\""));
		assert!(json.contains("\"CONNECTED\""));
		assert!(json.contains("\"ENABLED\""));
	}

	#[test]
	fn test_storage_health_with_details() {
		let mut details = HashMap::new();
		details.insert("redis_version".to_string(), "7.0.0".to_string());
		details.insert("uptime_days".to_string(), "30".to_string());

		let storage = StorageHealth {
			backend: "Redis".to_string(),
			ready: true,
			checks: Vec::new(),
			details,
			error: None,
		};

		let json = serde_json::to_string(&storage).unwrap();
		assert!(json.contains("\"redis_version\":\"7.0.0\""));
		assert!(json.contains("\"uptime_days\":\"30\""));
	}

	#[test]
	fn test_storage_health_file_backend() {
		let storage = StorageHealth {
			backend: "File".to_string(),
			ready: true,
			checks: vec![
				ReadinessCheck {
					name: "directory".to_string(),
					passed: true,
					status: "EXISTS".to_string(),
					message: Some("Path: ./data/storage".to_string()),
				},
				ReadinessCheck {
					name: "writable".to_string(),
					passed: true,
					status: "WRITABLE".to_string(),
					message: None,
				},
			],
			details: HashMap::new(),
			error: None,
		};

		let json = serde_json::to_string(&storage).unwrap();
		assert!(json.contains("\"backend\":\"File\""));
		assert!(json.contains("\"directory\""));
		assert!(json.contains("\"writable\""));
	}

	#[test]
	fn test_storage_health_memory_backend() {
		let storage = StorageHealth {
			backend: "Memory".to_string(),
			ready: true,
			checks: Vec::new(),
			details: HashMap::new(),
			error: None,
		};

		let json = serde_json::to_string(&storage).unwrap();
		assert!(json.contains("\"backend\":\"Memory\""));
		assert!(json.contains("\"ready\":true"));
	}

	#[test]
	fn test_health_response_without_redis() {
		let response = HealthResponse {
			status: "healthy".to_string(),
			storage: StorageHealth {
				backend: "Memory".to_string(),
				ready: true,
				checks: Vec::new(),
				details: HashMap::new(),
				error: None,
			},
			redis: None,
			solver_id: "test-solver".to_string(),
			version: "0.1.0".to_string(),
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"status\":\"healthy\""));
		assert!(json.contains("\"backend\":\"Memory\""));
		// redis should be omitted when None
		assert!(!json.contains("\"redis\""));
	}

	#[test]
	fn test_health_response_file_storage() {
		let response = HealthResponse {
			status: "healthy".to_string(),
			storage: StorageHealth {
				backend: "File".to_string(),
				ready: true,
				checks: vec![ReadinessCheck {
					name: "persistence".to_string(),
					passed: true,
					status: "ENABLED".to_string(),
					message: Some("File-based storage is always persistent".to_string()),
				}],
				details: HashMap::new(),
				error: None,
			},
			redis: None,
			solver_id: "file-solver".to_string(),
			version: "0.1.0".to_string(),
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"backend\":\"File\""));
		assert!(json.contains("\"solver_id\":\"file-solver\""));
	}

	#[test]
	fn test_storage_health_not_ready() {
		let storage = StorageHealth {
			backend: "Redis".to_string(),
			ready: false,
			checks: vec![ReadinessCheck {
				name: "connectivity".to_string(),
				passed: false,
				status: "DISCONNECTED".to_string(),
				message: Some("Connection timeout".to_string()),
			}],
			details: HashMap::new(),
			error: Some("Failed to connect to Redis".to_string()),
		};

		let json = serde_json::to_string(&storage).unwrap();
		assert!(json.contains("\"ready\":false"));
		assert!(json.contains("\"passed\":false"));
		assert!(json.contains("\"DISCONNECTED\""));
		assert!(json.contains("Failed to connect to Redis"));
	}
}
