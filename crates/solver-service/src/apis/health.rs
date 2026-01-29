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
