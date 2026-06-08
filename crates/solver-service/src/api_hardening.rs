//! Public API hardening middleware.
//!
//! These controls keep public endpoints available without making `/quotes`
//! private by default. Operators can still opt into JWT auth separately.

use crate::server::AppState;
use axum::{
	body::Body,
	extract::State,
	http::{Request, StatusCode},
	middleware::{self, Next},
	response::{IntoResponse, Response},
	Router,
};
use solver_config::{ApiConfig, RateLimitConfig};
use solver_types::QuoteError;
use std::{
	collections::HashMap,
	net::{IpAddr, Ipv4Addr, SocketAddr},
	sync::{Arc, Mutex},
	time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub(crate) struct ApiRateLimiter {
	requests_per_second: f64,
	burst_capacity: f64,
	idle_ttl: Duration,
	clients: Arc<Mutex<HashMap<IpAddr, ClientBucket>>>,
}

#[derive(Clone, Debug)]
struct ClientBucket {
	tokens: f64,
	last_refill: Instant,
	last_seen: Instant,
}

impl ApiRateLimiter {
	pub(crate) fn new(config: &RateLimitConfig) -> Self {
		Self {
			requests_per_second: config.requests_per_minute.max(1) as f64 / 60.0,
			burst_capacity: config.burst_size.max(1) as f64,
			idle_ttl: Duration::from_secs(60),
			clients: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	#[cfg(test)]
	pub(crate) fn new_for_test(max_requests: usize, window: Duration) -> Self {
		Self {
			requests_per_second: max_requests.max(1) as f64 / window.as_secs_f64(),
			burst_capacity: max_requests.max(1) as f64,
			idle_ttl: window,
			clients: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	pub(crate) fn allows(&self, ip: IpAddr) -> bool {
		self.allows_at(ip, Instant::now())
	}

	fn allows_at(&self, ip: IpAddr, now: Instant) -> bool {
		let mut clients = self.clients.lock().expect("rate limiter lock poisoned");
		self.evict_expired_locked(&mut clients, now);

		let bucket = clients.entry(ip).or_insert(ClientBucket {
			tokens: self.burst_capacity,
			last_refill: now,
			last_seen: now,
		});
		refill_bucket(bucket, now, self.requests_per_second, self.burst_capacity);
		bucket.last_seen = now;

		if bucket.tokens < 1.0 {
			return false;
		}
		bucket.tokens -= 1.0;
		true
	}

	fn evict_expired_locked(&self, clients: &mut HashMap<IpAddr, ClientBucket>, now: Instant) {
		clients.retain(|_, bucket| {
			refill_bucket(bucket, now, self.requests_per_second, self.burst_capacity);
			now.duration_since(bucket.last_seen) < self.idle_ttl
				|| bucket.tokens < self.burst_capacity
		});
	}

	#[cfg(test)]
	pub(crate) fn tracked_clients_for_test(&self) -> usize {
		self.clients
			.lock()
			.expect("rate limiter lock poisoned")
			.len()
	}
}

fn refill_bucket(
	bucket: &mut ClientBucket,
	now: Instant,
	requests_per_second: f64,
	burst_capacity: f64,
) {
	let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
	if elapsed > 0.0 {
		bucket.tokens = (bucket.tokens + elapsed * requests_per_second).min(burst_capacity);
		bucket.last_refill = now;
	}
}

pub(crate) async fn api_rate_limit_middleware(
	State(limiter): State<ApiRateLimiter>,
	request: Request<Body>,
	next: Next,
) -> Response {
	let ip = request
		.extensions()
		.get::<axum::extract::ConnectInfo<SocketAddr>>()
		.map(|connect_info| connect_info.0.ip())
		.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

	if !limiter.allows(ip) {
		return StatusCode::TOO_MANY_REQUESTS.into_response();
	}

	next.run(request).await
}

#[derive(Clone)]
pub(crate) struct QuoteConcurrencyLimiter {
	permits: Arc<Semaphore>,
}

impl QuoteConcurrencyLimiter {
	pub(crate) fn new(max_concurrent_requests: usize) -> Self {
		Self {
			permits: Arc::new(Semaphore::new(max_concurrent_requests)),
		}
	}

	pub(crate) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
		self.permits.clone().try_acquire_owned().ok()
	}
}

pub(crate) async fn quote_concurrency_middleware(
	State(limiter): State<QuoteConcurrencyLimiter>,
	request: Request<Body>,
	next: Next,
) -> Response {
	let Some(_permit) = limiter.try_acquire() else {
		let error: solver_types::APIError = QuoteError::SolverCapacityExceeded.into();
		return error.into_response();
	};

	next.run(request).await
}

pub(crate) fn apply_rate_limit(
	routes: Router<AppState>,
	api_config: &ApiConfig,
) -> Router<AppState> {
	let rate_limit = api_config.rate_limiting.clone().unwrap_or_default();

	if !rate_limit.enabled {
		return routes;
	}

	routes.layer(middleware::from_fn_with_state(
		ApiRateLimiter::new(&rate_limit),
		api_rate_limit_middleware,
	))
}

pub(crate) fn apply_quote_concurrency(
	quote_routes: Router<AppState>,
	api_config: &ApiConfig,
) -> Router<AppState> {
	let quote_config = api_config.quote.clone().unwrap_or_default();
	let max_concurrent_requests = quote_config.max_concurrent_requests.max(1);

	quote_routes.layer(middleware::from_fn_with_state(
		QuoteConcurrencyLimiter::new(max_concurrent_requests),
		quote_concurrency_middleware,
	))
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::{body, routing::get};
	use solver_types::ErrorResponse;
	use tower::ServiceExt;

	#[test]
	fn burst_size_caps_immediate_requests_and_refills_at_configured_rate() {
		let limiter = ApiRateLimiter::new(&RateLimitConfig {
			enabled: true,
			requests_per_minute: 60,
			burst_size: 2,
		});
		let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
		let start = Instant::now();

		assert!(limiter.allows_at(ip, start));
		assert!(limiter.allows_at(ip, start));
		assert!(
			!limiter.allows_at(ip, start),
			"burst capacity should cap immediate traffic"
		);
		assert!(limiter.allows_at(ip, start + Duration::from_secs(1)));
		assert!(
			!limiter.allows_at(ip, start + Duration::from_secs(1)),
			"only one token should refill after one second at 60 requests/minute"
		);
	}

	#[tokio::test]
	async fn quote_concurrency_saturation_returns_structured_capacity_error() {
		let limiter = QuoteConcurrencyLimiter::new(1);
		let _held = limiter
			.try_acquire()
			.expect("first quote request should acquire the only permit");
		let app =
			Router::new()
				.route("/", get(|| async { "ok" }))
				.layer(middleware::from_fn_with_state(
					limiter,
					quote_concurrency_middleware,
				));

		let response = app
			.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
		let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
			.await
			.expect("body");
		let parsed: ErrorResponse = serde_json::from_slice(&body_bytes).expect("parse body");
		assert_eq!(parsed.error, "SOLVER_CAPACITY_EXCEEDED");
		assert_eq!(parsed.retry_after, Some(60));
	}
}
