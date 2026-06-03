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
use std::{
	collections::{HashMap, VecDeque},
	net::{IpAddr, Ipv4Addr, SocketAddr},
	sync::{Arc, Mutex},
	time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub(crate) struct ApiRateLimiter {
	max_requests: usize,
	window: Duration,
	clients: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
}

impl ApiRateLimiter {
	pub(crate) fn new(config: &RateLimitConfig) -> Self {
		Self {
			max_requests: config.requests_per_minute.max(config.burst_size).max(1) as usize,
			window: Duration::from_secs(60),
			clients: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	#[cfg(test)]
	pub(crate) fn new_for_test(max_requests: usize, window: Duration) -> Self {
		Self {
			max_requests: max_requests.max(1),
			window,
			clients: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	pub(crate) fn allows(&self, ip: IpAddr) -> bool {
		self.allows_at(ip, Instant::now())
	}

	fn allows_at(&self, ip: IpAddr, now: Instant) -> bool {
		let mut clients = self.clients.lock().expect("rate limiter lock poisoned");
		self.evict_expired_locked(&mut clients, now);

		let entries = clients.entry(ip).or_default();
		if entries.len() >= self.max_requests {
			return false;
		}
		entries.push_back(now);
		true
	}

	fn evict_expired_locked(&self, clients: &mut HashMap<IpAddr, VecDeque<Instant>>, now: Instant) {
		clients.retain(|_, entries| {
			while entries
				.front()
				.is_some_and(|instant| now.duration_since(*instant) >= self.window)
			{
				entries.pop_front();
			}
			!entries.is_empty()
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
		return StatusCode::SERVICE_UNAVAILABLE.into_response();
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
