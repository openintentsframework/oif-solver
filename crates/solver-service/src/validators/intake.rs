use solver_config::Config;
use solver_types::{APIError, ApiErrorType, QuoteError};

pub fn ensure_quote_intake_enabled(config: &Config) -> Result<(), QuoteError> {
	if config.solver.is_intake_disabled() {
		return Err(QuoteError::SolverIntakeDisabled);
	}
	Ok(())
}

pub fn ensure_order_intake_enabled(config: &Config) -> Result<(), APIError> {
	if config.solver.is_intake_disabled() {
		return Err(intake_disabled_api_error());
	}
	Ok(())
}

pub fn intake_disabled_api_error() -> APIError {
	APIError::ServiceUnavailable {
		error_type: ApiErrorType::SolverIntakeDisabled,
		message: "Solver intake is disabled; new quotes and orders are temporarily unavailable"
			.to_string(),
		retry_after: None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_config::{ConfigBuilder, SolverIngressMode};
	use solver_types::{APIError, ApiErrorType, QuoteError};

	#[test]
	fn ensure_quote_intake_enabled_allows_active_mode() {
		let mut config = ConfigBuilder::new().build();
		config.solver.ingress_mode = SolverIngressMode::Active;

		assert!(ensure_quote_intake_enabled(&config).is_ok());
	}

	#[test]
	fn ensure_quote_intake_enabled_rejects_intake_disabled() {
		let mut config = ConfigBuilder::new().build();
		config.solver.ingress_mode = SolverIngressMode::IntakeDisabled;

		let err = ensure_quote_intake_enabled(&config).unwrap_err();
		assert!(matches!(err, QuoteError::SolverIntakeDisabled));
	}

	#[test]
	fn ensure_order_intake_enabled_rejects_intake_disabled() {
		let mut config = ConfigBuilder::new().build();
		config.solver.ingress_mode = SolverIngressMode::IntakeDisabled;

		let err = ensure_order_intake_enabled(&config).unwrap_err();
		assert!(matches!(
			err,
			APIError::ServiceUnavailable {
				error_type: ApiErrorType::SolverIntakeDisabled,
				..
			}
		));
	}
}
