use solver_config::Config;
use solver_types::QuoteError;

pub fn ensure_intake_enabled<E>(config: &Config) -> Result<(), E>
where
	E: From<QuoteError>,
{
	if config.solver.is_intake_disabled() {
		return Err(QuoteError::SolverIntakeDisabled.into());
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_config::{ConfigBuilder, SolverIngressMode};
	use solver_types::{APIError, ApiErrorType, QuoteError};

	#[test]
	fn ensure_intake_enabled_allows_active_mode_for_quote_errors() {
		let mut config = ConfigBuilder::new().build();
		config.solver.ingress_mode = SolverIngressMode::Active;

		assert!(ensure_intake_enabled::<QuoteError>(&config).is_ok());
	}

	#[test]
	fn ensure_intake_enabled_returns_quote_error_when_disabled() {
		let mut config = ConfigBuilder::new().build();
		config.solver.ingress_mode = SolverIngressMode::IntakeDisabled;

		let err = ensure_intake_enabled::<QuoteError>(&config).unwrap_err();
		assert!(matches!(err, QuoteError::SolverIntakeDisabled));
	}

	#[test]
	fn ensure_intake_enabled_allows_active_mode_for_api_errors() {
		let mut config = ConfigBuilder::new().build();
		config.solver.ingress_mode = SolverIngressMode::Active;

		assert!(ensure_intake_enabled::<APIError>(&config).is_ok());
	}

	#[test]
	fn ensure_intake_enabled_returns_api_error_when_disabled() {
		let mut config = ConfigBuilder::new().build();
		config.solver.ingress_mode = SolverIngressMode::IntakeDisabled;

		let err = ensure_intake_enabled::<APIError>(&config).unwrap_err();
		assert!(matches!(
			err,
			APIError::ServiceUnavailable {
				error_type: ApiErrorType::SolverIntakeDisabled,
				..
			}
		));
	}
}
