//! Configuration validation utilities for the OIF solver system.

use async_trait::async_trait;
use thiserror::Error;

/// Errors that can occur during configuration validation.
#[derive(Debug, Error)]
pub enum ValidationError {
	/// Error that occurs when a required field is missing.
	#[error("Missing required field: {0}")]
	MissingField(String),
	/// Error that occurs when a field has an invalid value.
	#[error("Invalid value for field '{field}': {message}")]
	InvalidValue { field: String, message: String },
	/// Error that occurs when field type is incorrect.
	#[error("Type mismatch for field '{field}': expected {expected}, got {actual}")]
	TypeMismatch {
		field: String,
		expected: String,
		actual: String,
	},
	/// Error that occurs when deserialization fails.
	#[error("Failed to deserialize config: {0}")]
	DeserializationError(String),
}

/// Type of a configuration field.
#[derive(Debug)]
pub enum FieldType {
	String,
	Integer { min: Option<i64>, max: Option<i64> },
	Boolean,
	Array(Box<FieldType>),
	Table(Schema),
}

/// Type alias for field validator functions.
pub type FieldValidator = Box<dyn Fn(&toml::Value) -> Result<(), String> + Send + Sync>;

/// A field definition with name and type.
pub struct Field {
	pub name: String,
	pub field_type: FieldType,
	pub validator: Option<FieldValidator>,
}

impl std::fmt::Debug for Field {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Field")
			.field("name", &self.name)
			.field("field_type", &self.field_type)
			.field("validator", &self.validator.is_some())
			.finish()
	}
}

impl Field {
	/// Creates a new field with the given name and type.
	pub fn new(name: impl Into<String>, field_type: FieldType) -> Self {
		Self {
			name: name.into(),
			field_type,
			validator: None,
		}
	}

	/// Adds a custom validator to this field.
	pub fn with_validator<F>(mut self, validator: F) -> Self
	where
		F: Fn(&toml::Value) -> Result<(), String> + Send + Sync + 'static,
	{
		self.validator = Some(Box::new(validator));
		self
	}
}

/// Schema definition with required and optional fields.
#[derive(Debug)]
pub struct Schema {
	pub required: Vec<Field>,
	pub optional: Vec<Field>,
}

impl Schema {
	/// Creates a new schema with required and optional fields.
	pub fn new(required: Vec<Field>, optional: Vec<Field>) -> Self {
		Self { required, optional }
	}

	/// Validates a TOML value against this schema.
	pub fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
		let table = config
			.as_table()
			.ok_or_else(|| ValidationError::TypeMismatch {
				field: "root".to_string(),
				expected: "table".to_string(),
				actual: config.type_str().to_string(),
			})?;

		// Check required fields
		for field in &self.required {
			let value = table
				.get(&field.name)
				.ok_or_else(|| ValidationError::MissingField(field.name.clone()))?;

			validate_field_type(&field.name, value, &field.field_type)?;

			// Run custom validator if present
			if let Some(validator) = &field.validator {
				validator(value).map_err(|msg| ValidationError::InvalidValue {
					field: field.name.clone(),
					message: msg,
				})?;
			}
		}

		// Check optional fields if present
		for field in &self.optional {
			if let Some(value) = table.get(&field.name) {
				validate_field_type(&field.name, value, &field.field_type)?;

				// Run custom validator if present
				if let Some(validator) = &field.validator {
					validator(value).map_err(|msg| ValidationError::InvalidValue {
						field: field.name.clone(),
						message: msg,
					})?;
				}
			}
		}

		Ok(())
	}
}

/// Validates that a value matches the expected field type.
fn validate_field_type(
	field_name: &str,
	value: &toml::Value,
	expected_type: &FieldType,
) -> Result<(), ValidationError> {
	match expected_type {
		FieldType::String => {
			if !value.is_str() {
				return Err(ValidationError::TypeMismatch {
					field: field_name.to_string(),
					expected: "string".to_string(),
					actual: value.type_str().to_string(),
				});
			}
		}
		FieldType::Integer { min, max } => {
			let int_val = value
				.as_integer()
				.ok_or_else(|| ValidationError::TypeMismatch {
					field: field_name.to_string(),
					expected: "integer".to_string(),
					actual: value.type_str().to_string(),
				})?;

			if let Some(min_val) = min {
				if int_val < *min_val {
					return Err(ValidationError::InvalidValue {
						field: field_name.to_string(),
						message: format!("Value {} is less than minimum {}", int_val, min_val),
					});
				}
			}

			if let Some(max_val) = max {
				if int_val > *max_val {
					return Err(ValidationError::InvalidValue {
						field: field_name.to_string(),
						message: format!("Value {} is greater than maximum {}", int_val, max_val),
					});
				}
			}
		}
		FieldType::Boolean => {
			if !value.is_bool() {
				return Err(ValidationError::TypeMismatch {
					field: field_name.to_string(),
					expected: "boolean".to_string(),
					actual: value.type_str().to_string(),
				});
			}
		}
		FieldType::Array(inner_type) => {
			let array = value
				.as_array()
				.ok_or_else(|| ValidationError::TypeMismatch {
					field: field_name.to_string(),
					expected: "array".to_string(),
					actual: value.type_str().to_string(),
				})?;

			for (i, item) in array.iter().enumerate() {
				validate_field_type(&format!("{}[{}]", field_name, i), item, inner_type)?;
			}
		}
		FieldType::Table(schema) => {
			schema.validate(value).map_err(|e| match e {
				ValidationError::MissingField(f) => {
					ValidationError::MissingField(format!("{}.{}", field_name, f))
				}
				ValidationError::InvalidValue { field, message } => ValidationError::InvalidValue {
					field: format!("{}.{}", field_name, field),
					message,
				},
				ValidationError::TypeMismatch {
					field,
					expected,
					actual,
				} => ValidationError::TypeMismatch {
					field: format!("{}.{}", field_name, field),
					expected,
					actual,
				},
				other => other,
			})?;
		}
	}

	Ok(())
}

/// Trait defining a configuration schema that can validate TOML values.
#[async_trait]
pub trait ConfigSchema: Send + Sync {
	/// Validates a TOML configuration value against this schema.
	///
	/// This method should check:
	/// - Required fields are present
	/// - Field types are correct
	/// - Values meet any constraints (ranges, patterns, etc.)
	fn validate(&self, config: &toml::Value) -> Result<(), ValidationError>;
}
