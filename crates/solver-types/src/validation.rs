//! Configuration validation utilities for the OIF solver system.
//!
//! This module provides a flexible and type-safe framework for validating TOML configuration
//! files. It supports hierarchical validation with nested schemas, custom validators, and
//! detailed error reporting.

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

/// Represents the type of a configuration field.
///
/// This enum defines the possible types that a field in a TOML configuration
/// can have, including primitive types and complex structures.
#[derive(Debug)]
pub enum FieldType {
	/// A string value.
	String,
	/// An integer value with optional minimum and maximum bounds.
	Integer {
		/// Minimum allowed value (inclusive).
		min: Option<i64>,
		/// Maximum allowed value (inclusive).
		max: Option<i64>,
	},
	/// A boolean value (true/false).
	Boolean,
	/// An array of values, all of the same type.
	Array(Box<FieldType>),
	/// A nested table with its own schema.
	Table(Schema),
}

/// Type alias for field validator functions.
///
/// Validators are custom functions that can perform additional validation
/// beyond type checking. They receive a TOML value and return an error
/// message if validation fails.
pub type FieldValidator = Box<dyn Fn(&toml::Value) -> Result<(), String> + Send + Sync>;

/// Represents a field in a configuration schema.
///
/// A field has a name, a type, and an optional custom validator function.
/// Fields can be either required or optional within a schema.
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
	///
	/// # Arguments
	///
	/// * `name` - The name of the field as it appears in the TOML configuration
	/// * `field_type` - The expected type of the field
	pub fn new(name: impl Into<String>, field_type: FieldType) -> Self {
		Self {
			name: name.into(),
			field_type,
			validator: None,
		}
	}

	/// Adds a custom validator to this field.
	///
	/// Custom validators allow for complex validation logic beyond simple type checking.
	/// The validator function receives the field's value and should return an error
	/// message if validation fails.
	///
	/// # Arguments
	///
	/// * `validator` - A closure that validates the field value
	pub fn with_validator<F>(mut self, validator: F) -> Self
	where
		F: Fn(&toml::Value) -> Result<(), String> + Send + Sync + 'static,
	{
		self.validator = Some(Box::new(validator));
		self
	}
}

/// Defines a validation schema for TOML configuration.
///
/// A schema consists of required fields that must be present and optional
/// fields that may be present. Each field has a type and optional custom
/// validation logic.
///
/// Schemas can be nested to validate complex hierarchical configurations.
#[derive(Debug)]
pub struct Schema {
	pub required: Vec<Field>,
	pub optional: Vec<Field>,
}

impl Schema {
	/// Creates a new schema with required and optional fields.
	///
	/// # Arguments
	///
	/// * `required` - Fields that must be present in the configuration
	/// * `optional` - Fields that may be present but are not required
	pub fn new(required: Vec<Field>, optional: Vec<Field>) -> Self {
		Self { required, optional }
	}

	/// Validates a TOML value against this schema.
	///
	/// This method performs comprehensive validation:
	/// 1. Checks that all required fields are present
	/// 2. Validates the type of each field
	/// 3. Runs custom validators if defined
	/// 4. Recursively validates nested tables
	///
	/// # Arguments
	///
	/// * `config` - The TOML value to validate
	///
	/// # Returns
	///
	/// * `Ok(())` if validation succeeds
	/// * `Err(ValidationError)` with details about what failed
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - A required field is missing
	/// - A field has the wrong type
	/// - A custom validator fails
	/// - A nested schema validation fails
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
///
/// This function performs type checking and recursively validates nested structures.
/// For integers, it also checks min/max bounds. For arrays, it validates each element.
/// For tables, it delegates to the nested schema.
///
/// # Arguments
///
/// * `field_name` - The name of the field being validated (for error messages)
/// * `value` - The TOML value to validate
/// * `expected_type` - The expected type of the field
///
/// # Returns
///
/// * `Ok(())` if the value matches the expected type
/// * `Err(ValidationError)` with details about the type mismatch
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
		},
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
		},
		FieldType::Boolean => {
			if !value.is_bool() {
				return Err(ValidationError::TypeMismatch {
					field: field_name.to_string(),
					expected: "boolean".to_string(),
					actual: value.type_str().to_string(),
				});
			}
		},
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
		},
		FieldType::Table(schema) => {
			schema.validate(value).map_err(|e| match e {
				ValidationError::MissingField(f) => {
					ValidationError::MissingField(format!("{}.{}", field_name, f))
				},
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
		},
	}

	Ok(())
}

/// Trait defining a configuration schema that can validate TOML values.
///
/// Implement this trait to create custom configuration validators that can
/// be used across different parts of the application. This is particularly
/// useful for plugin systems or when you need polymorphic validation behavior.
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
