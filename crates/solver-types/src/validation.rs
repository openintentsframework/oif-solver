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

#[cfg(test)]
mod tests {
	use super::*;
	use toml::Value;

	#[test]
	fn test_validation_error_display() {
		let missing_field = ValidationError::MissingField("test_field".to_string());
		assert_eq!(
			missing_field.to_string(),
			"Missing required field: test_field"
		);

		let invalid_value = ValidationError::InvalidValue {
			field: "port".to_string(),
			message: "must be positive".to_string(),
		};
		assert_eq!(
			invalid_value.to_string(),
			"Invalid value for field 'port': must be positive"
		);

		let type_mismatch = ValidationError::TypeMismatch {
			field: "enabled".to_string(),
			expected: "boolean".to_string(),
			actual: "string".to_string(),
		};
		assert_eq!(
			type_mismatch.to_string(),
			"Type mismatch for field 'enabled': expected boolean, got string"
		);

		let deserialization_error =
			ValidationError::DeserializationError("invalid format".to_string());
		assert_eq!(
			deserialization_error.to_string(),
			"Failed to deserialize config: invalid format"
		);
	}

	#[test]
	fn test_field_creation() {
		let field = Field::new("test_field", FieldType::String);
		assert_eq!(field.name, "test_field");
		assert!(matches!(field.field_type, FieldType::String));
		assert!(field.validator.is_none());
	}

	#[test]
	fn test_field_with_validator() {
		let field = Field::new(
			"port",
			FieldType::Integer {
				min: None,
				max: None,
			},
		)
		.with_validator(|value| {
			let port = value.as_integer().unwrap();
			if port > 0 && port <= 65535 {
				Ok(())
			} else {
				Err("Port must be between 1 and 65535".to_string())
			}
		});

		assert_eq!(field.name, "port");
		assert!(field.validator.is_some());
	}

	#[test]
	fn test_field_debug() {
		let field = Field::new("test", FieldType::Boolean);
		let debug_str = format!("{:?}", field);
		assert!(debug_str.contains("Field"));
		assert!(debug_str.contains("test"));
		assert!(debug_str.contains("Boolean"));
	}

	#[test]
	fn test_schema_creation() {
		let required = vec![Field::new("name", FieldType::String)];
		let optional = vec![Field::new("enabled", FieldType::Boolean)];
		let schema = Schema::new(required, optional);

		assert_eq!(schema.required.len(), 1);
		assert_eq!(schema.optional.len(), 1);
		assert_eq!(schema.required[0].name, "name");
		assert_eq!(schema.optional[0].name, "enabled");
	}

	#[test]
	fn test_validate_string_field() {
		let schema = Schema::new(vec![Field::new("name", FieldType::String)], vec![]);

		let valid_config = toml::from_str(r#"name = "test""#).unwrap();
		assert!(schema.validate(&valid_config).is_ok());

		let invalid_config = toml::from_str(r#"name = 123"#).unwrap();
		let result = schema.validate(&invalid_config);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::TypeMismatch { .. }
		));
	}

	#[test]
	fn test_validate_integer_field() {
		let schema = Schema::new(
			vec![Field::new(
				"port",
				FieldType::Integer {
					min: Some(1),
					max: Some(65535),
				},
			)],
			vec![],
		);

		let valid_config = toml::from_str(r#"port = 8080"#).unwrap();
		assert!(schema.validate(&valid_config).is_ok());

		let too_small = toml::from_str(r#"port = 0"#).unwrap();
		let result = schema.validate(&too_small);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::InvalidValue { .. }
		));

		let too_large = toml::from_str(r#"port = 70000"#).unwrap();
		let result = schema.validate(&too_large);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::InvalidValue { .. }
		));
	}

	#[test]
	fn test_validate_boolean_field() {
		let schema = Schema::new(vec![Field::new("enabled", FieldType::Boolean)], vec![]);

		let valid_config = toml::from_str(r#"enabled = true"#).unwrap();
		assert!(schema.validate(&valid_config).is_ok());

		let invalid_config = toml::from_str(r#"enabled = "yes""#).unwrap();
		let result = schema.validate(&invalid_config);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::TypeMismatch { .. }
		));
	}

	#[test]
	fn test_validate_array_field() {
		let schema = Schema::new(
			vec![Field::new(
				"tags",
				FieldType::Array(Box::new(FieldType::String)),
			)],
			vec![],
		);

		let valid_config = toml::from_str(r#"tags = ["tag1", "tag2"]"#).unwrap();
		assert!(schema.validate(&valid_config).is_ok());

		let invalid_config = toml::from_str(r#"tags = [1, 2, 3]"#).unwrap();
		let result = schema.validate(&invalid_config);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::TypeMismatch { .. }
		));
	}

	#[test]
	fn test_validate_nested_table() {
		let nested_schema = Schema::new(
			vec![Field::new("host", FieldType::String)],
			vec![Field::new(
				"port",
				FieldType::Integer {
					min: None,
					max: None,
				},
			)],
		);

		let schema = Schema::new(
			vec![Field::new("database", FieldType::Table(nested_schema))],
			vec![],
		);

		let valid_config = toml::from_str(
			r#"
			[database]
			host = "localhost"
			port = 5432
		"#,
		)
		.unwrap();
		assert!(schema.validate(&valid_config).is_ok());

		let invalid_config = toml::from_str(
			r#"
			[database]
			port = 5432
		"#,
		)
		.unwrap();
		let result = schema.validate(&invalid_config);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::MissingField(_)
		));
	}

	#[test]
	fn test_missing_required_field() {
		let schema = Schema::new(
			vec![Field::new("required_field", FieldType::String)],
			vec![],
		);

		let config = toml::from_str(r#"other_field = "value""#).unwrap();
		let result = schema.validate(&config);
		assert!(result.is_err());

		if let ValidationError::MissingField(field) = result.unwrap_err() {
			assert_eq!(field, "required_field");
		} else {
			panic!("Expected MissingField error");
		}
	}

	#[test]
	fn test_optional_field_validation() {
		let schema = Schema::new(
			vec![Field::new("name", FieldType::String)],
			vec![Field::new("enabled", FieldType::Boolean)],
		);

		// Config without optional field should be valid
		let config_without_optional = toml::from_str(r#"name = "test""#).unwrap();
		assert!(schema.validate(&config_without_optional).is_ok());

		// Config with valid optional field should be valid
		let config_with_optional = toml::from_str(
			r#"
			name = "test"
			enabled = true
		"#,
		)
		.unwrap();
		assert!(schema.validate(&config_with_optional).is_ok());

		// Config with invalid optional field should fail
		let config_with_invalid_optional = toml::from_str(
			r#"
			name = "test"
			enabled = "yes"
		"#,
		)
		.unwrap();
		let result = schema.validate(&config_with_invalid_optional);
		assert!(result.is_err());
	}

	#[test]
	fn test_custom_validator_success() {
		let field = Field::new(
			"port",
			FieldType::Integer {
				min: None,
				max: None,
			},
		)
		.with_validator(|value| {
			let port = value.as_integer().unwrap();
			if port > 1024 {
				Ok(())
			} else {
				Err("Port must be greater than 1024".to_string())
			}
		});

		let schema = Schema::new(vec![field], vec![]);
		let config = toml::from_str(r#"port = 8080"#).unwrap();
		assert!(schema.validate(&config).is_ok());
	}

	#[test]
	fn test_custom_validator_failure() {
		let field = Field::new(
			"port",
			FieldType::Integer {
				min: None,
				max: None,
			},
		)
		.with_validator(|value| {
			let port = value.as_integer().unwrap();
			if port > 1024 {
				Ok(())
			} else {
				Err("Port must be greater than 1024".to_string())
			}
		});

		let schema = Schema::new(vec![field], vec![]);
		let config = toml::from_str(r#"port = 80"#).unwrap();
		let result = schema.validate(&config);
		assert!(result.is_err());

		if let ValidationError::InvalidValue { field, message } = result.unwrap_err() {
			assert_eq!(field, "port");
			assert_eq!(message, "Port must be greater than 1024");
		} else {
			panic!("Expected InvalidValue error");
		}
	}

	#[test]
	fn test_validate_non_table_root() {
		let schema = Schema::new(vec![], vec![]);
		let invalid_root = Value::String("not a table".to_string());
		let result = schema.validate(&invalid_root);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::TypeMismatch { .. }
		));
	}

	#[test]
	fn test_integer_bounds() {
		let schema = Schema::new(
			vec![Field::new(
				"count",
				FieldType::Integer {
					min: Some(0),
					max: Some(100),
				},
			)],
			vec![],
		);

		// Valid values
		let valid_configs = [r#"count = 0"#, r#"count = 50"#, r#"count = 100"#];

		for config_str in &valid_configs {
			let config = toml::from_str(config_str).unwrap();
			assert!(
				schema.validate(&config).is_ok(),
				"Failed for config: {}",
				config_str
			);
		}

		// Invalid values
		let invalid_configs = [r#"count = -1"#, r#"count = 101"#];

		for config_str in &invalid_configs {
			let config = toml::from_str(config_str).unwrap();
			let result = schema.validate(&config);
			assert!(
				result.is_err(),
				"Should have failed for config: {}",
				config_str
			);
			assert!(matches!(
				result.unwrap_err(),
				ValidationError::InvalidValue { .. }
			));
		}
	}

	#[test]
	fn test_array_of_integers() {
		let schema = Schema::new(
			vec![Field::new(
				"numbers",
				FieldType::Array(Box::new(FieldType::Integer {
					min: None,
					max: None,
				})),
			)],
			vec![],
		);

		let valid_config = toml::from_str(r#"numbers = [1, 2, 3]"#).unwrap();
		assert!(schema.validate(&valid_config).is_ok());

		let invalid_config = toml::from_str(r#"numbers = [1, "two", 3]"#).unwrap();
		let result = schema.validate(&invalid_config);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::TypeMismatch { .. }
		));
	}

	#[test]
	fn test_empty_array() {
		let schema = Schema::new(
			vec![Field::new(
				"items",
				FieldType::Array(Box::new(FieldType::String)),
			)],
			vec![],
		);

		let config = toml::from_str(r#"items = []"#).unwrap();
		assert!(schema.validate(&config).is_ok());
	}

	#[test]
	fn test_nested_error_paths() {
		let nested_schema = Schema::new(
			vec![Field::new("required_nested", FieldType::String)],
			vec![],
		);

		let schema = Schema::new(
			vec![Field::new("config", FieldType::Table(nested_schema))],
			vec![],
		);

		let invalid_config = toml::from_str(
			r#"
			[config]
			other_field = "value"
		"#,
		)
		.unwrap();

		let result = schema.validate(&invalid_config);
		assert!(result.is_err());

		if let ValidationError::MissingField(field) = result.unwrap_err() {
			assert_eq!(field, "config.required_nested");
		} else {
			panic!("Expected MissingField error with nested path");
		}
	}

	#[test]
	fn test_complex_nested_structure() {
		let database_schema = Schema::new(
			vec![
				Field::new("host", FieldType::String),
				Field::new(
					"port",
					FieldType::Integer {
						min: Some(1),
						max: Some(65535),
					},
				),
			],
			vec![Field::new(
				"timeout",
				FieldType::Integer {
					min: Some(0),
					max: None,
				},
			)],
		);

		let schema = Schema::new(
			vec![
				Field::new("app_name", FieldType::String),
				Field::new("database", FieldType::Table(database_schema)),
			],
			vec![],
		);

		let valid_config = toml::from_str(
			r#"
			app_name = "my_app"
			
			[database]
			host = "localhost"
			port = 5432
			timeout = 30
		"#,
		)
		.unwrap();

		assert!(schema.validate(&valid_config).is_ok());
	}

	// Test implementation of ConfigSchema trait
	struct TestConfigSchema {
		schema: Schema,
	}

	impl TestConfigSchema {
		fn new() -> Self {
			let schema = Schema::new(vec![Field::new("test_field", FieldType::String)], vec![]);
			Self { schema }
		}
	}

	#[async_trait]
	impl ConfigSchema for TestConfigSchema {
		fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
			self.schema.validate(config)
		}
	}

	#[test]
	fn test_config_schema_trait() {
		let config_schema = TestConfigSchema::new();

		let valid_config = toml::from_str(r#"test_field = "value""#).unwrap();
		assert!(config_schema.validate(&valid_config).is_ok());

		let invalid_config = toml::from_str(r#"other_field = "value""#).unwrap();
		let result = config_schema.validate(&invalid_config);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ValidationError::MissingField(_)
		));
	}

	#[test]
	fn test_integer_no_bounds() {
		let schema = Schema::new(
			vec![Field::new(
				"value",
				FieldType::Integer {
					min: None,
					max: None,
				},
			)],
			vec![],
		);

		let configs = [r#"value = -1000"#, r#"value = 0"#, r#"value = 1000000"#];

		for config_str in &configs {
			let config = toml::from_str(config_str).unwrap();
			assert!(
				schema.validate(&config).is_ok(),
				"Failed for: {}",
				config_str
			);
		}
	}

	#[test]
	fn test_nested_array_of_tables() {
		let item_schema = Schema::new(
			vec![Field::new("name", FieldType::String)],
			vec![Field::new("enabled", FieldType::Boolean)],
		);

		let schema = Schema::new(
			vec![Field::new(
				"items",
				FieldType::Array(Box::new(FieldType::Table(item_schema))),
			)],
			vec![],
		);

		let valid_config = toml::from_str(
			r#"
			[[items]]
			name = "item1"
			enabled = true
			
			[[items]]
			name = "item2"
		"#,
		)
		.unwrap();

		assert!(schema.validate(&valid_config).is_ok());
	}

	#[test]
	fn test_error_propagation_in_nested_structures() {
		let nested_schema = Schema::new(vec![Field::new("inner", FieldType::String)], vec![]);

		let schema = Schema::new(
			vec![Field::new("outer", FieldType::Table(nested_schema))],
			vec![],
		);

		let config = toml::from_str(
			r#"
			[outer]
			inner = 123
		"#,
		)
		.unwrap();

		let result = schema.validate(&config);
		assert!(result.is_err());

		if let ValidationError::TypeMismatch {
			field,
			expected,
			actual,
		} = result.unwrap_err()
		{
			assert_eq!(field, "outer.inner");
			assert_eq!(expected, "string");
			assert_eq!(actual, "integer");
		} else {
			panic!("Expected TypeMismatch error with nested path");
		}
	}
}
