use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::ops::Deref;
use validator::validate_email;

use super::validation::{Validatable, Validation, ValidationError, ValidationErrors, Validator};
use super::validators::{required_key, required_value};

/// A field for validating that an email address is a valid address.
/// Mostly follows Django semantics.
#[derive(Debug, Default, Serialize)]
pub struct EmailField {
    pub value: String,
    pub key: String,
}

impl EmailField {
    pub fn from_string(value: String) -> Self {
        Self { value, ..Self::default() }
    }

    pub fn new<S>(value: S) -> Self where S: Into<String> {
        Self::from_string(value.into())
    }

    pub fn with_key<S>(mut self, key: S) -> Self where S: Into<String> {
        self.key = key.into();
        self
    }
}

impl From<String> for EmailField {
    fn from(value: String) -> Self { Self::from_string(value) }
}

impl fmt::Display for EmailField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<'de> Deserialize<'de> for EmailField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(EmailField::from_string)
    }
}

impl Deref for EmailField {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Validatable<String> for EmailField {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        let v: Validator<String, String> = Validator::<String, String>::new()
            .validation(required_key)
            .validation(required_value)
            .validation(|value: &String, key: &String| {
                if validate_email(value) {
                    Ok(())
                } else {
                    Err(ValidationError::new(key.clone(), "INVALID_EMAIL")
                        .with_message(|_| "not a valid email address".to_owned())
                        .into())
                }
            });
        v.validate_value(&self.value, &self.key)
    }
}
