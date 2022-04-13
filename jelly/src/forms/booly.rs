use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::ops::Deref;

use super::validation::{Validatable, Validation, ValidationErrors, Validator};
use super::validators::required_key;

/// A simple BoolField.
///
/// Checks to see if the value is `true` or not in validation. This means
/// that your input should literally pass `true` or `false`.
#[derive(Debug, Default, Serialize)]
pub struct BoolField {
    pub value: bool,
    pub key: String,
}

impl BoolField {
    pub fn new(value: bool) -> Self {
        Self { value, ..Self::default() }
    }

    pub fn with_key<S>(mut self, key: S) -> Self where S: Into<String> {
        self.key = key.into();
        self
    }
}

impl fmt::Display for BoolField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<'de> Deserialize<'de> for BoolField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(BoolField::new)
    }
}

impl Deref for BoolField {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Validatable<String> for BoolField {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        let v: Validator<bool, String> = Validator::<bool, String>::new()
            .validation(required_key);
        v.validate_value(&self.value, &self.key)
    }
}
