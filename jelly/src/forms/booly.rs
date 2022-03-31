use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::ops::Deref;

use super::Validation;

/// A simple BoolField.
///
/// Checks to see if the value is `true` or not in validation. This means
/// that your input should literally pass `true` or `false`.
#[derive(Debug, Default, Serialize)]
pub struct BoolField {
    pub value: bool,
    pub errors: Vec<String>,
}

impl BoolField {
    pub fn new(value: bool) -> Self {
        Self { value, ..Self::default() }
    }
}

impl From<bool> for BoolField {
    fn from(value: bool) -> Self { Self::new(value) }
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

impl Validation for BoolField {
    fn is_valid(&mut self) -> bool { true }
}
