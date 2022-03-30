use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::ops::Deref;
use validator::validate_email;

use super::Validation;

/// A field for validating that an email address is a valid address.
/// Mostly follows Django semantics.
#[derive(Debug, Default, Serialize)]
pub struct EmailField {
    pub value: String,
    pub errors: Vec<String>,
}

impl EmailField {
    pub fn new<S>(value: S) -> Self where S: Into<String> {
        Self { value: value.into(), errors: Vec::new() }
    }
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
        Deserialize::deserialize(deserializer).map(|t: String| EmailField::new(t))
    }
}

impl Deref for EmailField {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Validation for EmailField {
    fn is_valid(&mut self) -> bool {
        if self.value == "" {
            self.errors
                .push("Email address cannot be blank.".to_string());
            return false;
        }

        if !validate_email(&self.value) {
            self.errors.push("Invalid email format.".to_string());
            return false;
        }

        true
    }
}
