use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::ops::Deref;

use super::Validation;

/// A generic field for validating that an input is not blank.
/// In truth, if you don't want to easily check this, you could just use a
/// `String` instead - but if you want to keep the same conventions
/// (e.g, `errors`) then feel free to use this.
#[derive(Debug, Default, Serialize)]
pub struct TextField {
    pub value: String,
    pub errors: Vec<String>,
}

impl TextField {
    pub fn from_string(value: String) -> Self {
        Self { value, ..Self::default() }
    }

    pub fn new<S>(value: S) -> Self where S: Into<String> {
        Self::from_string(value.into())
    }
}

impl From<String> for TextField {
    fn from(value: String) -> Self { Self::from_string(value) }
}

impl fmt::Display for TextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<'de> Deserialize<'de> for TextField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(TextField::from_string)
    }
}

impl Deref for TextField {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Validation for TextField {
    fn is_valid(&mut self) -> bool {
        if self.value.is_empty() {
            self.errors.push("Value cannot be blank.".to_string());
            return false;
        }

        true
    }
}
