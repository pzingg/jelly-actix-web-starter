use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::ops::Deref;

use super::Validation;

/// A field for validating that a URL slug is valid for a URL.
#[derive(Debug, Default, Serialize)]
pub struct SlugField {
    pub value: String,
    pub errors: Vec<String>,
}


impl SlugField {
    pub fn from_string(value: String) -> Self {
        Self { value, ..Self::default() }
    }

    pub fn new<S>(value: S) -> Self where S: Into<String> {
        Self::from_string(value.into())
    }
}

impl From<String> for SlugField {
    fn from(value: String) -> Self { Self::from_string(value) }
}

impl fmt::Display for SlugField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<'de> Deserialize<'de> for SlugField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(SlugField::from_string)
    }
}

impl Deref for SlugField {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Validation for SlugField {
    fn is_valid(&mut self) -> bool {
        if self.value.is_empty() {
            self.errors.push("Slugs cannot be blank!".to_string());
        }

        if self.value.contains(' ') {
            self.errors.push("Slugs can't contain spaces.".to_string());
        }

        self.errors.is_empty()
    }
}
