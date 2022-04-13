use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::ops::Deref;

use super::validation::{Validatable, Validation, ValidationError, ValidationErrors, Validator};
use super::validators::{required_key, required_value};

/// A field for validating that a URL slug is valid for a URL.
#[derive(Debug, Default, Serialize)]
pub struct SlugField {
    pub value: String,
    pub key: String,
}


impl SlugField {
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

impl Validatable<String> for SlugField {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        let v: Validator<String, String> = Validator::<String, String>::new()
            .validation(required_key)
            .validation(required_value)
            .validation(|value: &String, key: &String| {
                if !value.contains(' ') {
                    Ok(())
                } else {
                    Err(ValidationError::new(key.clone(), "INVALID_SLUG")
                        .with_message(move |_|
                            "slugs cannot contain spaces".to_owned())
                        .into())
                }
            });
        v.validate_value(&self.value, &self.key)
    }
}
