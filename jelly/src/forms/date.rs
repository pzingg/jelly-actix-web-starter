use std::fmt;
use std::ops::Deref;

use chrono::NaiveDate;
use serde::{Deserialize, Deserializer};

use super::validation::{Validatable, Validation, ValidationError, ValidationErrors, Validator};
use super::validators::required_key;

/// A field for accepting and validating a date string.
#[derive(Debug, Default)]
pub struct DateField {
    pub value: String,
    pub date: Option<chrono::NaiveDate>,
    pub key: String,
}

impl DateField {
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

    pub fn with_date(mut self) -> Self {
        self.date = NaiveDate::parse_from_str(&self.value, "%m/%d/%Y").ok();
        self
    }
}

impl From<String> for DateField {
    fn from(value: String) -> Self { Self::from_string(value) }
}

impl fmt::Display for DateField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<'de> Deserialize<'de> for DateField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(DateField::from_string)
    }
}

impl Deref for DateField {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Validatable<String> for DateField {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        let v: Validator<String, String> = Validator::<String, String>::new()
            .validation(required_key)
            .validation(|value: &String, key: &String| {
                match NaiveDate::parse_from_str(&value, "%m/%d/%Y") {
                    Ok(_date) => Ok(()),
                    Err(_) => {
                        Err(ValidationError::new(key.clone(), "INVALID_DATE")
                        .with_message(|_| "not a valid date: {}".to_owned())
                        .into())
                    },
                }
            });
        v.validate_value(&self.value, &self.key)
    }
}
