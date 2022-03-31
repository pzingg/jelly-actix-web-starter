use std::fmt;
use std::ops::Deref;

use super::Validation;
use chrono::NaiveDate;
use log::error;
use serde::{Deserialize, Deserializer};

/// A field for accepting and validating a date string.
#[derive(Debug, Default)]
pub struct DateField {
    pub value: String,
    pub date: Option<chrono::NaiveDate>,
    pub errors: Vec<String>,
}

impl DateField {
    pub fn from_string(value: String) -> Self {
        Self { value, ..Self::default() }
    }

    pub fn new<S>(value: S) -> Self where S: Into<String> {
        Self::from_string(value.into())
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

impl Validation for DateField {
    fn is_valid(&mut self) -> bool {
        match NaiveDate::parse_from_str(&self.value, "%m/%d/%Y") {
            Ok(date) => {
                self.date = Some(date);
                true
            }

            Err(e) => {
                error!("Error parsing DateField: {}", e);
                self.errors.push("Invalid date format.".to_string());
                false
            }
        }
    }
}
