use fancy_regex::Regex;
use lazy_static::lazy_static;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::ops::Deref;
use zxcvbn::zxcvbn;

use super::Validation;

/// A field for validating password strength. Will also include
/// hints on how to make a better password.
#[derive(Debug, Default, Serialize)]
pub struct PasswordField {
    pub value: String,
    pub errors: Vec<String>,
    pub hints: Vec<String>,
}

impl PasswordField {
    pub fn validate_with(&mut self, user_inputs: &[&str], cfg: &PasswordConfig) -> bool {
        let length_valid = match &cfg.length {
            Some(length) => {
                self.validate_length(length.0, length.1)
            },
            _ => true,
        };
        let regex_valid = match &cfg.regex {
            Some(regex) => self.validate_regex(&regex.regex, &regex.message),
            _ => true,
        };
        let strength_valid = match cfg.strength {
            Some(strength) => self.validate_strength(strength, user_inputs),
            _ => true,
        };
        length_valid && regex_valid && strength_valid
    }

    pub fn validate_length(&mut self, min_length: usize, max_length: usize) -> bool {
        match self.value.len() {
            0 => {
                self.errors.push("Password cannot be blank.".to_owned());
                false
            }
            x if x < min_length => {
                self.errors.push(format!(
                    "Password must be at least {} characters.",
                    min_length
                ));
                false
            }
            x if x > max_length => {
                self.errors.push(format!(
                    "Password must be at most {} characters.",
                    max_length
                ));
                false
            }
            _ => true,
        }
    }

    pub fn validate_regex(&mut self, regex: &Regex, message: &str) -> bool {
        if regex.is_match(&self.value).unwrap() {
            true
        } else {
            self.errors.push(message.to_owned());
            false
        }
    }

    pub fn validate_strength(&mut self, strength: u8, user_inputs: &[&str]) -> bool {
        // The unwrap is safe, as it only errors if the
        // password is blank, which we already
        // handle above.
        let estimate = zxcvbn(&self.value, user_inputs).unwrap();
        if estimate.score() >= strength {
            true
        } else {
            if let Some(feedback) = estimate.feedback() {
                if let Some(warning) = feedback.warning() {
                    self.errors.push(format!("{}", warning));
                } else {
                    self.errors
                        .push(format!("{}", "Password not strong enough."));
                }

                self.hints = feedback
                    .suggestions()
                    .iter()
                    .map(|s| format!("{}", s))
                    .collect();
            }
            false
        }
    }
}

impl fmt::Display for PasswordField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<'de> Deserialize<'de> for PasswordField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(|t| PasswordField {
            value: t,
            errors: Vec::new(),
            hints: Vec::new(),
        })
    }
}

impl Deref for PasswordField {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Validation for PasswordField {
    fn is_valid(&mut self) -> bool {
        self.validate_with(&[], &PasswordConfig::default())
    }
}

#[derive(Clone, Debug)]
pub struct RegexConfig {
    regex: Regex,
    message: String,
}

impl RegexConfig {
    fn new(pattern: &str, message: &str) -> Self {
        RegexConfig {
            regex: Regex::new(pattern).unwrap(),
            message: message.to_owned(),
        }
    }
}

lazy_static! {
    pub static ref DEFAULT_REGEX: RegexConfig = RegexConfig::new(
        r#"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&*!?])[-_a-zA-Z0-9@#$%^&*!?]+$"#,
        "Password must contain upper, lower, number, symbol (@#$%^&*!?)."
    );
}

#[derive(Clone, Debug)]
pub struct PasswordConfig {
    length: Option<(usize, usize)>,
    regex: Option<RegexConfig>,
    strength: Option<u8>, // 3 is default
}

impl Default for PasswordConfig {
    fn default() -> Self {
        PasswordConfig {
            length: Some((8, 255)),
            regex: Some(DEFAULT_REGEX.clone()),
            strength: None,
        }
    }
}
