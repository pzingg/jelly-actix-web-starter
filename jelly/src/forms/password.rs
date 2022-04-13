use fancy_regex::Regex;
use lazy_static::lazy_static;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::ops::Deref;
use zxcvbn::zxcvbn;

use super::validation::{concat_results, Validatable, Validation, ValidationError, ValidationErrors, Validator};
use super::validators::{required_key, required_value};

/// A field for validating password strength. Will also include
/// hints on how to make a better password.
#[derive(Debug, Default, Serialize)]
pub struct PasswordField {
    pub value: String,
    pub key: String,
}

impl PasswordField {
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

    pub fn validate_with(&self, user_inputs: &[&str], cfg: &PasswordPolicy) -> Result<(), ValidationErrors<String>> {
        let _ok = self.validate()?;

        let length_validation = match &cfg.length {
            Some(length) => {
                self.validate_length(length.0, length.1)
            },
            _ => Ok(()),
        };
        let regex_validation = match &cfg.regex {
            Some(regex) => {
                let re = Regex::new(&regex.pattern).unwrap();
                self.validate_regex(&re, regex.message.clone())
            },
            _ => Ok(()),
        };
        let strength_validation = match &cfg.strength {
            Some(strength) => self.validate_strength(strength.clone(), user_inputs),
            _ => Ok(()),
        };

        concat_results(vec![length_validation, regex_validation, strength_validation])
    }

    pub fn validate_confirmation(&self, confirm: &str) -> Result<(), ValidationErrors<String>> {
        if self.value == confirm {
            Ok(())
        } else {
            Err(ValidationError::new(self.key.clone(), "PASSWORD_CONFIRMATION")
                .with_message(move |_| "passwords must match".to_owned())
                .into())
        }
    }

    pub fn validate_length(&self, min_length: usize, max_length: usize) -> Result<(), ValidationErrors<String>> {
        match self.value.len() {
            0 => Ok(()), // already validated
            x if x < min_length =>
                Err(ValidationError::new(self.key.clone(), "PASSWORD_MIN_LENGTH")
                .with_message(move |_| format!("must be at least {} characters", min_length))
                .into()),
            x if x > max_length =>
                Err(ValidationError::new(self.key.clone(), "PASSWORD_MAX_LENGTH")
                .with_message(move |_| format!("must be at most {} characters", max_length))
                .into()),
            _ => Ok(()),
        }
    }

    pub fn validate_regex(&self, regex: &Regex, message: String) -> Result<(), ValidationErrors<String>> {
        if regex.is_match(&self.value).unwrap() {
            Ok(())
        } else {
            Err(ValidationError::new(self.key.clone(), "PASSWORD_FORMAT")
                .with_message(move |_| message.clone())
                .into())
        }
    }

    pub fn validate_strength(&self, strength: PasswordScore, user_inputs: &[&str]) -> Result<(), ValidationErrors<String>> {
        // The unwrap is safe, as it only errors if the
        // password is blank, which we already
        // handle above.
        let words = split_inputs(user_inputs);
        let estimate = zxcvbn(&self.value,
            words
                .iter()
                .map(|s| s.as_ref())
                .collect::<Vec<&str>>()
                .as_slice()).unwrap();
        if estimate.score() >= strength as u8 {
            Ok(())
        } else {
            let mut hints: Vec<String> = Vec::new();
            let mut warning: Option<String> = None;
            if let Some(feedback) = estimate.feedback() {
                hints = feedback
                    .suggestions()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                warning = feedback
                    .warning()
                    .map(|w| w.to_string())
            }
            let mut errors: ValidationErrors<String> = ValidationError::new(self.key.clone(), "PASSWORD_STRENGTH")
                .with_message(move |_| match &warning {
                    Some(message) => format!("not strong enough. {}", message),
                    None => "not strong enough".to_owned()
                    }
                )
                .into();
            if !hints.is_empty() {
                errors.extend(ValidationError::new(self.key.clone(), "PASSWORD_HINTS")
                    .with_message(move |_| hints.join("\n"))
                    .into())
            }
            Err(errors)
        }
    }
}

impl From<String> for PasswordField {
    fn from(value: String) -> Self { Self::from_string(value) }
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
        Deserialize::deserialize(deserializer).map(PasswordField::from_string)
    }
}

impl Deref for PasswordField {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Validatable<String> for PasswordField {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        let v: Validator<String, String> = Validator::<String, String>::new()
            .validation(required_key)
            .validation(required_value);
        v.validate_value(&self.value, &self.key)
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegexConfig {
    pattern: String,
    message: String,
}

impl RegexConfig {
    fn new(pattern: &str, message: &str) -> Self {
        RegexConfig {
            pattern: pattern.to_owned(),
            message: message.to_owned(),
        }
    }
}

lazy_static! {
    pub static ref REGEX_ANH: RegexConfig = RegexConfig::new(
        r#"^[-a-zA-Z0-9]+$"#,
        "can only contain uppercase, lowercase, numbers, and hyphens."
    );
    pub static ref REGEX_ULNS: RegexConfig = RegexConfig::new(
        r#"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[-_.@#$%^&*!?])[-_.@#$%^&*!?a-zA-Z0-9]+$"#,
        "must contain at least one each of uppercase, lowercase, number, and symbol from this set: -_@#$%^&*!?."
    );
}

impl Default for RegexConfig {
    fn default() -> Self {
        REGEX_ANH.clone()
    }
}

#[repr(u8)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PasswordScore {
    TooGuessable = 0,      // risky password. (guesses < 10^3)
    VeryGuessable = 1,     // protection from throttled online attacks. (guesses < 10^6)
    SomewhatGuessable = 2, // protection from unthrottled online attacks. (guesses < 10^8)
    SafelyUnguessable = 3, // moderate protection from offline slow-hash scenario. (guesses < 10^10)
    VeryUnguessable = 4,   // strong protection from offline slow-hash scenario. (guesses >= 10^10)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordPolicy {
    length: Option<(usize, usize)>,
    regex: Option<RegexConfig>,
    strength: Option<PasswordScore>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicy {
            length: Some((8, 255)),
            regex: Some(REGEX_ANH.clone()),
            strength: Some(PasswordScore::SafelyUnguessable),
        }
    }
}

// DONE: removes all "non-word" chars,
// DONE: removes words 3 chars or shorter
// DONE: removes duplicates
pub fn split_inputs(inputs: &[&str]) -> Vec<String> {
    let splitter = Regex::new(r#"\W"#).unwrap();
    let mut uniques: HashSet<String> = HashSet::new();
    let mut result: Vec<String> = Vec::new();
    for input in inputs {
        let words: Vec<String> = splitter
            .replace_all(*input, " ")
            .split(' ')
            .filter(|w| w.len() > 3)
            .map(|w| w.to_lowercase())
            .collect();
        for word in words {
            if !uniques.contains(&word) {
                uniques.insert(word.clone());
                result.push(word);
            }
        }
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn splits_user_inputs() {
        let user_inputs = &["Peter Zingg", "peter.zingg@gmail.com"];
        let result = split_inputs(user_inputs);
        assert_eq!(result.len(), 3);
        assert_eq!(result, vec!["peter", "zingg", "gmail"])
    }
}
