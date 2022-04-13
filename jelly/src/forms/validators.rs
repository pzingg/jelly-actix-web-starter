use uuid::Uuid;

use super::validation::{ValidationError, ValidationErrors};

/// Just checks that key is present. Should be placed on every field.
pub fn required_key<Value>(_value: &Value, key: &String) -> Result<(), ValidationErrors<String>> {
  if key.is_empty() {
      Err(ValidationError::new(Uuid::new_v4().to_hyphenated().to_string(), "REQUIRED_KEY")
          .with_message(|_| "must have a unique key".to_owned())
          .into())
  } else {
      Ok(())
  }
}

/// Just checks that key is present. Should be placed on every field.
pub fn required_value(value: &String, key: &String) -> Result<(), ValidationErrors<String>> {
    if value.is_empty() {
        Err(ValidationError::new(key.clone(), "REQUIRED_VALUE")
            .with_message(|_| "cannot be blank".to_owned())
            .into())
    } else {
        Ok(())
    }
}
