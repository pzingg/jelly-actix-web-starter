//! Implements a set of input types that can be used for Form handling. Mostly modeled after
//! Django's Form class.
//!
//! Example:
//!
//! ```rust
//! use jelly::forms::{EmailField, PasswordField};
//! use jelly::forms::validation::{concat_results, Validatable, ValidationErrors};
//! use serde::Deserialize;
//!
//! #[derive(Debug, Default, Deserialize)]
//! pub struct MyForm {
//!     pub email: EmailField,
//!     pub password: PasswordField
//! }
//!
//! impl Validatable<String> for MyForm {
//!     fn validate(&self) -> Result<(), ValidationErrors<String>> {
//!         concat_results(
//!             vec![
//!                 self.email.validate(),
//!                 self.password.validate(),
//!             ]
//!         )
//!     }
//! }
//! ```

mod booly;
pub use booly::BoolField;

mod date;
pub use date::DateField;

mod email;
pub use email::EmailField;

mod password;
pub use password::{split_inputs, PasswordPolicy, PasswordField};

mod slug;
pub use slug::SlugField;

mod text;
pub use text::TextField;

pub use form_validation as validation;

mod validators;
pub use validators::required_key;
