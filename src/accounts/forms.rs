use jelly::forms::{EmailField, PasswordPolicy, PasswordField, TextField};
use jelly::forms::validation::{concat_results, Validatable, ValidationErrors};
use serde::{Deserialize, Serialize};

fn default_redirect_path() -> String {
    "/".into()
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct LoginForm {
    pub email: EmailField,
    pub password: TextField, // not checking strength, just presence
    #[serde(default = "default_redirect_path")]
    pub redirect: String,
}

impl LoginForm {
    pub fn set_keys(mut self) -> Self {
        self.email = self.email.with_key("email");
        self.password = self.password.with_key("password");
        self
    }
}

impl Validatable<String> for LoginForm {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        concat_results(vec![self.email.validate(), self.password.validate()])
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NewAccountForm {
    #[serde(skip)]
    pub policy: PasswordPolicy,
    pub name: TextField,
    pub email: EmailField,
    pub password: PasswordField,
}

impl NewAccountForm {
    pub fn set_keys(mut self) -> Self {
        self.name = self.name.with_key("name");
        self.email = self.email.with_key("email");
        self.password = self.password.with_key("password");
        self
    }
}

impl Validatable<String> for NewAccountForm {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        concat_results(vec![
            self.name.validate(),
            self.email.validate(),
            self.password.validate_with(&[&self.name, &self.email], &self.policy)
        ])
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct EmailForm {
    pub email: EmailField,
}

impl EmailForm {
    pub fn set_keys(mut self) -> Self {
        self.email = self.email.with_key("email");
        self
    }
}

impl Validatable<String> for EmailForm {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        self.email.validate()
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct ChangePasswordForm {
    // Unused in rendering, but stored here to enable password
    // checking with relative values.
    pub name: Option<String>,
    pub email: Option<String>,

    pub password: PasswordField,
    pub password_confirm: PasswordField,
}

impl ChangePasswordForm {
    pub fn set_keys(mut self) -> Self {
        self.password = self.password.with_key("password");
        self.password_confirm = self.password_confirm.with_key("password_confirm");
        self
    }

    pub fn set_name_and_email(mut self, name: &str, email: &str) -> Self {
        self.name = Some(name.to_owned());
        self.email = Some(email.to_owned());
        self
    }
}

impl Validatable<String> for ChangePasswordForm {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        let mut inputs: Vec<&str> = Vec::new();
        if let Some(name) = &self.name {
            inputs.push(name);
        }
        if let Some(email) = &self.email {
            inputs.push(email);
        }
        concat_results(vec![
            self.password.validate_with(&inputs, &PasswordPolicy::default()),
            self.password_confirm.validate_confirmation(&self.password.value)
        ])
    }
}
