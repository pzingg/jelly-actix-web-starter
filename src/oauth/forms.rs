use jelly::forms::{EmailField, TextField};
use jelly::forms::validation::{concat_results, Validatable, ValidationErrors};
use jelly::oauth;
use serde::{Deserialize, Serialize};

fn default_provider() -> String {
    oauth::client::DEFAULT_PROVIDER.to_string()
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct OAuthLoginForm {
    #[serde(default = "default_provider")]
    pub provider: String,
    pub email_hint: bool,
    pub email: EmailField,
}

impl OAuthLoginForm {
    pub fn new(provider: &str) -> Self {
        let provider = if oauth::client::valid_provider(provider) {
            provider
        } else {
            oauth::client::DEFAULT_PROVIDER
        };

        let hints = oauth::client::provider_hints(provider);
        OAuthLoginForm {
            provider: provider.to_string(),
            email_hint: hints.map_or(false, |hint| hint.uses_email_hint),
            ..OAuthLoginForm::default()
        }
    }

    pub fn set_keys(mut self) -> Self {
        self.email = self.email.with_key("email");
        self
    }
}

impl Validatable<String> for OAuthLoginForm {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        if self.email_hint {
            self.email.validate()
        } else {
            Ok(())
        }
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct LinkIdentityForm {
    pub provider: String,
    pub username: String,
    pub name: TextField,
    pub email: EmailField,
}

impl LinkIdentityForm {
    pub fn set_keys(mut self) -> Self {
        self.name = self.name.with_key("name");
        self.email = self.email.with_key("email");
        self
    }
}

impl Validatable<String> for LinkIdentityForm {
    fn validate(&self) -> Result<(), ValidationErrors<String>> {
        concat_results(vec![self.email.validate(), self.name.validate()])
    }
}
