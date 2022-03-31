use jelly::forms::{EmailField, TextField, Validation};
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

impl Validation for OAuthLoginForm {
    fn is_valid(&mut self) -> bool {
        !self.email_hint || self.email.is_valid()
    }
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
            email: EmailField::default()
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

impl Validation for LinkIdentityForm {
    fn is_valid(&mut self) -> bool {
        self.email.is_valid()
    }
}
