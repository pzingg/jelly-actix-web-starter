use jelly::forms::{EmailField, Validation};
use serde::{Deserialize, Serialize};

fn default_provider() -> String {
    "google".into()
}

fn default_redirect_path() -> String {
    "/".into()
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct LoginForm {
    pub email: EmailField,

    #[serde(default = "default_provider")]
    pub provider: String,

    #[serde(default = "default_redirect_path")]
    pub redirect: String,
}

impl Validation for LoginForm {
    fn is_valid(&mut self) -> bool {
        self.email.is_valid()
    }
}
