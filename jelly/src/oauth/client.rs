use lazy_static::lazy_static;
use oauth2::basic::BasicClient;
use oauth2::{url, AuthUrl, ClientId, ClientSecret, RedirectUrl, RevocationUrl, TokenUrl};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

use crate::oauth::{ProviderHints, ScopedClient, UserInfo, UserInfoDeserializer};

struct ClientConfig<'a> {
    redirect_uri: &'a str,
    client_id_env: &'a str,
    client_secret_env: Option<&'a str>,
    auth_url: &'a str,
    token_url: &'a str,
    revoke_url: Option<&'a str>,
    scopes: &'a [&'a str],
    login_hint_key: Option<&'a str>,
    user_info_uri: &'a str,
    user_info_params: &'a [(&'a str, &'a str)],
    user_info_headers: &'a [(&'a [u8], &'a str)],
    user_info_de: UserInfoDeserializer,
}

type HintMap = HashMap<&'static str, ProviderHints>;

type ClientMap = HashMap<String, Option<ScopedClient>>;

lazy_static! {
    static ref LOGIN_HINTS: Arc<Mutex<HintMap>> = Arc::new(Mutex::new(build_hints()));
    static ref CLIENTS: Arc<Mutex<ClientMap>> = Arc::new(Mutex::new(HashMap::new()));
}

pub const DEFAULT_PROVIDER: &str = "google";

pub fn valid_provider(provider: &str) -> bool {
    LOGIN_HINTS.lock().unwrap().contains_key(provider)
}

pub fn provider_hints(provider: &str) -> Option<ProviderHints> {
    LOGIN_HINTS.lock().unwrap().get(provider).copied()
}

fn build_hints() -> HintMap {
    let mut hints = HashMap::new();
    hints.insert(
        "google",
        ProviderHints {
            uses_email_hint: true,
        },
    );
    hints.insert(
        "twitter",
        ProviderHints {
            uses_email_hint: false,
        },
    );
    hints.insert(
        "github",
        ProviderHints {
            uses_email_hint: false,
        },
    );
    hints
}

// TODO is there a better return value than client.clone() ?
pub fn client_for(provider: &str) -> Option<ScopedClient> {
    if valid_provider(provider) {
        let mut provider_map = CLIENTS.lock().unwrap();
        if !provider_map.contains_key(provider) {
            // Important: the root domain host cannot have a numeric IP address.
            let root_domain = env::var("JELLY_DOMAIN").expect("JELLY_DOMAIN not set!");
            // Important: the redirect_uri must have the trailing slash,
            // and it must be registered with the OAuth provider.
            let redirect_uri = format!("{}/oauth/callback/", root_domain);
            let client = build_client(provider, &redirect_uri);
            provider_map.insert(provider.to_owned(), client);
        }
        match provider_map.get(provider) {
            Some(Some(client)) => Some(client.clone()),
            _ => None,
        }
    } else {
        None
    }
}

/// Redirect URI must match exactly with registered.
fn build_client<'a>(provider: &'a str, redirect_uri: &'a str) -> Option<ScopedClient> {
    match provider {
        "google" => Some(ClientConfig {
            redirect_uri,
            client_id_env: "GOOGLE_CLIENT_ID",
            client_secret_env: Some("GOOGLE_CLIENT_SECRET"),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            revoke_url: Some("https://oauth2.googleapis.com/revoke"),
            scopes: &[
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
            ],
            login_hint_key: Some("login_hint"),
            user_info_uri: "https://www.googleapis.com/oauth2/v3/userinfo",
            user_info_params: &[],
            user_info_headers: &[(b"Accept", "application/json")],
            user_info_de: google_de,
        }),
        "twitter" => Some(ClientConfig {
            redirect_uri,
            client_id_env: "TWITTER_CLIENT_ID",
            client_secret_env: None,
            auth_url: "https://twitter.com/i/oauth2/authorize",
            token_url: "https://api.twitter.com/2/oauth2/token",
            revoke_url: Some("https://api.twitter.com/2/oauth2/revoke"),
            scopes: &["tweet.read", "users.read"],
            login_hint_key: None,
            user_info_uri: "https://api.twitter.com/2/users/me",
            user_info_params: &[(
                "user.fields",
                "id,name,username,verified,url,profile_image_url",
            )],
            user_info_headers: &[(b"Accept", "application/json")],
            user_info_de: twitter_de,
        }),
        "github" => Some(ClientConfig {
            redirect_uri,
            client_id_env: "GITHUB_CLIENT_ID",
            client_secret_env: Some("GITHUB_CLIENT_SECRET"),
            auth_url: "https://github.com/login/oauth/authorize",
            token_url: "https://github.com/login/oauth/access_token",
            revoke_url: Some("https://api.twitter.com/2/oauth2/revoke"),
            scopes: &["read:user"],
            login_hint_key: Some("login"),
            user_info_uri: "https://api.github.com/user",
            user_info_params: &[],
            user_info_headers: &[
                (b"Accept", "application/vnd.github.v3+json"),
                (b"User-Agent", "Zingg-Starter-App"),
            ],
            user_info_de: github_de,
        }),
        _ => None,
    }
    .map(build_generic_oauth)
}

fn build_generic_oauth(cfg: ClientConfig) -> ScopedClient {
    let client_id = ClientId::new(env::var(cfg.client_id_env).expect(&format!(
        "Missing the {} environment variable.",
        cfg.client_id_env
    )));
    let client_secret = cfg.client_secret_env.map(|secret_env| {
        ClientSecret::new(
            env::var(secret_env)
                .expect(&format!("Missing the {} environment variable.", secret_env)),
        )
    });
    let auth_url =
        AuthUrl::new(cfg.auth_url.to_string()).expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new(cfg.token_url.to_string()).expect("Invalid token endpoint URL");

    let mut inner = BasicClient::new(client_id, client_secret, auth_url, Some(token_url))
        .set_redirect_uri(
            RedirectUrl::new(cfg.redirect_uri.to_string()).expect("Invalid redirect URL"),
        );

    if let Some(revoke_url) = cfg.revoke_url {
        let revocation_url =
            RevocationUrl::new(revoke_url.to_string()).expect("Invalid revocation endpoint URL");
        inner = inner.set_revocation_uri(revocation_url);
    }

    ScopedClient {
        inner,
        scopes: array_str_to_vec(cfg.scopes),
        user_info_uri: cfg.user_info_uri.to_owned(),
        login_hint_key: cfg.login_hint_key.map(|key| key.to_string()),
        user_info_params: array_tuple_str_to_vec(cfg.user_info_params),
        user_info_headers: array_tuple_u8_to_vec(cfg.user_info_headers),
        user_info_de: cfg.user_info_de,
    }
}

fn array_str_to_vec(a: &[&str]) -> Vec<String> {
    a.iter().map(|&x| x.into()).collect()
}

fn array_tuple_str_to_vec(a: &[(&str, &str)]) -> Vec<(String, String)> {
    a.iter().map(|&(k, v)| (k.into(), v.into())).collect()
}

fn array_tuple_u8_to_vec(a: &[(&[u8], &str)]) -> Vec<(Vec<u8>, String)> {
    a.iter().map(|&(k, v)| (k.into(), v.into())).collect()
}

// Google `userinfo` endpoint
#[derive(Debug, Deserialize, Serialize)]
struct GoogleUserInfo {
    sub: String,
    name: String,
    email: String,
    given_name: Option<String>,
    family_name: Option<String>,
    email_verified: Option<bool>,
    locale: Option<String>,
    // picture: Option<url::Url>,
}

impl From<GoogleUserInfo> for UserInfo {
    fn from(google: GoogleUserInfo) -> Self {
        UserInfo {
            provider: "google",
            id: google.sub,
            name: google.name,
            username: google.email.clone(),
            login_email: String::new(),
            provider_email: Some(google.email),
        }
    }
}

fn set_email(ui: UserInfo, email: &str) -> UserInfo {
    UserInfo {
        login_email: email.to_owned(),
        ..ui
    }
}

fn google_de(json_body: &str, email: &str) -> serde_json::Result<UserInfo> {
    serde_json::from_str::<GoogleUserInfo>(json_body)
        .map(|google| google.into())
        .map(|ui| set_email(ui, email))
}

// Twitter `users/me` endpoint
#[derive(Debug, Deserialize, Serialize)]
struct TwitterUserInfo {
    id: String,
    name: String,
    username: String,
    verified: Option<bool>,
    url: Option<url::Url>,
    // profile_image_url: Option<url::Url>,
}

impl From<TwitterUserInfo> for UserInfo {
    fn from(twitter: TwitterUserInfo) -> Self {
        UserInfo {
            provider: "twitter",
            id: twitter.id,
            name: twitter.name,
            username: twitter.username,
            login_email: String::new(),
            provider_email: None,
        }
    }
}

fn twitter_de(json_body: &str, email: &str) -> serde_json::Result<UserInfo> {
    serde_json::from_str::<TwitterUserInfo>(json_body)
        .map(|twitter| twitter.into())
        .map(|ui| set_email(ui, email))
}

// Github `users` endpoint
// https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
#[derive(Debug, Deserialize, Serialize)]
struct GithubUserInfo {
    id: i32,
    name: String,
    login: String,
    email: Option<String>,
    html_url: Option<url::Url>,
    // avatar_url: Option<url::Url>,
}

impl From<GithubUserInfo> for UserInfo {
    fn from(github: GithubUserInfo) -> Self {
        UserInfo {
            provider: "github",
            id: github.id.to_string(),
            name: github.name,
            username: github.login,
            login_email: String::new(),
            provider_email: github.email,
        }
    }
}

fn github_de(json_body: &str, email: &str) -> serde_json::Result<UserInfo> {
    serde_json::from_str::<GithubUserInfo>(json_body)
        .map(|github| github.into())
        .map(|ui| set_email(ui, email))
}
