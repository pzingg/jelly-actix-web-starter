use lazy_static::lazy_static;
use oauth2::basic::BasicClient;
use oauth2::{url, AuthUrl, ClientId, ClientSecret, RedirectUrl, RevocationUrl, TokenUrl};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

use crate::oauth::{ScopedClient, UserInfo, UserInfoDeserializer, UserInfoRequest};

pub const DEFAULT_PROVIDER: &str = "google";

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ProviderHints {
    pub uses_email_hint: bool,
}

type HintMap = HashMap<&'static str, ProviderHints>;

type ClientMap = HashMap<String, Option<ScopedClient>>;

// TODO 105: use once_cell get_or_init and/or once_cell:sync::Lazy
lazy_static! {
    static ref LOGIN_HINTS: Arc<Mutex<HintMap>> = Arc::new(Mutex::new(build_hints()));
    static ref CLIENTS: Arc<Mutex<ClientMap>> = Arc::new(Mutex::new(HashMap::new()));
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
    hints.insert(
        "facebook",
        ProviderHints {
            uses_email_hint: false,
        },
    );
    hints
}

pub fn valid_provider(provider: &str) -> bool {
    LOGIN_HINTS.lock().unwrap().contains_key(provider)
}

pub fn provider_hints(provider: &str) -> Option<ProviderHints> {
    LOGIN_HINTS.lock().unwrap().get(provider).copied()
}

pub fn client_for(provider: &str) -> Option<ScopedClient> {
    if valid_provider(provider) {
        let mut provider_map = CLIENTS.lock().unwrap();
        if !provider_map.contains_key(provider) {
            // Important: the root domain host cannot have a numeric IP address.
            let root_domain = env::var("JELLY_DOMAIN").expect("JELLY_DOMAIN not set!");
            // Important: the redirect_uri must have the trailing slash,
            // and it must be registered with the OAuth provider.
            let redirect_uri = format!("{}/oauth/callback", root_domain);
            let client = build_client(provider, &redirect_uri);
            provider_map.insert(provider.to_string(), client);
        }
        match provider_map.get(provider) {
            // TODO 104: can we avoid client.clone() ?
            Some(Some(client)) => Some(client.clone()),
            _ => None,
        }
    } else {
        None
    }
}

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
    user_info_deserializer: UserInfoDeserializer,
}

impl<'a> From<ClientConfig<'a>> for ScopedClient {
    fn from(cfg: ClientConfig<'a>) -> Self {
        let client_id = ClientId::new(
            env::var(cfg.client_id_env)
                .unwrap_or_else(|_| panic!("Missing the {} environment variable.", cfg.client_id_env)),
        );
        let client_secret = cfg.client_secret_env.map(|secret_env| {
            ClientSecret::new(
                env::var(secret_env)
                    .unwrap_or_else(|_| panic!("Missing the {} environment variable.", secret_env)),
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

        Self {
            inner,
            scopes: array_str_to_vec(cfg.scopes),
            login_hint_key: cfg.login_hint_key.map(|key| key.to_string()),
            user_info_request: UserInfoRequest {
                uri: cfg.user_info_uri.to_string(),
                params: array_tuple_str_to_vec(cfg.user_info_params),
                headers: array_tuple_u8_to_vec(cfg.user_info_headers),
                deserializer: cfg.user_info_deserializer,
            },
        }
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
            user_info_deserializer: deserialize_google,
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
            user_info_deserializer: deserialize_twitter,
        }),
        "github" => Some(ClientConfig {
            redirect_uri,
            client_id_env: "GITHUB_CLIENT_ID",
            client_secret_env: Some("GITHUB_CLIENT_SECRET"),
            auth_url: "https://github.com/login/oauth/authorize",
            token_url: "https://github.com/login/oauth/access_token",
            revoke_url: None,
            scopes: &["read:user"],
            login_hint_key: Some("login"),
            user_info_uri: "https://api.github.com/user",
            user_info_params: &[],
            user_info_headers: &[
                (b"Accept", "application/vnd.github.v3+json"),
                (b"User-Agent", "Zingg-Starter-App"),
            ],
            user_info_deserializer: deserialize_github,
        }),
        "facebook" => Some(ClientConfig {
            redirect_uri,
            client_id_env: "FACEBOOK_CLIENT_ID",
            client_secret_env: Some("FACEBOOK_CLIENT_SECRET"),
            auth_url: "https://www.facebook.com/v13.0/dialog/oauth",
            token_url: "https://graph.facebook.com/v13.0/oauth/access_token",
            revoke_url: None,
            scopes: &["public_profile", "email"],
            login_hint_key: None,
            user_info_uri: "https://graph.facebook.com/v13.0/me",
            user_info_params: &[],
            user_info_headers: &[(b"Accept", "application/json")],
            user_info_deserializer: deserialize_facebook,
        }),
        _ => None,
    }
    .map(|cfg| cfg.into())
}

fn deserialize_google(json_body: &str, email: &str) -> serde_json::Result<UserInfo> {
    parse_user_info::<GoogleUserInfo>(json_body, email)
}

fn deserialize_twitter(json_body: &str, email: &str) -> serde_json::Result<UserInfo> {
    parse_user_info::<TwitterUserInfo>(json_body, email)
}

fn deserialize_github(json_body: &str, email: &str) -> serde_json::Result<UserInfo> {
    parse_user_info::<GithubUserInfo>(json_body, email)
}

fn deserialize_facebook(json_body: &str, email: &str) -> serde_json::Result<UserInfo> {
    parse_user_info::<FacebookUserInfo>(json_body, email)
}

fn parse_user_info<'de, T: Deserialize<'de> + Into<UserInfo>>(
    json_body: &'de str,
    email: &str,
) -> serde_json::Result<UserInfo> {
    serde_json::from_str::<'de, T>(json_body)
        .map(|obj| obj.into())
        .map(|info| UserInfo {
            login_email: email.to_string(),
            ..info
        })
}

/// Google `userinfo` endpoint
/// See https://any-api.com/googleapis_com/oauth2/docs/userinfo/oauth2_userinfo_get
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
            username: Some(google.email.clone()),
            login_email: String::new(),
            provider_email: Some(google.email),
        }
    }
}

/// Twitter `users/me` endpoint
/// See https://developer.twitter.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me
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
            username: Some(twitter.username),
            provider_email: None,
            ..Default::default()
        }
    }
}

/// Github `users` endpoint
/// See https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
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
            username: Some(github.login),
            provider_email: github.email,
            ..Default::default()
        }
    }
}

/// Facebook `user` endpoint
/// See https://developers.facebook.com/docs/graph-api/reference/v13.0/user
#[derive(Debug, Deserialize, Serialize)]
struct FacebookUserInfo {
    id: String,
    name: String,
    email: Option<String>,
    verified: bool,
    link: url::Url,
}

impl From<FacebookUserInfo> for UserInfo {
    fn from(facebook: FacebookUserInfo) -> Self {
        UserInfo {
            provider: "facebook",
            id: facebook.id,
            name: facebook.name,
            username: None,
            provider_email: facebook.email,
            ..Default::default()
        }
    }
}
