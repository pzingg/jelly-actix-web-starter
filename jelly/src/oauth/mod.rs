//! URL dispatcher for oauth related API endpoints.

use std::collections::HashMap;
use std::{env, result, str};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::http::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use oauth2::http::method::Method;
use oauth2::reqwest::http_client;
use oauth2::{url, AccessToken, AuthorizationCode, ClientId, ClientSecret, PkceCodeVerifier, TokenResponse};
use serde::{Deserialize, Serialize};

use crate::error::OAuthError;


pub mod client;

const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_FORMENCODED: &str = "application/x-www-form-urlencoded";

// Google userinfo endpoint
#[derive(Debug, Deserialize, Serialize)]
pub struct UserInfo {
    pub sub: String,
    pub name: String,
    pub email: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email_verified: Option<bool>,
    pub locale: Option<String>,
    // pub picture: Option<Url>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OAuthFlow {
    pub provider_name: String,
    pub authorization_code: String,
    pub csrf_token_secret: String,
    pub pkce_verifier_secret: String,
}

#[derive(Debug)]
pub struct ClientFlow {
    pub client: BasicClient,
    pub flow: OAuthFlow,
}

impl OAuthFlow {
    pub fn set_authorization_code(mut self, code: &str) -> Self {
        self.authorization_code = code.to_owned();
        self
    }
}

type ProviderMap = HashMap<String, Option<BasicClient>>;

lazy_static! {
    static ref PROVIDER_NAMES: Vec<&'static str> = vec!["google"];
    static ref OAUTH_PROVIDERS: Arc<Mutex<ProviderMap>> = Arc::new(Mutex::new(HashMap::new()));
}

// TODO is there a better return value than client.clone() ?
pub fn client_for(provider_name: &str) -> Option<BasicClient> {
    if PROVIDER_NAMES.contains(&provider_name) {
        let mut provider_map = OAUTH_PROVIDERS.lock().unwrap();
        if !provider_map.contains_key(provider_name) {
            // Important: the root domain host cannot have a numeric IP address.
            let root_domain = env::var("JELLY_DOMAIN").expect("JELLY_DOMAIN not set!");
            // Important: the redirect_uri must have the trailing slash,
            // and it must be registered with the OAuth provider.
            let redirect_uri = url::Url::parse(&format!("{}/oauth/callback/", root_domain)).unwrap();
            let name = provider_name.to_owned();
            let client = build_client(provider_name, &redirect_uri);
            provider_map.insert(name, client);
        }
        match provider_map.get(provider_name) {
            Some(Some(client)) => Some(client.clone()),
            _ => None,
        }
    } else {
        None
    }
}

fn build_client(provider_name: &str, redirect_uri: &url::Url) -> Option<BasicClient> {
    match provider_name {
        "google" => Some(client::google_oauth(redirect_uri)),
        _ => None,
    }
}

pub fn request_token(client_flow: ClientFlow) -> result::Result<BasicTokenResponse, OAuthError> {
    let client = client_flow.client
        .exchange_code(AuthorizationCode::new(
            client_flow.flow.authorization_code.clone(),
        ))
        .set_pkce_verifier(PkceCodeVerifier::new(
            client_flow.flow.pkce_verifier_secret.clone(),
        ));
    client
        .request(http_client)
        .map_err(|e| OAuthError::GrantTokenError(e).into())
}

pub fn fetch_user_info(token_response: BasicTokenResponse) -> result::Result<UserInfo, OAuthError> {
    let access_token = token_response.access_token();
    let refresh_token = token_response.refresh_token();

    // TODO why is refresh_token None?
    info!("refresh_token {:?}", refresh_token);

    let scope_request = build_scope_request(
        access_token,
        None,
        None,
        vec![],
        &url::Url::parse("https://www.googleapis.com/oauth2/v3/userinfo").unwrap(),
    );
    match http_client(scope_request) {
        Ok(scope_response) => {
            let response_body = str::from_utf8(scope_response.body.as_slice()).unwrap();
            // info!("got body {}", response_body);
            serde_json::from_str::<UserInfo>(response_body)
                .map_err(|e| OAuthError::DecodeProfileError(e))
        }
        Err(e) => Err(OAuthError::FetchProfileError(e)),
    }
}

fn build_scope_request<'a>(
    access_token: &'a AccessToken,
    client_id: Option<&'a ClientId>,
    client_secret: Option<&'a ClientSecret>,
    params: Vec<(&'a str, &'a str)>,
    url: &'a url::Url,
) -> oauth2::HttpRequest {
    let mut headers = HeaderMap::new();
    headers.append(ACCEPT, HeaderValue::from_static(CONTENT_TYPE_JSON));
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_FORMENCODED),
    );

    let mut params: Vec<(&str, &str)> = params;
    params.push(("access_token", access_token.secret()));
    if let Some(ref client_id) = client_id {
        params.push(("client_id", client_id.as_str()));
    }
    if let Some(ref client_secret) = client_secret {
        params.push(("client_secret", client_secret.secret()));
    }

    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
        .into_bytes();

    oauth2::HttpRequest {
        url: url.to_owned(),
        method: Method::POST,
        headers,
        body,
    }
}
