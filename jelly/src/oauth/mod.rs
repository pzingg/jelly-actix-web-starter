//! URL dispatcher for oauth related API endpoints.

use std::marker::Copy;
use std::{result, str};

use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::http::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use oauth2::http::method::Method;
use oauth2::reqwest::http_client;
use oauth2::{
    url, AccessToken, AuthorizationCode, AuthorizationRequest, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::error::{Error, OAuthError};
use crate::SESSION_OAUTH_TOKEN;
use actix_session::Session;

pub mod client;

#[derive(Debug, Deserialize, Serialize)]
pub struct UserInfo {
    pub provider: &'static str,
    pub id: String,
    pub name: String,
    pub username: String,
    pub login_email: String,
    pub provider_email: Option<String>,
}

// Accepts the json body to be deserialized and the email the user began
// the authorization with.
type UserInfoDeserializer = fn(&str, &str) -> serde_json::Result<UserInfo>;

#[derive(Debug, Deserialize, Serialize)]
pub struct OAuthFlow {
    pub provider: String,
    pub email: String,
    pub authorization_code: String,
    pub csrf_token_secret: String,
    pub pkce_verifier_secret: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ProviderHints {
    pub uses_email_hint: bool,
}

#[derive(Clone)]
pub struct ScopedClient {
    pub inner: BasicClient,
    pub scopes: Vec<String>,
    pub login_hint_key: Option<String>,
    pub user_info_uri: String,
    pub user_info_params: Vec<(String, String)>,
    pub user_info_headers: Vec<(Vec<u8>, String)>,
    pub user_info_de: UserInfoDeserializer,
}

pub struct ClientFlow {
    pub client: ScopedClient,
    pub flow: OAuthFlow,
}

pub struct TokenInfo {
    pub provider: String,
    pub email: String,
    pub response: BasicTokenResponse,
    pub user_info_uri: String,
    pub user_info_params: Vec<(String, String)>,
    pub user_info_headers: Vec<(Vec<u8>, String)>,
    pub user_info_de: UserInfoDeserializer,
}

impl OAuthFlow {
    pub fn set_authorization_code(mut self, code: &str) -> Self {
        self.authorization_code = code.to_owned();
        self
    }
}

pub fn pkce_authorization_request<'a>(
    client: &'a ScopedClient,
    login_hint: Option<&'a str>,
) -> (AuthorizationRequest<'a>, PkceCodeVerifier) {
    // Google and Twitter support Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let mut authorization_request = client
        .inner
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_code_challenge);

    // Add "login_hint=email"
    if let (Some(key), Some(email)) = (&client.login_hint_key, login_hint) {
        authorization_request = authorization_request.add_extra_param(key, email);
    }

    for scope in client.scopes.as_slice() {
        authorization_request = authorization_request.add_scope(Scope::new(scope.to_string()));
    }

    (authorization_request, pkce_code_verifier)
}

pub fn request_token(client_flow: ClientFlow) -> result::Result<TokenInfo, OAuthError> {
    let client = client_flow
        .client
        .inner
        .exchange_code(AuthorizationCode::new(
            client_flow.flow.authorization_code.clone(),
        ))
        .set_pkce_verifier(PkceCodeVerifier::new(
            client_flow.flow.pkce_verifier_secret.clone(),
        ));

    client
        .request(http_client)
        .map(move |response| TokenInfo {
            provider: client_flow.flow.provider,
            email: client_flow.flow.email.clone(),
            response,
            user_info_uri: client_flow.client.user_info_uri.clone(),
            user_info_params: client_flow.client.user_info_params.clone(),
            user_info_headers: client_flow.client.user_info_headers.clone(),
            user_info_de: client_flow.client.user_info_de,
        })
        .map_err(|e| OAuthError::GrantTokenError(e).into())
}

pub fn fetch_user_info(
    session: &Session,
    token_info: TokenInfo,
) -> result::Result<UserInfo, Error> {
    let access_token = token_info.response.access_token();

    // TODO why is refresh_token None?
    if let Some(refresh_token) = token_info.response.refresh_token() {
        session.set(SESSION_OAUTH_TOKEN, refresh_token)?;
    }

    let scope_request = get_user_info_request(
        access_token,
        &token_info.user_info_uri,
        &token_info.user_info_params,
        &token_info.user_info_headers,
    );
    match http_client(scope_request) {
        Ok(scope_response) => {
            let response_body = str::from_utf8(scope_response.body.as_slice()).unwrap();
            // info!("got user_info body: {}", response_body);

            let deserialize_and_map = token_info.user_info_de;
            deserialize_and_map(response_body, &token_info.email)
                .map_err(|e| Error::OAuth(OAuthError::DecodeProfileError(e)))
        }
        Err(e) => Err(Error::OAuth(OAuthError::FetchProfileError(e))),
    }
}

fn get_user_info_request<'a>(
    access_token: &'a AccessToken,
    endpoint_uri: &'a str,
    extra_params: &[(String, String)],
    extra_headers: &[(Vec<u8>, String)],
) -> oauth2::HttpRequest {
    let token_value = access_token.secret();

    let mut headers = HeaderMap::new();
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token_value)).unwrap(),
    );
    for (key, value) in extra_headers {
        headers.append(
            HeaderName::from_bytes(key).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }

    let body: Vec<u8> = vec![];
    let url = url::Url::parse_with_params(endpoint_uri, extra_params).unwrap();
    oauth2::HttpRequest {
        method: Method::GET,
        url,
        headers,
        body,
    }
}
