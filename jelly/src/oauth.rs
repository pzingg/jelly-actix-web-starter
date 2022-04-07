//! URL dispatcher for oauth related API endpoints.

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
pub struct OAuthFlow {
    pub provider: String,
    pub email: String,
    pub authorization_code: String,
    pub csrf_token_secret: String,
    pub pkce_verifier_secret: String,
}

impl OAuthFlow {
    pub fn set_authorization_code(mut self, code: &str) -> Self {
        self.authorization_code = code.to_string();
        self
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct UserInfo {
    pub provider: &'static str,
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub provider_email: Option<String>,
    pub login_email: String,
}

// Accepts the json body to be deserialized and the email the user began
// the authorization with.
type UserInfoDeserializer = fn(&str, &str) -> serde_json::Result<UserInfo>;

#[derive(Clone)]
pub struct UserInfoRequest {
    pub uri: String,
    pub params: Vec<(String, String)>,
    pub headers: Vec<(Vec<u8>, String)>,
    pub deserializer: UserInfoDeserializer,
}

#[derive(Clone)]
pub struct ScopedClient {
    pub inner: BasicClient,
    pub scopes: Vec<String>,
    pub login_hint_key: Option<String>,
    pub user_info_request: UserInfoRequest,
}

pub struct ClientFlow {
    pub client: ScopedClient,
    pub flow: OAuthFlow,
}

pub struct TokenInfo {
    pub provider: String,
    pub email: String,
    pub response: BasicTokenResponse,
    pub user_info_request: UserInfoRequest,
}

impl TokenInfo {
    pub fn parse_user_info_response(
        &self,
        response: &oauth2::HttpResponse,
    ) -> Result<UserInfo, OAuthError> {
        let body = str::from_utf8(response.body.as_slice()).unwrap();
        // info!("got user_info body: {}", body);

        let deser = self.user_info_request.deserializer;
        deser(body, &self.email).map_err(OAuthError::DecodeProfileError)
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
            response,
            provider: client_flow.flow.provider,
            email: client_flow.flow.email,
            user_info_request: client_flow.client.user_info_request,
        })
        .map_err(OAuthError::GrantTokenError)
}

pub fn fetch_user_info(
    session: &Session,
    token_info: TokenInfo,
) -> result::Result<UserInfo, Error> {
    let access_token = token_info.response.access_token();
    if let Some(refresh_token) = token_info.response.refresh_token() {
        session.insert(SESSION_OAUTH_TOKEN, refresh_token)?;
    }

    let user_info_request = get_user_info_request(access_token, &token_info.user_info_request);
    http_client(user_info_request)
        .map_err(OAuthError::FetchProfileError)
        .and_then(|response| token_info.parse_user_info_response(&response))
        .map_err(Error::OAuth)
}

fn get_user_info_request<'a>(
    access_token: &'a AccessToken,
    fetcher: &'a UserInfoRequest,
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
    for (key, value) in fetcher.headers.iter() {
        headers.append(
            HeaderName::from_bytes(key).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }

    let body: Vec<u8> = vec![];
    let url = url::Url::parse_with_params(&fetcher.uri, fetcher.params.iter()).unwrap();

    oauth2::HttpRequest {
        method: Method::GET,
        url,
        headers,
        body,
    }
}
