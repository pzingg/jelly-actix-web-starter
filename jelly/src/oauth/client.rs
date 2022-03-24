use oauth2::basic::BasicClient;
use oauth2::url::Url;
use oauth2::{
    AuthUrl, AuthorizationRequest, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RevocationUrl, Scope, TokenUrl,
};
use std::env;

pub fn google_oauth(redirect_uri: &Url) -> BasicClient {
    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID").expect("Missing the GOOGLE_CLIENT_ID environment variable."),
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET")
            .expect("Missing the GOOGLE_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
        .expect("Invalid token endpoint URL");

    // Set up the config for the Google OAuth2 process.
    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).expect("Invalid redirect URL"))
    // Google supports OAuth 2.0 Token Revocation (RFC-7009)
    .set_revocation_uri(
        RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
            .expect("Invalid revocation endpoint URL"),
    )
}

// These example scopes request access to the "calendar" features and the user's profile:
// "https://www.googleapis.com/auth/calendar"
// "https://www.googleapis.com/auth/plus.me"

pub fn pkce_authorization_request<'a>(
    client: &'a BasicClient,
    scopes: &'a [&str],
    login_hint: Option<&'a str>
) -> (AuthorizationRequest<'a>, PkceCodeVerifier) {
    // Google supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    // login_hint: email
    let mut authorization_request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_code_challenge);

    authorization_request = match login_hint {
        None => authorization_request,
        Some(email) => authorization_request.add_extra_param("login_hint", email),
    };

    for scope in scopes {
        authorization_request = authorization_request.add_scope(Scope::new(scope.to_string()));
    }
    (authorization_request, pkce_code_verifier)
}
