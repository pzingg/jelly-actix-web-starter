use jelly::actix_session::{Session, UserSession};
use jelly::actix_web::web::Query;
use jelly::error::OAuthError;
use jelly::oauth::{ClientFlow, OAuthFlow, UserInfo};
use jelly::oauth2::basic::BasicClient;
use jelly::prelude::*;
use jelly::{oauth, Result, SESSION_OAUTH_FLOW};
use serde::{Deserialize, Serialize};
use std::{result, str};

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthRequest {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Handle callback from Google. Query string in request is:
///   code=<authorization_code>
///   state=<state>
///   scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+openid
///   authuser=0
///   prompt=consent
pub async fn exchange_code_for_token(
    request: HttpRequest,
    query: Query<AuthRequest>,
) -> Result<HttpResponse> {
    validate_inputs(request.get_session(), query)
        .and_then(oauth::request_token)
        .and_then(oauth::fetch_user_info)
        .map_err(|e| e.into())
        .and_then(|user_info| finalize_authentication(request, user_info))
}

fn validate_inputs(
    session: Session,
    query: Query<AuthRequest>,
) -> result::Result<ClientFlow, OAuthError> {
    let maybe_flow = session.get::<OAuthFlow>(SESSION_OAUTH_FLOW);
    session.remove(SESSION_OAUTH_FLOW);

    match maybe_flow {
        Ok(Some(flow)) => match &query.error {
            Some(e) => Err(OAuthError::GrantAuthorizationError(e.to_owned())),
            _ => match (&query.state, &query.code) {
                (Some(state), Some(auth_code)) => {
                    if flow.csrf_token_secret == state.to_owned() {
                        match oauth::client_for(&flow.provider_name) {
                            Some(client) => Ok(ClientFlow {
                                client,
                                flow: flow.set_authorization_code(auth_code),
                            }),
                            _ => Err(OAuthError::ParseSessionError),
                        }
                    } else {
                        Err(OAuthError::VerifyStateError)
                    }
                }
                _ => Err(OAuthError::ParseRequestError),
            },
        },
        _ => Err(OAuthError::ParseSessionError),
    }
}

fn finalize_authentication(request: HttpRequest, user_info: UserInfo) -> Result<HttpResponse> {
    // TODO set token in DB (create user if necessary)
    // TODO set user authenticated
    request.flash("Profile", "Got user profile.")?;
    request.redirect("/")
}
