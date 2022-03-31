use jelly::actix_session::{Session, UserSession};
use jelly::actix_web::web;
use jelly::error::OAuthError;
use jelly::forms::{EmailField, TextField};
use jelly::oauth::{ClientFlow, OAuthFlow, UserInfo};
use jelly::prelude::*;
use jelly::{oauth, Result, SESSION_OAUTH_FLOW, SESSION_OAUTH_TOKEN};
use serde::{Deserialize, Serialize};
use std::{result, str};

use crate::accounts::Account;
use crate::oauth::forms::LinkIdentityForm;

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
    query: web::Query<AuthRequest>,
) -> Result<HttpResponse> {
    let session = &request.get_session();
    validate_inputs(session, query)
        .and_then(oauth::request_token)
        .map_err(|e| e.into())
        .and_then(|token_info| oauth::fetch_user_info(session, token_info))
        .and_then(|user_info| finalize_authentication(request, user_info))
}

pub async fn confirm_identity(
    request: HttpRequest,
    form: web::Form<LinkIdentityForm>,
) -> Result<HttpResponse> {
    let mut form = form.into_inner();

    if !form.is_valid() {
        return request.render(400, "oauth/confirm.html", {
            let mut context = Context::new();
            context.insert("error", "Invalid email.");
            context.insert("form", &form);
            context
        });
    }

    let refresh_token = request.get_session().get::<String>(SESSION_OAUTH_TOKEN)?;
    let db = request.db_pool()?;
    let user = request.user()?;
    let account_id = if user.is_anonymous {
        Account::id_by_email(&form.email.value, db).await.ok()
    } else {
        Some(user.id)
    };

    if let Ok(user) = Account::merge_identity_and_login(&form, refresh_token, account_id, db).await
    {
        // last_login already updated, so just:
        request.set_user(user)?;
        return request.redirect("/dashboard/");
    }

    request.render(400, "oauth/confirm.html", {
        let mut context = Context::new();
        context.insert("error", "Invalid email.");
        context.insert("form", &form);
        context
    })
}

fn validate_inputs(
    session: &Session,
    query: web::Query<AuthRequest>,
) -> result::Result<ClientFlow, OAuthError> {
    let maybe_flow = session.get::<OAuthFlow>(SESSION_OAUTH_FLOW);
    session.remove(SESSION_OAUTH_FLOW);
    session.remove(SESSION_OAUTH_TOKEN);

    match maybe_flow {
        Ok(Some(flow)) => match &query.error {
            Some(e) => Err(OAuthError::GrantAuthorizationError(e.to_string())),
            _ => match (&query.state, &query.code) {
                (Some(state), Some(auth_code)) => {
                    if state.eq(&flow.csrf_token_secret) {
                        match oauth::client::client_for(&flow.provider) {
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
    let form = LinkIdentityForm {
        provider: user_info.provider.to_string(),
        username: user_info.username,
        name: TextField::new(user_info.name),
        email: EmailField::new(user_info.login_email),
    };

    request.render(200, "oauth/confirm.html", {
        let mut ctx = Context::new();
        ctx.insert("form", &form);
        ctx
    })
}
