use jelly::accounts::User;
use jelly::actix_web::{web::Path, HttpRequest};
use jelly::prelude::*;
use jelly::request::DatabasePool;
use jelly::Result;

use crate::accounts::views::utils::validate_token;
use crate::accounts::{Account, TokenInfo};

/// Just renders a standard "Check your email and verify" page.
pub async fn verify(request: HttpRequest) -> Result<HttpResponse> {
    request.render(200, "accounts/verify/index.html", Context::new())
}

/// Given a link (of form {uidb64}-{ts}-{token}), verifies the
/// token and user, signs them in, and redirects to the dashboard.
///
/// In general, we do not want to leak information, so any errors here
/// should simply report as "invalid or expired".
pub async fn with_token(
    request: HttpRequest,
    path: Path<TokenInfo>,
) -> Result<HttpResponse> {
    if let Ok(account) = validate_token(&request, &path.uidb64, &path.ts, &path.token).await {
        let db = request.db_pool()?;
        Account::mark_verified(account.id, db).await?;

        request.set_user(User {
            id: account.id,
            name: account.name,
            is_admin: account.is_admin,
            is_anonymous: false,
        })?;

        request.redirect("/dashboard")
    } else {
        request.render(200, "accounts/invalid_token.html", Context::new())
    }
}
