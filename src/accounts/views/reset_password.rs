use jelly::accounts::User;
use jelly::actix_web::{web, HttpRequest};
use jelly::forms::validation::{Validatable};
use jelly::prelude::*;
use jelly::Result;

use crate::accounts::forms::{ChangePasswordForm, EmailForm};
use crate::accounts::jobs::{SendPasswordWasResetEmail, SendResetPasswordEmail};
use crate::accounts::views::utils::validate_token;
use crate::accounts::{Account, TokenInfo};

/// Just renders a standard "Enter Your Email" password reset page.
pub async fn form(request: HttpRequest) -> Result<HttpResponse> {
    request.render(200, "accounts/reset_password/index.html", {
        let mut context = Context::new();
        context.insert("form", &EmailForm::default());
        context.insert("sent", &false);
        context
    })
}

/// Processes the reset password request, which ultimately just passes
/// it to a background worker to execute - we do this to avoid any timing
/// attacks re: leaking user existence.
pub async fn request_reset(request: HttpRequest, form: web::Form<EmailForm>) -> Result<HttpResponse> {
    let form = form.into_inner().set_keys();
    if let Err(errors) = form.validate() {
        return request.render(400, "accounts/reset_password/index.html", {
            let mut context = Context::new();

            // ValidationErrors object is serialized into HashMap here
            context.insert("errors", &errors);
            context.insert("form", &form);
            context.insert("sent", &false);
            context
        });
    }

    let queue = request.job_queue()?;
    queue.queue(SendResetPasswordEmail {
        to: form.email.value.clone(),
    }).await?;

    request.render(200, "accounts/reset_password/requested.html", {
        let mut context = Context::new();
        context.insert("sent", &true);
        context
    })
}

/// Given a link (of form {uidb64}-{ts}-{token}), verifies the
/// token and user, and presents them a change password form.
///
/// In general, we do not want to leak information, so any errors here
/// should simply report as "invalid or expired". It's a bit verbose, but
/// such is Rust for this type of thing. Write it once and move on. ;P
pub async fn with_token(
    request: HttpRequest,
    path: web::Path<TokenInfo>,
) -> Result<HttpResponse> {
    if let Ok(_account) = validate_token(&request, &path.uidb64, &path.ts, &path.token).await {
        request.render(200, "accounts/reset_password/change_password.html", {
            let mut context = Context::new();
            context.insert("form", &ChangePasswordForm::default());
            context.insert("uidb64", &path.uidb64);
            context.insert("ts", &path.ts);
            context.insert("token", &path.token);
            context
        })
    } else {
        request.render(200, "accounts/invalid_token.html", Context::new())
    }
}

/// Verifies the password is fine, and if so, signs the user in and redirects
/// them to the dashboard with a flash message.
pub async fn reset(
    request: HttpRequest,
    path: web::Path<TokenInfo>,
    form: web::Form<ChangePasswordForm>,
) -> Result<HttpResponse> {
    match validate_token(&request, &path.uidb64, &path.ts, &path.token).await {
        Ok(account) => {
            // Note! This is a case where we need to fetch the user ahead of form validation.
            // While it would be nice to avoid the DB hit, validating that their password is secure
            // requires pulling some account values...
            let form = form
                .into_inner()
                .set_keys()
                .set_name_and_email(&account.name, &account.email);
            if let Err(errors) = form.validate() {
                return request.render(200, "accounts/reset_password/change_password.html", {
                    let mut context = Context::new();

                    // ValidationErrors object is serialized into HashMap here
                    context.insert("errors", &errors);
                    context.insert("form", &form);
                    context
                });
            }

            let pool = request.db_pool()?;
            Account::update_password_and_last_login(account.id, &form.password, pool).await?;

            let queue = request.job_queue()?;
            queue.queue(SendPasswordWasResetEmail {
                to: account.email.clone(),
            }).await?;

            request.set_user(User {
                id: account.id,
                name: account.name,
                is_admin: account.is_admin,
                is_anonymous: false,
            })?;

            request.flash("Password Reset", "Your password was successfully reset.")?;
            request.redirect("/dashboard")
        },
        Err(_) => {
            request.flash("Password Reset", "The link you used is invalid. Please request another password reset.")?;
            request.redirect("/")
        }
    }
}
