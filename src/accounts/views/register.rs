use jelly::actix_web::{web, HttpRequest};
use jelly::forms::validation::{Validatable};
use jelly::prelude::*;
use jelly::request::{Authentication, DatabasePool};
use jelly::Result;

use crate::accounts::forms::NewAccountForm;
use crate::accounts::jobs::{SendAccountOddRegisterAttemptEmail, SendVerifyAccountEmail};
use crate::accounts::Account;

pub async fn form(request: HttpRequest) -> Result<HttpResponse> {
    if request.is_authenticated()? {
        return request.redirect("/dashboard");
    }

    request.render(200, "accounts/register.html", {
        let mut ctx = Context::new();
        ctx.insert("form", &NewAccountForm::default());
        ctx
    })
}

pub async fn create_account(
    request: HttpRequest,
    form: web::Form<NewAccountForm>,
) -> Result<HttpResponse> {
    if request.is_authenticated()? {
        return request.redirect("/dashboard");
    }
    // Will use default password policy
    let form = form.into_inner().set_keys();
    if let Err(errors) = form.validate() {
        return request.render(400, "accounts/register.html", {
            let mut ctx = Context::new();
            ctx.insert("errors", &errors);
            ctx.insert("form", &form);
            ctx
        });
    }

    // Catch this error
    // if duplicate:
    //  - send email to existing user asking if they were trying to sign in
    //  - pass requesting user through normal "fake" flow to avoid leaking if
    //      an account exists?
    let queue = request.job_queue()?;
    let db = request.db_pool()?;
    match Account::register(&form, db).await {
        Ok(uid) => {
            queue.queue(SendVerifyAccountEmail { to: uid }).await?;
        }

        Err(e) => {
            error!("Error with registering: {:?}", e);
            queue.queue(SendAccountOddRegisterAttemptEmail {
                to: form.email.value.clone(),
            }).await?;
        }
    }

    // No matter what, just appear as if it worked.
    request.redirect("/accounts/verify")
}
