use jelly::actix_web::{web, HttpRequest};
use jelly::forms::validation::{Validatable};
use jelly::prelude::*;
use jelly::request::{Authentication, DatabasePool};
use jelly::Result;

use crate::accounts::forms::LoginForm;
use crate::accounts::Account;

/// The login form.
pub async fn form(request: HttpRequest) -> Result<HttpResponse> {
    if request.is_authenticated()? {
        return request.redirect("/dashboard");
    }

    request.render(200, "accounts/login.html", {
        let mut ctx = Context::new();
        ctx.insert("form", &LoginForm::default());
        ctx
    })
}

/// POST-handler for logging in.
pub async fn authenticate(
    request: HttpRequest,
    form: web::Form<LoginForm>,
) -> Result<HttpResponse> {
    if request.is_authenticated()? {
        return request.redirect("/dashboard");
    }
    let form = form.into_inner().set_keys();
    if let Err(errors) = form.validate() {
        return request.render(400, "accounts/login.html", {
            let mut context = Context::new();
            context.insert("error", &errors);
            context.insert("form", &form);
            context
        });
    }

    let db = request.db_pool()?;
    if let Ok(user) = Account::authenticate(&form, db).await {
        Account::update_last_login(user.id, db).await?;
        request.set_user(user)?;
        return request.redirect("/dashboard");
    }

    request.render(400, "accounts/login.html", {
        let mut context = Context::new();
        context.insert("error", "Invalid email or password.");
        context.insert("form", &form);
        context
    })
}
