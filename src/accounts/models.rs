// Implements a basic Account model, with support for creating/updating/deleting
// users, along with welcome email and verification.

use jelly::accounts::{OneTimeUseTokenGenerator, User};
use jelly::chrono::{DateTime, Utc};
use jelly::djangohashers as hasher;
use jelly::error::Error;
use jelly::serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPool, types::Json, FromRow};

use super::forms::{LoginForm, NewAccountForm};
use crate::oauth::forms::LinkIdentityForm;

/// Personalized profile data that is a pain to make a needless JOIN
/// for; just shove it in a jsonb field.
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Profile {}

/// A user Account.
/// Note: `password` can be None if authenticating via OAuth.
#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub password: Option<String>,
    pub profile: Json<Profile>,
    pub plan: i32,
    pub is_active: bool,
    pub is_admin: bool,
    pub has_verified_email: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

struct UserPass {
    id: i32,
    name: String,
    password: Option<String>,
    is_admin: bool,
}

impl UserPass {
    fn check_password(&self, password: &str) -> Result<bool, Error> {
        self.password
            .as_ref()
            .ok_or(Error::NoPasswordForAccount)
            .and_then(|encoded| hasher::check_password(password, encoded).map_err(|e| e.into()))
    }
}

impl Account {
    pub async fn get(id: i32, pool: &PgPool) -> Result<Self, Error> {
        Ok(sqlx::query_as_unchecked!(
            Account,
            "
            SELECT
                id, name, email, password, profile, plan,
                is_active, is_admin, has_verified_email,
                last_login, created, updated
            FROM accounts WHERE id = $1
        ",
            id
        )
        .fetch_one(pool)
        .await?)
    }

    pub async fn get_by_email(email: &str, pool: &PgPool) -> Result<Self, Error> {
        Ok(sqlx::query_as_unchecked!(
            Account,
            "
            SELECT
                id, name, email, password, profile, plan,
                is_active, is_admin, has_verified_email,
                last_login, created, updated
            FROM accounts WHERE email = $1
        ",
            email
        )
        .fetch_one(pool)
        .await?)
    }

    pub async fn id_by_email(email: &str, pool: &PgPool) -> Result<i32, Error> {
        Ok(sqlx::query!(
            "
            SELECT id
            FROM accounts WHERE email = $1
        ",
            email
        )
        .fetch_one(pool)
        .await?
        .id)
    }

    pub async fn authenticate(form: &LoginForm, pool: &PgPool) -> Result<User, Error> {
        let user = sqlx::query_as_unchecked!(
            UserPass,
            "
            SELECT
                id, name, password, is_admin
            FROM accounts WHERE email = $1
        ",
            form.email.value
        )
        .fetch_one(pool)
        .await?;

        user.check_password(&form.password.value)?;

        Ok(User {
            id: user.id,
            name: user.name,
            is_admin: user.is_admin,
            is_anonymous: false,
        })
    }

    pub async fn fetch_email(id: i32, pool: &PgPool) -> Result<(String, String), Error> {
        let data = sqlx::query!(
            "
            SELECT
                name, email
            FROM accounts WHERE id = $1
        ",
            id
        )
        .fetch_one(pool)
        .await?;

        Ok((data.name, data.email))
    }

    pub async fn fetch_name_from_email(email: &str, pool: &PgPool) -> Result<String, Error> {
        let data = sqlx::query!(
            "
            SELECT name FROM accounts WHERE email = $1
        ",
            email
        )
        .fetch_one(pool)
        .await?;

        Ok(data.name)
    }

    pub async fn register(form: &NewAccountForm, pool: &PgPool) -> Result<i32, Error> {
        // TODO 101: return InvalidPassword if password is empty
        let password = hasher::make_password(&form.password);

        Ok(sqlx::query!(
            "
            INSERT INTO accounts (name, email, password)
            VALUES ($1, $2, $3)
            RETURNING id
        ",
            form.name.value,
            form.email.value,
            password
        )
        .fetch_one(pool)
        .await?
        .id)
    }

    pub async fn mark_verified(id: i32, pool: &PgPool) -> Result<(), Error> {
        sqlx::query!(
            "
            UPDATE accounts
            SET has_verified_email = true, last_login = now()
            WHERE id = $1
        ",
            id
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn update_last_login(id: i32, pool: &PgPool) -> Result<(), Error> {
        sqlx::query!(
            "
            UPDATE accounts
            SET last_login = now()
            WHERE id = $1
        ",
            id
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn update_password_and_last_login(
        id: i32,
        password: &str,
        pool: &PgPool,
    ) -> Result<(), Error> {
        // TODO 101: return InvalidPassword if password is empty
        let password = hasher::make_password(password);

        sqlx::query!(
            "
            UPDATE accounts
            SET password = $2, last_login = now()
            WHERE id = $1
        ",
            id,
            password
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn merge_identity_and_login(
        form: &LinkIdentityForm,
        refresh_token: Option<String>,
        current_account_id: Option<i32>,
        pool: &PgPool,
    ) -> Result<User, Error> {
        let mut tx = pool.begin().await?;

        let linked_account_id = sqlx::query!(
            "
            SELECT account_id
            FROM identities
            WHERE provider = $1 AND username = $2
        ",
            form.provider,
            form.username,
        )
        .fetch_optional(&mut tx)
        .await?
        .map(|r| r.account_id);

        match (linked_account_id, current_account_id) {
            (Some(linked_id), None) => {
                // The account is linked to a local account and
                //    no session cookie is present --> Login
                let user = sqlx::query_as_unchecked!(
                    Account,
                    "
                    UPDATE accounts
                    SET last_login = now()
                    WHERE id = $1
                    RETURNING
                        id, name, email, password, profile, plan,
                        is_active, is_admin, has_verified_email,
                        last_login, created, updated
                ",
                    linked_id
                )
                .fetch_one(&mut tx)
                .await?;

                tx.commit().await?;

                Ok(User {
                    id: user.id,
                    name: user.name,
                    is_admin: user.is_admin,
                    is_anonymous: false,
                })
            }
            (None, None) => {
                // The account is not linked to a local account and
                //    no session cookie is present --> Register
                let user = sqlx::query_as_unchecked!(
                    Account,
                    "
                    INSERT INTO accounts (name, email, password, last_login)
                    VALUES ($1, $2, $3, now())
                    RETURNING
                        id, name, email, password, profile, plan,
                        is_active, is_admin, has_verified_email,
                        last_login, created, updated
                ",
                    form.name.value,
                    form.email.value,
                    jelly::NO_PASSWORD,
                )
                .fetch_one(&mut tx)
                .await?;

                let _identity_id = sqlx::query!(
                    "
                    INSERT INTO identities (account_id, provider, username, name, refresh_token)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                ",
                    user.id,
                    form.provider,
                    form.username,
                    form.name.value,
                    refresh_token,
                )
                .fetch_one(&mut tx)
                .await?
                .id;

                tx.commit().await?;

                Ok(User {
                    id: user.id,
                    name: user.name,
                    is_admin: user.is_admin,
                    is_anonymous: false,
                })
            }
            (Some(linked_id), Some(account_id)) => {
                // The account is linked to a local account and
                //    a session cookie is present --> Merge
                if linked_id == account_id {
                    let user = sqlx::query_as_unchecked!(
                        Account,
                        "
                        UPDATE accounts
                        SET name = $1, last_login = now()
                        WHERE id = $2
                        RETURNING
                            id, name, email, password, profile, plan,
                            is_active, is_admin, has_verified_email,
                            last_login, created, updated
                    ",
                        form.name.value,
                        account_id
                    )
                    .fetch_one(&mut tx)
                    .await?;

                    tx.commit().await?;

                    Ok(User {
                        id: user.id,
                        name: user.name,
                        is_admin: user.is_admin,
                        is_anonymous: false,
                    })
                } else {
                    Err(Error::Generic(
                        "The provider account is linked to a different account".to_string(),
                    ))
                }
            }
            (None, Some(account_id)) => {
                // The account is not linked to a local account and
                //    a session cookie is present --> Linking Additional account
                let user = sqlx::query_as_unchecked!(
                    Account,
                    "
                    UPDATE accounts
                    SET last_login = now()
                    WHERE id = $1
                    RETURNING
                        id, name, email, password, profile, plan,
                        is_active, is_admin, has_verified_email,
                        last_login, created, updated
                ",
                    account_id
                )
                .fetch_one(&mut tx)
                .await?;

                let _identity_id = sqlx::query!(
                    "
                    INSERT INTO identities (account_id, provider, username, name, refresh_token)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                ",
                    account_id,
                    form.provider,
                    form.username,
                    form.name.value,
                    refresh_token,
                )
                .fetch_one(&mut tx)
                .await?
                .id;

                tx.commit().await?;

                Ok(User {
                    id: user.id,
                    name: user.name,
                    is_admin: user.is_admin,
                    is_anonymous: false,
                })
            }
        }
    }
}

impl OneTimeUseTokenGenerator for Account {
    fn hash_value(&self) -> String {
        format!(
            "{}{}{}{}",
            self.id,
            self.password.as_ref().unwrap_or(&"NoPassword".to_string()),
            match self.last_login {
                Some(ts) => format!("{}", ts.timestamp()),
                None => "Unverified".to_string(),
            },
            self.email
        )
    }
}

/// Oauth identities
/// From https://stackoverflow.com/questions/6666267/architecture-for-merging-multiple-user-accounts-together
///
/// How to link multiple accounts?
///
/// The first time the user signs-up for your service, they first go to
/// the third party provider and come back with a verified third-party id.
/// You then create a local account for them and collect whatever other
/// information you want. We collect their email address and also ask
/// them to pick a local username (we try to pre-populate the form with
/// their existing username from the other provider). Having some form
/// of local identifier (email, username) is very important for account
/// recovery later.
///
/// The server knows this is a first time login if the browser does not
/// have a session cookie (valid or expired) for an existing account,
/// and that the third-party account used is not found. We try to inform
/// the user that they are not just logging-in, but are creating a new
/// account so that if they already have an account, they will hopefully
/// pause and login with their existing account instead.
///
/// We use the exact same flow to link additional accounts, but when the
/// user comes back from the third party, the presence of a valid session
/// cookie is used to differentiate between an attempt to link a new
/// account to a login action. We only allow one third-party account of
/// each type and if there is already one linked, block the action. It
/// should not be a problem because the interface to link a new account
/// is disabled if you already have one (per provider), but just in case.
///
/// How to merge accounts?
///
/// If a user tried to link a new third-party account which is already
/// linked to a local account, you simply prompt them to confirm they
/// want to merge the two accounts (assuming you can handle such a merge
/// with your data set - often easier said than done). You can also
/// provide them with a special button to request a merge but in
/// practice, all they are doing is linking another account.
///
/// This is a pretty simple state machine. The user comes back from the
/// third-party with a third-party account id. Your database can be
/// in one of four states:
///
/// The account is linked to a local account and
///    no session cookie is present --> Login
/// The account is linked to a local account and
///    a session cookie is present --> Merge
/// The account is not linked to a local account and
///    no session cookie is present --> Register
/// The account is not linked to a local account and
///    a session cookie is present --> Linking Additional account
///
/// How to perform account recovery with third-party providers?
///
/// This is still experimental territory. I have not seen a perfect UX for
/// this as most services provide both a local password next to the
/// third-party accounts and therefore focus on the "forgot my password"
/// use case, not everything else that can go wrong.
///
/// We've opted to use "Need help signing in?" and when you click, ask
/// the user for their email or username. We look it up and if we find
/// a matching account, email that user a link which can automatically
/// log them into the service (good for one time). Once in, we take them
/// directly to the account linking page, tell them they should take a
/// look and potentially link additional accounts, and show them the
/// third-party accounts they already have linked.
///
/// An OAuth provider Identity.
#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    pub id: i32,
    pub account_id: i32,
    pub provider: String,
    pub username: String,
    pub name: Option<String>,
    pub refresh_token: Option<String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

impl Identity {
    pub async fn get(id: i32, pool: &PgPool) -> Result<Self, Error> {
        Ok(sqlx::query_as_unchecked!(
            Identity,
            "
            SELECT
                id, account_id, provider, username, name,
                refresh_token, created, updated
            FROM identities WHERE id = $1
        ",
            id
        )
        .fetch_one(pool)
        .await?)
    }

    pub async fn get_by_provider_username(
        provider: &str,
        username: &str,
        pool: &PgPool,
    ) -> Result<Self, Error> {
        Ok(sqlx::query_as_unchecked!(
            Identity,
            "
            SELECT
                id, account_id, provider, username, name,
                refresh_token, created, updated
            FROM identities
            WHERE provider = $1 AND username = $2
        ",
            provider,
            username,
        )
        .fetch_one(pool)
        .await?)
    }

    pub async fn linked_to_account_id(account_id: i32, pool: &PgPool) -> Result<Vec<Self>, Error> {
        Ok(sqlx::query_as_unchecked!(
            Identity,
            "
            SELECT
                id, account_id, provider, username, name,
                refresh_token, created, updated
            FROM identities WHERE account_id = $1
        ",
            account_id
        )
        .fetch_all(pool)
        .await?)
    }
}
