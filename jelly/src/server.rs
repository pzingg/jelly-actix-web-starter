use std::env;
use std::sync::Arc;

use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;
use actix_web::{dev, middleware, web, App, HttpServer};
use actix_web::web::ServiceConfig;
use background_jobs::memory_storage::Storage;
use background_jobs::WorkerConfig;
use sqlx::postgres::PgPoolOptions;

use crate::email::{Configurable, Email};
use crate::jobs::{JobConfig, JobState, DEFAULT_QUEUE};

/// This struct provides a slightly simpler way to write `main.rs` in
/// the root project, and forces more coupling to app-specific modules.
#[derive(Default)]
pub struct Server {
    apps: Vec<Box<dyn Fn(&mut ServiceConfig) + Send + Sync + 'static>>,
    jobs: Vec<Box<dyn Fn(JobConfig) -> JobConfig + Send + Sync + 'static>>,
}

impl Server {
    /// Creates a new Server struct to configure.
    pub fn new() -> Self {
        Server::default()
    }

    /// Registers a service.
    pub fn register_service<F>(mut self, handler: F) -> Self
    where
        F: Fn(&mut ServiceConfig) + Send + Sync + 'static,
    {
        self.apps.push(Box::new(handler));
        self
    }

    /// Registers jobs.
    pub fn register_jobs<F>(mut self, handler: F) -> Self
    where
        F: Fn(JobConfig) -> JobConfig + Send + Sync + 'static,
    {
        self.jobs.push(Box::new(handler));
        self
    }

    /// Consumes and then runs the server, with default settings that we
    /// generally want.
    pub async fn run(self) -> std::io::Result<dev::Server> {
        dotenv::dotenv().ok();
        pretty_env_logger::init();
        Email::check_conf();

        let bind = env::var("BIND_TO").expect("BIND_TO not set!");
        let secret_key = Key::from(env::var("SECRET_KEY").expect("SECRET_KEY not set!").as_bytes());
        let _root_domain = env::var("JELLY_DOMAIN").expect("JELLY_DOMAIN not set!");

        #[cfg(feature = "production")]
        let cookie_domain = env::var("SESSIONID_DOMAIN").expect("SESSIONID_DOMAIN not set!");

        let template_store = crate::templates::load();
        let templates = template_store.templates.clone();

        let db_uri = env::var("DATABASE_URL").expect("DATABASE_URL not set!");
        let pool = PgPoolOptions::new()
            .connect(&db_uri)
            .await
            .expect("Unable to connect to database!");

        let apps = Arc::new(self.apps);
        let jobs = Arc::new(self.jobs);

        let server = HttpServer::new(move || {
            // !production needs no domain set, because browsers.
            #[cfg(not(feature = "production"))]
            let session_storage = SessionMiddleware::builder(
                CookieSessionStore::default(), secret_key.clone())
                .cookie_path("/".to_string())
                .cookie_name("sessionid".to_string())
                .cookie_secure(false);

            #[cfg(feature = "production")]
            let session_storage = SessionMiddleware::builder(
                CookieSessionStore::default(), secret_key.clone())
                .cookie_path("/".to_string())
                .cookie_name("sessionid".to_string())
                .cookie_secure(true)
                .cookie_same_site(actix_web::cookie::SameSite::Lax)
                .cookie_domain(Some(cookie_domain));

            let mut app = App::new()
                .app_data(pool.clone())
                .app_data(templates.clone())
                .wrap(middleware::Logger::default())
                .wrap(session_storage.build())
                .configure(crate::utils::static_handler)
                // Depending on your CORS needs, you may opt to change the
                // default service. Up to you.
                .default_service(web::to(crate::utils::default_handler));

            // Configure app resources and routes
            for handler in apps.iter() {
                app = app.configure(handler);
            }

            // Configure background jobs and start queue
            let storage = Storage::new();
            let state = JobState::new("JobState", pool.clone(), templates.clone());
            let mut worker_config = WorkerConfig::new(storage, move |_| state.clone());

            for handler in jobs.iter() {
                worker_config = (*handler)(worker_config);
            }

            let queue_handle = worker_config
                .set_worker_count(DEFAULT_QUEUE, 16)
                .start();

            app.app_data(web::Data::new(queue_handle))
        })
        .backlog(8192)
        .shutdown_timeout(0)
        .workers(4)
        .bind(&bind)?
        .run();

        Ok(server)
    }
}
