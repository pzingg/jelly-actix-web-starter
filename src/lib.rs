//! Your Service Description here, etc.

use actix::Actor;
use std::io;

#[macro_use]
extern crate log;

pub mod accounts;
pub mod dashboard;
pub mod oauth;
pub mod pages;
pub mod scheduler;

pub async fn main() -> io::Result<()> {
    let stdout = io::stdout();
    let _lock = stdout.lock();

    let config = jelly::ServerConfig::load().await;

    let sched = scheduler::Scheduler { pool: config.pool.clone(), schedule: scheduler::EVERY_MINUTE.to_string() };
    sched.start();

    jelly::Server::new()
        .register_service(pages::configure)
        .register_service(accounts::configure)
        .register_jobs(accounts::jobs::configure)
        .register_service(dashboard::configure)
        .register_service(oauth::configure)
        .run(config)
        .await?
        .await
}
