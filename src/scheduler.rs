use actix::prelude::*;
use std::str::FromStr;
use std::time::Duration;
use chrono::Local;
use cron::Schedule;
use sqlx::postgres::PgPool;
use crate::accounts::Account;

pub const EVERY_MINUTE: &str = "0 * * * * * *";

// Define Actor
#[derive(Clone)]
pub struct Scheduler {
    pub pool: PgPool,
    pub schedule: String,
}

#[derive(Message)]
#[rtype(result = "Result<i64, ()>")]
struct CountTask {}

impl Handler<CountTask> for Scheduler {
    type Result = ResponseFuture<Result<i64, ()>>;

    fn handle(&mut self, _msg: CountTask, _ctx: &mut Context<Self>) -> Self::Result {
        let pool = self.pool.clone();
        Box::pin(async move {
            match Account::count(&pool).await {
                Ok(count) => {
                    info!("There are {} accounts.", count);
                    Ok(count)
                }
                Err(_) => Err(())
            }
        }
    )}
}

// Provide Actor implementation for our actor
impl Actor for Scheduler {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        info!("Scheduler is alive");
        ctx.notify(CountTask {});
        ctx.run_later(duration_until_next(&self.schedule), move |this, ctx| {
            this.schedule_task(ctx)
        });
    }

    fn stopped(&mut self, _ctx: &mut Context<Self>) {
        info!("Scheduler is stopped");
    }
}

impl Scheduler {
    // Executes based on cron schedule
    fn schedule_task(&self, ctx: &mut Context<Self>) {
        info!("Scheduler::schedule_task {:?}", Local::now());
        ctx.notify(CountTask {});
        ctx.run_later(duration_until_next(&self.schedule), move |this, ctx| {
            this.schedule_task(ctx)
        });
    }
}

pub fn duration_until_next(schedule: &str) -> Duration {
    let cron_schedule = Schedule::from_str(schedule).unwrap();
    let now = Local::now();
    let next = cron_schedule.upcoming(Local).next().unwrap();
    let duration_until = next.signed_duration_since(now);
    duration_until.to_std().unwrap()
}
