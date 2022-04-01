use actix_web::{web, HttpRequest};
use background_jobs::QueueHandle;

use crate::error::Error;

/// A trait for adding jobs to a background queue.
pub trait JobQueue {
    /// Grabs the QueueHandle
    fn job_queue(&self) -> Result<&QueueHandle, Error>;
}

impl JobQueue for HttpRequest {
    fn job_queue(&self) -> Result<&QueueHandle, Error> {
        let handle: Option<&web::Data<QueueHandle>> = self.app_data();
        handle
            .map(|data| data.get_ref())
            .ok_or_else(|| Error::Generic("QueueHandle unavailable.".to_string()))
    }
}
