use actix_session::SessionExt;
use actix_web::HttpRequest;

use crate::SESSION_FLASH;
use crate::error::Error;
use crate::templates::FlashMessage;

/// `FlashMessages` implements a one-time-message (hence "Flash") that is useful
/// for old-school HTML flows that need to display messages in a standardized way
/// across pages.
pub trait FlashMessages {
    /// Adds a flash message to the stack.
    fn flash(&self, title: &str, message: &str) -> Result<(), Error>;

    /// Internally used; loads flash messages for template use and removes the existing
    /// stack.
    fn get_flash_messages(&self) -> Result<Vec<FlashMessage>, Error>;
}

impl FlashMessages for HttpRequest {
    fn flash(&self, title: &str, message: &str) -> Result<(), Error> {
        let session = self.get_session();

        // This could potentially do less serialization, but it's fine for now.
        // TODO 103: Look at whether this can be done with just &str rather than String
        let mut messages: Vec<FlashMessage> = match session.get(SESSION_FLASH)? {
            Some(messages) => messages,
            None => Vec::new(),
        };

        messages.push(FlashMessage {
            title: title.to_string(),
            message: message.to_string(),
        });
        session.insert(SESSION_FLASH, messages)?;

        Ok(())
    }

    fn get_flash_messages(&self) -> Result<Vec<FlashMessage>, Error> {
        let session = self.get_session();

        let messages = match session.get(SESSION_FLASH)? {
            Some(messages) => messages,
            None => Vec::new(),
        };

        session.remove(SESSION_FLASH);
        Ok(messages)
    }
}
