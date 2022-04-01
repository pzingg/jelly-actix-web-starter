//! Your Service Description here, etc.

use jelly::actix_web;
use std::io;

// clippy: this import is redundant
// use mainlib;

#[actix_web::main]
async fn main() -> io::Result<()> {
    mainlib::main().await
}
