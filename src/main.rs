//! Your Service Description here, etc.

use jelly::actix_web;
use std::io;
// use mainlib; clippy: this import is redundant

#[actix_web::main]
async fn main() -> io::Result<()> {
    mainlib::main().await
}
