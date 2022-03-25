use jelly::actix_web::web::{resource, ServiceConfig};
use jelly::prelude::*;
use jelly::Result;

pub async fn homepage(request: HttpRequest) -> Result<HttpResponse> {
    request.render(200, "index.html", Context::new())
}

pub fn configure(config: &mut ServiceConfig) {
    config.service(resource("/").to(homepage));
}
