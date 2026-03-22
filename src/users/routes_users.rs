use crate::{auth, crates::*, users};

pub fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("/register", web::post().to(users::handler_users::register_user))
            .route("/login", web::post().to(users::handler_users::login_user))
            .route("/refresh", web::post().to(auth::handler_auth::refresh_token))
            .route("/logout", web::post().to(auth::handler_auth::logout))
    );


}
