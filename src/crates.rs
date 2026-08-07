// src/crates.rs

// --------------------
// Crates externas
// --------------------

// Actix Web
pub use actix_web::{
    cookie::{Cookie, SameSite},
    web, 
    HttpMessage, 
    HttpResponse,
    HttpRequest,
    Responder,
    Result
};
// Jsonwebtoken
pub use jsonwebtoken::{
    encode, Header, EncodingKey
};

// Serde
pub use serde::{Deserialize, Serialize};

// Std
pub use std::{
    time::{SystemTime, UNIX_EPOCH},
    env,
};

// Time
pub use time::Duration as TimeDuration;

// Chrono
pub use chrono::{
    Utc, 
    Duration as ChronoDuration, 
    DateTime,
};

// UUID
pub use uuid::Uuid;

// Rand
pub use rand::RngCore;

// Sha2
pub use sha2::{Sha256, Digest};

// Base64 — el trait `Engine` tiene que estar en ámbito para poder codificar.
pub use base64::prelude::{BASE64_STANDARD, Engine};

// SQLx
pub use sqlx::{
    PgPool,
    postgres::PgPoolOptions,
    Pool,
    Postgres,
    Executor,
    FromRow,

};
// --------------------
// Módulos internos
// --------------------

pub use crate::auth::handler_auth::{
    Claims,
    create_jwt,
    create_auth_cookie,
    generate_refresh_token,
    create_refresh_cookie
};

pub use crate::users::models_users::{
    LoginUser,
    RegisterUserPayload,

};