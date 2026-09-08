use crate::crates::*;
use crate::users::models_users::*;
use uuid::Uuid;

/// Da de alta a alguien. Una fila, una tabla.
///
/// Antes esto era la primera mitad de un alta en dos pasos: se insertaba el
/// usuario y después su ficha de dueño, empleado o administrador, y por eso hacía
/// falta una transacción y un `&mut PgConnection`. Ya no hay segunda mitad, así
/// que tampoco hace falta la transacción: una sola sentencia ya es atómica.
pub async fn create_user(
    pool: &PgPool,
    id: Uuid,
    data: &RegisterUserPayload,
    password_hash: &str,
) -> Result<User, actix_web::Error> {
    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO auth.users (id, email, password_hash, full_name)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(&data.email)
    .bind(password_hash)
    .bind(&data.full_name)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        log::error!("create_user error: {e:?}");
        actix_web::error::ErrorInternalServerError("db error")
    })
}

pub async fn find_user_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<User>, actix_web::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM auth.users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)
}

pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM auth.users WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
}

pub async fn store_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &str,
    agent: &str,
    ip: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), actix_web::Error> {
    sqlx::query(
        "INSERT INTO auth.refresh_tokens (user_id, token_hash, user_agent, ip, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(agent)
    .bind(ip)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(())
}
