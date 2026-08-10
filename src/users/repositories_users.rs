use crate::crates::*;
use crate::users::models_users::*;
use sqlx::PgConnection;
use crate::users::models_users::EmployerSummary;
use uuid::Uuid;

pub async fn create_user(
    conn: &mut PgConnection,
    id: Uuid,
    data: &RegisterUserBase,
    password_hash: &str,
) -> Result<User, actix_web::Error> {

    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO auth.users (
            id, email, password_hash,
            full_name, user_type
        )
        VALUES ($1,$2,$3,$4,$5)
        RETURNING *
        "#
    )
    .bind(id)
    .bind(&data.email)
    .bind(password_hash)
    .bind(&data.full_name)
    .bind(&data.user_type)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        log::error!("create_user error: {:?}", e);
        actix_web::error::ErrorInternalServerError("db error")
    })
}

pub async fn create_owner(
    conn: &mut PgConnection,
    user_id: Uuid,
    data: &RegisterOwner,
) -> Result<(), actix_web::Error> {

    sqlx::query(
        r#"
        INSERT INTO auth.owners (user_id, cpf)
        VALUES ($1, $2)
        "#
    )
    .bind(user_id)
    .bind(&data.cpf)
    .execute(conn) 
    .await
    .map_err(|e| {
        log::error!("create_owner error: {:?}", e);
        actix_web::error::ErrorInternalServerError("db error")
    })?;

    Ok(())
}

pub async fn create_employer(
    conn: &mut PgConnection,
    user_id: Uuid,
    owner_id: Uuid,
    restaurant_id: Uuid,
    data: &RegisterEmployer,
) -> Result<(), actix_web::Error> {

    sqlx::query(
        r#"
        INSERT INTO auth.employers (
            user_id, owner_id, restaurant_id, cpf, hire_date, role_gerarqui, salary
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        "#
    )
    .bind(user_id)
    .bind(owner_id)
    .bind(restaurant_id)
    .bind(&data.cpf)
    .bind(&data.hire_date)
    .bind(&data.role)
    .bind(&data.salary)
    .execute(conn)
    .await
    .map_err(|e| {
        log::error!("create_employer error: {:?}", e);
        actix_web::error::ErrorInternalServerError("db error")
    })?;

    Ok(())
}

pub async fn get_employees_summary_by_restaurant(
    conn: &mut PgConnection,
    restaurant_id: Uuid,
) -> Result<Vec<EmployerSummary>, actix_web::Error> {
    let employers = sqlx::query_as::<_, EmployerSummary>(
        r#"
        SELECT 
            u.full_name,
            e.is_active,
            e.role_gerarqui,
            e.salary
        FROM auth.employers e
        LEFT JOIN auth.users u ON u.id = e.user_id
        WHERE e.restaurant_id = $1
        "#
    )
    .bind(restaurant_id)
    .fetch_all(conn)
    .await
    .map_err(|e| {
        log::error!("get_employees_summary error: {:?}", e);
        actix_web::error::ErrorInternalServerError("db error")
    })?;

    Ok(employers)
}

pub async fn create_admin(
    conn: &mut PgConnection,
    user_id: Uuid,
    data: &RegisterAdmin,
) -> Result<(), actix_web::Error> {

    sqlx::query(
        r#"
        INSERT INTO auth.admins (user_id, access_level, internal_note)
        VALUES ($1,$2,$3)
        "#
    )
    .bind(user_id)
    .bind(data.access_level)
    .bind(&data.internal_note)
    .execute(conn)
    .await
    .map_err(|e| {
        log::error!("create_admin error: {:?}", e);
        actix_web::error::ErrorInternalServerError("db error")
    })?;

    Ok(())
}

pub async fn find_user_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<User>, actix_web::Error> {

    sqlx::query_as::<_, User>("SELECT * FROM auth.users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))
}

pub async fn find_user_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<User, sqlx::Error> {

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
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(agent)
    .bind(ip)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(())
}