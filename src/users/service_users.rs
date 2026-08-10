use crate::{auth, crates::*, users::{self, models_users, repositories_users}};
use crate::users::models_users::*;
pub struct AuthResponse {
    pub access_cookie: Cookie<'static>,
    pub refresh_cookie: Cookie<'static>,
    pub user_json: serde_json::Value,
}

pub async fn register_user_service(
    pool: &PgPool,
    data: models_users::RegisterUserPayload,
    agent: String,
    ip: String,
    req: HttpRequest,
) -> Result<AuthResponse, actix_web::Error> {
        // 🔥 Solo Employer requiere auth
        let (owner_id, restaurant_id) = match data.base.user_type {
            models_users::UserType::Employer => {
                let owner_id = req
                    .extensions()
                    .get::<Uuid>()
                    .copied()
                    .ok_or_else(|| actix_web::error::ErrorUnauthorized("Owner not authenticated"))?;

                let restaurant_id: Uuid = req
                    .headers()
                    .get("x-restaurant-id")
                    .ok_or_else(|| actix_web::error::ErrorBadRequest("x-restaurant-id missing"))?
                    .to_str()
                    .map_err(|_| actix_web::error::ErrorBadRequest("invalid x-restaurant-id"))?
                    .parse()
                    .map_err(|_| actix_web::error::ErrorBadRequest("x-restaurant-id must be UUID"))?;

                (Some(owner_id), Some(restaurant_id))
            }

            // Owner/Admin no necesitan JWT
            _ => (None, None),
        };

    // 🔐 Transacción (OBLIGATORIA por el trigger)
    let mut tx = pool.begin().await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    // 👇 SACA LA CONEXIÓN
    let conn = tx.as_mut();

    // 🔑 Hash password
    let password_hash = bcrypt::hash(&data.base.password, bcrypt::DEFAULT_COST)
        .map_err(|_| actix_web::error::ErrorInternalServerError("hash error"))?;

    let user_id = Uuid::new_v4();

    // USER BASE
    let user = repositories_users::create_user(
        &mut tx,
        user_id,
        &data.base,
        &password_hash,
    ).await?;
    
    
    // PERFIL SEGÚN TIPO
    match data.base.user_type {
        models_users::UserType::Owner => {
            let owner = data.owner
                .ok_or_else(|| actix_web::error::ErrorBadRequest("owner data required"))?;

            repositories_users::create_owner(&mut tx, user_id, &owner).await?;
        }

        models_users::UserType::Employer => {
        let employer = data.employer
            .ok_or_else(|| actix_web::error::ErrorBadRequest("employer data required"))?;

        let owner_id = owner_id.unwrap();          // ya validado arriba
        let restaurant_id = restaurant_id.unwrap();

        repositories_users::create_employer(
            &mut tx,
            user_id,
            owner_id,
            restaurant_id,
            &employer,
        ).await?;
}

        models_users::UserType::Admin => {
            let admin = data.admin
                .ok_or_else(|| actix_web::error::ErrorBadRequest("admin data required"))?;

            repositories_users::create_admin(&mut tx, user_id, &admin).await?;
        }
    }

    tx.commit().await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    // =========================
    // 🔐 AUTH (TU IMPLEMENTACIÓN)
    // =========================

    // Access token.
    //
    // Un usuario recién registrado **no tiene ningún rol todavía**, así que aquí
    // se carga igualmente en vez de dar por hecho que está vacío: si algún día el
    // alta concede un rol por defecto, esto ya lo recoge sin que nadie se acuerde
    // de volver.
    let rbac = crate::rbac::repositories_rbac::cargar(pool, user.id)
        .await
        .map_err(|e| {
            log::error!("no se pudo cargar el RBAC al registrar: {e}");
            actix_web::error::ErrorInternalServerError("db error")
        })?;

    let access_token = auth::handler_auth::create_jwt(user.id, &rbac)
        .map_err(|_| actix_web::error::ErrorInternalServerError("jwt error"))?;

    let access_cookie = auth::handler_auth::create_auth_cookie(&access_token);

    // Refresh token
    let (refresh_token, refresh_hash) = auth::handler_auth::generate_refresh_token();
    let refresh_cookie = auth::handler_auth::create_refresh_cookie(&refresh_token);

    auth::handler_auth::store_refresh_token(
        pool,
        user.id,
        refresh_hash,
        agent,
        ip,
    )
    .await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(AuthResponse {
        access_cookie,
        refresh_cookie,
        user_json: serde_json::json!(user),
    })
}


pub async fn login_user_service(
    pool: &PgPool,
    data: LoginUser,
    agent: String,
    ip: String,
) -> Result<AuthResponse, actix_web::Error> {

    let user = match users::repositories_users::find_user_by_email(pool, &data.email).await? {
        Some(u) => u,
        None => return Err(actix_web::error::ErrorUnauthorized("Invalid credentials")),
    };

   /*if !user.activo {
        return Err(actix_web::error::ErrorForbidden("User not active"));
    }*/

    // Verify password
    let valid = bcrypt::verify(&data.password, &user.password_hash)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to verify password"))?;

    if !valid {
        return Err(actix_web::error::ErrorUnauthorized("Invalid credentials"));
    }

    // Roles y permisos, resueltos una vez y firmados dentro del token.
    let rbac = crate::rbac::repositories_rbac::cargar(pool, user.id)
        .await
        .map_err(|e| {
            log::error!("no se pudo cargar el RBAC al entrar: {e}");
            actix_web::error::ErrorInternalServerError("Error en la base de datos")
        })?;

    // Tokens
    let token = create_jwt(user.id, &rbac)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Token error"))?;
    let access_cookie = create_auth_cookie(&token);
    let expires_at = Utc::now() + chrono::Duration::days(30);
    let (refresh_token, refresh_hash) = generate_refresh_token();
    let refresh_cookie = create_refresh_cookie(&refresh_token);

    users::repositories_users::store_refresh_token(pool, user.id, &refresh_hash, &agent, &ip, expires_at).await?;

Ok(AuthResponse {
    access_cookie,
    refresh_cookie,
    user_json: serde_json::json!({
        "user_id": user.id,
        "user_type": user.user_type,
        "roles": rbac.roles,
        "permisos": rbac.permisos,
    }),
})
}

pub async fn get_user_profile_service(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<UserProfile, String> {
    // 1️⃣ Trae el user
    let user = users::repositories_users::find_user_by_id(pool, user_id)
        .await
        .map_err(|e| e.to_string())?;

    // 2️⃣ Trae Owner, Employer y Admin si existen
    let owner = sqlx::query_as::<_, Owner>("SELECT * FROM auth.owners WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;

    let employer = sqlx::query_as::<_, Employer>("SELECT * FROM auth.employers WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;

    let admin = sqlx::query_as::<_, Admin>("SELECT * FROM auth.admins WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;

    // 3️⃣ Roles y permisos, leídos de la base.
    //
    // Estos dos campos existían con un `vec![]` y un comentario que decía «aquí
    // puedes llenar tus roles si tienes lógica de RBAC». Ya la hay. Se leen de la
    // base y no del token porque este endpoint devuelve **el perfil real**, y un
    // token emitido hace nueve minutos puede no reflejar un cambio reciente.
    let rbac = crate::rbac::repositories_rbac::cargar(pool, user_id)
        .await
        .map_err(|e| e.to_string())?;

    let profile = UserProfile {
        user,
        owner,
        employer,
        admin,
        roles: rbac.roles,
        permissions: rbac.permisos,
    };

    Ok(profile)
}
