use crate::crates::*;
use crate::users::models_users::*;
use crate::users::{self, repositories_users};

pub struct AuthResponse {
    pub access_cookie: Cookie<'static>,
    pub refresh_cookie: Cookie<'static>,
    pub user_json: serde_json::Value,
}

/// Alta de una cuenta.
///
/// Aquí había una máquina de tres casos: un empleado tenía que venir autenticado
/// por su dueño y con una cabecera `x-restaurant-id`, y cada tipo insertaba además
/// en su tabla satélite dentro de una transacción. Todo eso era el alta de un
/// producto concreto, no de una identidad, y se fue el 2026-09-08 con las tablas.
///
/// Lo que queda es lo que hace un sistema de identidad: comprobar que no hay nadie
/// con ese correo, guardar el hash y abrir sesión. **Quién puede darse de alta es
/// decisión del consumidor**, que monta esta ruta o no la monta.
pub async fn register_user_service(
    pool: &PgPool,
    data: RegisterUserPayload,
    agent: String,
    ip: String,
) -> Result<AuthResponse, actix_web::Error> {
    // El hash se calcula antes de tocar la base para que la contraseña en claro no
    // llegue nunca al log de consultas de PostgreSQL.
    let password_hash = crate::passwords::cifrar(&data.password)
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let user_id = Uuid::new_v4();
    let user = repositories_users::create_user(pool, user_id, &data, &password_hash).await?;

    // Un usuario recién registrado **no tiene ningún rol todavía**, así que aquí se
    // carga igualmente en vez de dar por hecho que está vacío: si algún día el alta
    // concede un rol por defecto, esto ya lo recoge sin que nadie se acuerde de
    // volver.
    let rbac = crate::rbac::repositories_rbac::cargar(pool, user.id)
        .await
        .map_err(|e| {
            log::error!("no se pudo cargar el RBAC al registrar: {e}");
            actix_web::error::ErrorInternalServerError("db error")
        })?;

    let access_token = create_jwt(user.id, &rbac)
        .map_err(|_| actix_web::error::ErrorInternalServerError("jwt error"))?;
    let access_cookie = create_auth_cookie(&access_token);

    let expires_at = Utc::now() + ChronoDuration::days(30);
    let (refresh_token, refresh_hash) = generate_refresh_token();
    let refresh_cookie = create_refresh_cookie(&refresh_token);

    repositories_users::store_refresh_token(pool, user.id, &refresh_hash, &agent, &ip, expires_at)
        .await?;

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

    match crate::passwords::verificar(&data.password, &user.password_hash) {
        crate::passwords::Verificacion::Incorrecta => {
            return Err(actix_web::error::ErrorUnauthorized("Invalid credentials"));
        }
        crate::passwords::Verificacion::Correcta => {}
        // El hash era del formato viejo. **Este es el único instante en que se puede
        // migrar**: es cuando alguien acaba de escribir su contraseña bien, y sin
        // ella no hay forma de calcular el hash nuevo.
        //
        // Si la escritura falla, se entra igual. Que la base siga con un hash de
        // bcrypt un rato más no le impide a nadie usar el sistema, y negarle la
        // entrada a quien puso su contraseña correcta sí.
        crate::passwords::Verificacion::CorrectaYRehecha(nuevo) => {
            if let Err(e) =
                users::repositories_users::actualizar_password_hash(pool, user.id, &nuevo).await
            {
                log::warn!("no se pudo guardar el hash rehecho de {}: {e}", user.id);
            } else {
                log::info!("contraseña de {} migrada de bcrypt a argon2id", user.id);
            }
        }
    }

    // Roles y permisos, resueltos una vez y firmados dentro del token.
    let rbac = crate::rbac::repositories_rbac::cargar(pool, user.id)
        .await
        .map_err(|e| {
            log::error!("no se pudo cargar el RBAC al entrar: {e}");
            actix_web::error::ErrorInternalServerError("Error en la base de datos")
        })?;

    let token = create_jwt(user.id, &rbac)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Token error"))?;
    let access_cookie = create_auth_cookie(&token);

    let expires_at = Utc::now() + ChronoDuration::days(30);
    let (refresh_token, refresh_hash) = generate_refresh_token();
    let refresh_cookie = create_refresh_cookie(&refresh_token);

    users::repositories_users::store_refresh_token(
        pool,
        user.id,
        &refresh_hash,
        &agent,
        &ip,
        expires_at,
    )
    .await?;

    Ok(AuthResponse {
        access_cookie,
        refresh_cookie,
        user_json: serde_json::json!({
            "user_id": user.id,
            "roles": rbac.roles,
            "permisos": rbac.permisos,
        }),
    })
}

pub async fn get_user_profile_service(pool: &PgPool, user_id: Uuid) -> Result<UserProfile, String> {
    let user = users::repositories_users::find_user_by_id(pool, user_id)
        .await
        .map_err(|e| e.to_string())?;

    let rbac = crate::rbac::repositories_rbac::cargar(pool, user_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(UserProfile {
        user,
        roles: rbac.roles,
        permissions: rbac.permisos,
    })
}
