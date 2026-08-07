//! El primer usuario.
//!
//! Sin nadie dado de alta no se puede entrar, y sin entrar no se puede dar de
//! alta a nadie. El registro está abierto hoy, así que el problema no bloquea —
//! pero en cuanto se cierre, sí, y entonces hará falta esto de todas formas.
//!
//! Se crea al arrancar y **solo si no existe ya**: la función es idempotente, así
//! que arrancar dos veces no duplica nada ni sobrescribe una contraseña que se
//! haya cambiado luego.

use bcrypt::{DEFAULT_COST, hash};
use sqlx::PgPool;

use crate::config;

/// Crea el administrador inicial si hay credenciales configuradas y no existe.
///
/// **No aborta el arranque si falla.** Un servicio de identidad que no arranca
/// porque el usuario semilla ya estaba, o porque la contraseña del entorno tiene
/// algo raro, deja de dar sesiones a todo el mundo por un problema que no afecta a
/// nadie que ya esté dentro. Se registra el aviso y se sigue.
pub async fn crear_admin_si_falta(pool: &PgPool) {
    let Some((email, password)) = config::admin_inicial() else {
        log::debug!("sin ADMIN_EMAIL/ADMIN_PASSWORD: no se crea administrador inicial");
        return;
    };

    match ya_existe(pool, &email).await {
        Ok(true) => {
            log::info!("administrador inicial ya existe: {email}");
            return;
        }
        Ok(false) => {}
        Err(err) => {
            log::warn!("no se pudo comprobar si existe el administrador inicial: {err}");
            return;
        }
    }

    // El hash se calcula aquí y no en SQL: la contraseña en claro no debe llegar
    // nunca al log de consultas de PostgreSQL.
    let password_hash = match hash(&password, DEFAULT_COST) {
        Ok(h) => h,
        Err(err) => {
            log::warn!("no se pudo cifrar la contraseña del administrador inicial: {err}");
            return;
        }
    };

    // `state` y `user_type` son NOT NULL en el esquema y no significan nada para un
    // administrador interno: son restos del modelo de restaurantes. Se rellenan
    // con lo mínimo y desaparecerán al separar la identidad del negocio.
    let insercion = sqlx::query(
        r#"
        INSERT INTO auth.users (email, password_hash, full_name, state, user_type, is_active)
        VALUES ($1, $2, $3, 'GO', 'admin', TRUE)
        ON CONFLICT (email) DO NOTHING
        "#,
    )
    .bind(&email)
    .bind(&password_hash)
    .bind("Administrador")
    .execute(pool)
    .await;

    match insercion {
        Ok(res) if res.rows_affected() > 0 => {
            log::info!("administrador inicial creado: {email}");
        }
        Ok(_) => log::info!("administrador inicial ya existía: {email}"),
        Err(err) => log::warn!("no se pudo crear el administrador inicial: {err}"),
    }
}

async fn ya_existe(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    let existe: Option<i32> = sqlx::query_scalar("SELECT 1 FROM auth.users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    Ok(existe.is_some())
}
