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
            // Aunque ya exista, se comprueba que tenga el rol. El administrador
            // de esta base se creó antes de que el RBAC estuviera sembrado, así
            // que existe y no es nada — y ese es justo el estado en el que nadie
            // puede conceder permisos a nadie.
            asegurar_rol_adm(pool, &email).await;
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

    // `user_type` sigue siendo NOT NULL y no significa nada para un administrador
    // interno: es el último resto del modelo de restaurantes en esta tabla. Se
    // rellena con lo mínimo y desaparecerá al separar la identidad del negocio.
    // `state` ya no está: se retiró el 2026-08-10.
    let insercion = sqlx::query(
        r#"
        INSERT INTO auth.users (email, password_hash, full_name, user_type, is_active)
        VALUES ($1, $2, $3, 'admin', TRUE)
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
            asegurar_rol_adm(pool, &email).await;
        }
        Ok(_) => log::info!("administrador inicial ya existía: {email}"),
        Err(err) => log::warn!("no se pudo crear el administrador inicial: {err}"),
    }
}

/// Le da el rol `adm` al administrador inicial si no lo tiene ya.
///
/// Idempotente y silenciosa cuando no hay nada que hacer. No aborta el arranque
/// si falla, por la misma razón que el resto de este fichero: un servicio de
/// identidad caído deja fuera a todo el mundo, y esto solo afecta a una cuenta.
///
/// Si el rol `adm` no existe todavía —la migración del RBAC no se ha aplicado—
/// no inserta nada y lo dice. Crear el rol aquí sería peor: el catálogo de
/// permisos vive en una migración, versionada y auditable, y no en un efecto
/// secundario del arranque.
async fn asegurar_rol_adm(pool: &PgPool, email: &str) {
    let resultado = sqlx::query(
        r#"
        INSERT INTO auth.user_roles (user_id, role_id)
        SELECT u.id, r.id
        FROM auth.users u, auth.roles r
        WHERE u.email = $1 AND r.name = 'adm'
        ON CONFLICT (user_id, role_id) DO NOTHING
        "#,
    )
    .bind(email)
    .execute(pool)
    .await;

    match resultado {
        Ok(res) if res.rows_affected() > 0 => {
            log::info!("rol adm concedido al administrador inicial: {email}")
        }
        Ok(_) => log::debug!("el administrador inicial ya tenía el rol adm, o el rol no existe"),
        Err(err) => log::warn!("no se pudo conceder el rol adm a {email}: {err}"),
    }
}

async fn ya_existe(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    let existe: Option<i32> = sqlx::query_scalar("SELECT 1 FROM auth.users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    Ok(existe.is_some())
}
