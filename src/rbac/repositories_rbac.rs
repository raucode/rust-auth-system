use crate::crates::*;

/// Lo que un usuario es y lo que puede hacer, resuelto desde la base.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Rbac {
    pub roles: Vec<String>,
    pub permisos: Vec<String>,
}

/// Carga roles y permisos efectivos de un usuario.
///
/// Se llama en el login y en el refresco, **no** en cada petición: ver el porqué
/// en la cabecera del módulo.
///
/// Un usuario sin ningún rol devuelve las dos listas vacías, y eso es una
/// respuesta legítima —no un error—: significa que puede entrar y no puede hacer
/// nada. Es exactamente lo que le pasa a una cuenta recién creada, y es el estado
/// correcto de partida.
pub async fn cargar(pool: &PgPool, user_id: Uuid) -> Result<Rbac, sqlx::Error> {
    let roles: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT r.name
        FROM auth.user_roles ur
        JOIN auth.roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1
        ORDER BY r.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // DISTINCT porque dos roles del mismo usuario pueden conceder el mismo
    // permiso, y un permiso repetido en el token solo lo engorda.
    let permisos: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT p.name
        FROM auth.user_roles ur
        JOIN auth.role_permissions rp ON rp.role_id = ur.role_id
        JOIN auth.permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = $1
        ORDER BY p.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(Rbac { roles, permisos })
}

/// El catálogo de roles, con cuántos permisos concede cada uno.
pub async fn listar_roles(pool: &PgPool) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let filas: Vec<(String, Option<String>, i64)> = sqlx::query_as(
        r#"
        SELECT r.name, r.description, COUNT(rp.permission_id)
        FROM auth.roles r
        LEFT JOIN auth.role_permissions rp ON rp.role_id = r.id
        GROUP BY r.name, r.description
        ORDER BY r.name
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(filas
        .into_iter()
        .map(|(name, description, permisos)| {
            serde_json::json!({ "rol": name, "descripcion": description, "permisos": permisos })
        })
        .collect())
}

/// Concede un rol a un usuario. Idempotente: concederlo dos veces no falla.
///
/// Devuelve `Ok(false)` si el rol no existe, para que la capa de arriba pueda
/// responder 404 en vez de 500 — pedir un rol inexistente es un error de quien
/// llama, no una avería.
pub async fn asignar_rol(pool: &PgPool, user_id: Uuid, rol: &str) -> Result<bool, sqlx::Error> {
    let filas = sqlx::query(
        r#"
        INSERT INTO auth.user_roles (user_id, role_id)
        SELECT $1, r.id FROM auth.roles r WHERE r.name = $2
        ON CONFLICT (user_id, role_id) DO NOTHING
        "#,
    )
    .bind(user_id)
    .bind(rol)
    .execute(pool)
    .await?;

    if filas.rows_affected() > 0 {
        return Ok(true);
    }

    // Cero filas puede ser «ya lo tenía» o «ese rol no existe». Son casos
    // distintos para quien llama, así que se distinguen.
    let existe: Option<i32> = sqlx::query_scalar("SELECT 1 FROM auth.roles WHERE name = $1")
        .bind(rol)
        .fetch_optional(pool)
        .await?;

    Ok(existe.is_some())
}

/// Retira un rol. Devuelve si había algo que retirar.
pub async fn retirar_rol(pool: &PgPool, user_id: Uuid, rol: &str) -> Result<bool, sqlx::Error> {
    let filas = sqlx::query(
        r#"
        DELETE FROM auth.user_roles ur
        USING auth.roles r
        WHERE ur.role_id = r.id AND ur.user_id = $1 AND r.name = $2
        "#,
    )
    .bind(user_id)
    .bind(rol)
    .execute(pool)
    .await?;

    Ok(filas.rows_affected() > 0)
}

/// Cuántos usuarios tienen un rol dado.
///
/// Existe para una sola cosa: **impedir que se retire el último `adm`**. Sin esa
/// guarda, un administrador puede quitarse el rol a sí mismo por error y dejar el
/// sistema sin nadie capaz de conceder permisos — y salir de ahí exige entrar a
/// mano en la base de datos.
pub async fn cuantos_tienen(pool: &PgPool, rol: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM auth.user_roles ur
        JOIN auth.roles r ON r.id = ur.role_id
        WHERE r.name = $1
        "#,
    )
    .bind(rol)
    .fetch_one(pool)
    .await
}

/// Comprueba que el usuario existe, antes de concederle nada.
pub async fn usuario_existe(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let existe: Option<i32> = sqlx::query_scalar("SELECT 1 FROM auth.users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(existe.is_some())
}
