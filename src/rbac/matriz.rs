//! La matriz rol → permisos, en memoria.
//!
//! ## Por qué esto existe
//!
//! Los permisos **vivían dentro del token**. Eso tenía dos problemas y el segundo
//! es el que importa:
//!
//! 1. El token crecía con el catálogo, y viaja en cada petición: es una cookie, y
//!    la manda el navegador con cada imagen y cada hoja de estilo. Con diez
//!    permisos eran 465 bytes; con cincuenta, más de un kilobyte en todas.
//! 2. **Retirar un permiso a un rol no surtía efecto hasta diez minutos después**,
//!    cuando caducaba el último token que lo llevaba dentro. La matriz es política
//!    de la empresa: si se decide que `user` ya no edita, tiene que dejar de
//!    editar, no dejar de editar dentro de un rato.
//!
//! ## Por qué en memoria y no consultando la base
//!
//! Porque quien pregunta es `/auth/verify`, y a eso lo llama el proxy en **cada**
//! petición HTTP. Consultar PostgreSQL ahí sería una consulta por cada icono de un
//! plano.
//!
//! Y no hace falta, porque son dos cosas de tamaño muy distinto:
//!
//! | | Qué es | Cuánto ocupa |
//! |---|---|---|
//! | `user_roles` | Qué roles tiene **una persona** | Crece con la plantilla |
//! | `role_permissions` | Qué concede **cada rol** | Cinco roles, diez permisos |
//!
//! Lo primero sigue en el token, que es donde va bien lo que es de cada uno. Lo
//! segundo cabe entero en memoria y se recarga solo.
//!
//! ## Caducidad corta en vez de invalidación
//!
//! Se recarga sola cada treinta segundos. Se eligió frente a invalidarla cuando
//! alguien toca la matriz porque esa vía **solo funciona si el cambio pasa por
//! este proceso**: un `UPDATE` a mano en `psql` no avisaría a nadie, y el día que
//! haya dos copias del auth corriendo cada una tendría su propia idea de quién
//! puede qué. Treinta segundos de retraso es un precio pequeño por no tener que
//! acordarse de nada.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::crates::*;

/// Cuánto vale una copia cargada antes de volver a leerla.
const VIGENCIA: Duration = Duration::from_secs(30);

struct Copia {
    /// Rol → permisos que concede, ya ordenados.
    por_rol: HashMap<String, Vec<String>>,
    cargada: Instant,
}

/// La matriz compartida por todo el proceso.
///
/// `RwLock` y no `Mutex`: se lee en cada petición y se escribe cada treinta
/// segundos, así que las lecturas no deben esperarse entre ellas.
pub struct Matriz {
    copia: RwLock<Option<Copia>>,
}

impl Matriz {
    pub fn nueva() -> Self {
        Self { copia: RwLock::new(None) }
    }

    /// Los permisos que conceden estos roles, sin repetidos y ordenados.
    ///
    /// Si la copia está caducada se recarga; si la recarga falla, **se sigue
    /// usando la copia vieja**. Un fallo momentáneo de la base no puede dejar sin
    /// permisos a todo el mundo: eso convertiría una incidencia de base de datos
    /// en un corte de acceso general.
    pub async fn permisos_de(&self, pool: &PgPool, roles: &[String]) -> Vec<String> {
        if self.caducada() {
            match leer_de_la_base(pool).await {
                Ok(por_rol) => {
                    if let Ok(mut guardia) = self.copia.write() {
                        *guardia = Some(Copia { por_rol, cargada: Instant::now() });
                    }
                }
                Err(e) => log::warn!("no se pudo recargar la matriz de permisos: {e}"),
            }
        }

        let Ok(guardia) = self.copia.read() else {
            return Vec::new();
        };
        let Some(copia) = guardia.as_ref() else {
            // Nunca se pudo cargar: ni una sola vez, ni siquiera al arrancar. Sin
            // permisos es lo correcto — inventarlos sería peor.
            return Vec::new();
        };

        let mut permisos: Vec<String> = roles
            .iter()
            .filter_map(|rol| copia.por_rol.get(rol))
            .flatten()
            .cloned()
            .collect();

        // Dos roles pueden conceder el mismo permiso.
        permisos.sort();
        permisos.dedup();
        permisos
    }

    fn caducada(&self) -> bool {
        match self.copia.read() {
            Ok(guardia) => match guardia.as_ref() {
                Some(copia) => copia.cargada.elapsed() > VIGENCIA,
                None => true,
            },
            // Si el candado está envenenado, se intenta recargar: no empeora nada.
            Err(_) => true,
        }
    }

    /// Carga la matriz al arrancar, para que la primera petición no pague la
    /// espera y para que un error de conexión se vea en el arranque y no más
    /// tarde, disfrazado de «este usuario no tiene permisos».
    pub async fn precargar(&self, pool: &PgPool) {
        match leer_de_la_base(pool).await {
            Ok(por_rol) => {
                let roles = por_rol.len();
                let total: usize = por_rol.values().map(Vec::len).sum();
                if let Ok(mut guardia) = self.copia.write() {
                    *guardia = Some(Copia { por_rol, cargada: Instant::now() });
                }
                log::info!("matriz de permisos cargada: {roles} roles, {total} concesiones");
            }
            Err(e) => log::error!("no se pudo cargar la matriz de permisos al arrancar: {e}"),
        }
    }
}

async fn leer_de_la_base(pool: &PgPool) -> Result<HashMap<String, Vec<String>>, sqlx::Error> {
    let filas: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT r.name, p.name
        FROM auth.role_permissions rp
        JOIN auth.roles r ON r.id = rp.role_id
        JOIN auth.permissions p ON p.id = rp.permission_id
        ORDER BY r.name, p.name
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut por_rol: HashMap<String, Vec<String>> = HashMap::new();
    for (rol, permiso) in filas {
        por_rol.entry(rol).or_default().push(permiso);
    }
    Ok(por_rol)
}
