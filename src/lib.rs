//! Identidad para servicios en Rust: sesiones, refresh y permisos, dentro de tu
//! propio binario.
//!
//! ## Qué resuelve, y por qué es una librería
//!
//! Todo servicio interno acaba necesitando lo mismo: quién eres, si tu sesión
//! sigue viva y qué te deja hacer tu rol. Escribirlo cada vez es escribir tres
//! veces el mismo JWT, el mismo refresh y la misma tabla de permisos —y equivocarse
//! en sitios distintos—. Esto se escribe una vez y se importa.
//!
//! ```ignore
//! // En el arranque de tu servicio, sobre un pool que ya tienes:
//! rust_auth_system::MIGRACIONES.run(&pool).await?;
//! let matriz = rust_auth_system::preparar(&pool).await;
//!
//! HttpServer::new(move || {
//!     App::new()
//!         .app_data(web::Data::new(pool.clone()))
//!         .app_data(matriz.clone())
//!         .configure(rust_auth_system::rutas_sesion)          // públicas: login, refresh…
//!         .configure(rust_auth_system::rutas_administracion)  // protegidas: perfil, RBAC…
//! })
//! ```
//!
//! El servicio que hace eso **no necesita proxy delante para autenticar**, ni
//! sabe qué es un JWT: pide la identidad al extractor y ya está resuelta.
//!
//! ## Lo que no está aquí
//!
//! **Integrar esto con plataformas que no son Rust es el trabajo del SSO**, que
//! es otro proyecto y nace de este. Allí vive el servicio suelto que responde
//! `GET /auth/verify` a un proxy inverso, con su web y sus frontends. Aquí no
//! hay binario: un componente que además se levanta solo acaba siendo dos cosas
//! y ninguna del todo.
//!
//! `rutas_sesion` incluye `verify` porque es una ruta más de sesión y no estorba
//! integrada; quien la necesita de verdad es ese servicio.
//!
//! ## Lo que el consumidor tiene que saber de la base
//!
//! Las migraciones crean y usan el esquema **`auth`**, así que conviven con las
//! tablas de quien las importe sin colisionar por nombre. Lo que sí colisiona es
//! el registro de migraciones: `sqlx` 0.8 lo escribe siempre en una tabla llamada
//! `_sqlx_migrations` y **no deja renombrarla** desde el `Migrator`. Ver
//! [`MIGRACIONES`].

pub mod auth;
pub mod bootstrap;
pub mod config;
pub mod crates;
pub mod db;
pub mod middleware;
pub mod rbac;
pub mod servicios;
pub mod users;

use actix_web::web;
use sqlx::PgPool;

use crate::middleware::AuthMiddleware;
use crate::rbac::matriz::Matriz;
use crate::rbac::routes_rbac::rbac_routes;
use crate::users::routes_users::user_routes;

/// Las migraciones del esquema `auth`, embebidas en el binario de quien importe
/// esto. No hace falta arrastrar la carpeta `migrations/` al despliegue.
///
/// ## El cuidado que hay que tener al compartir base
///
/// `sqlx` 0.8 anota lo aplicado en `_sqlx_migrations` y **no permite cambiarle el
/// nombre** desde el `Migrator` —solo expone `set_ignore_missing` y
/// `set_locking`—. Si el consumidor tiene sus propias migraciones sobre la misma
/// base y el mismo `search_path`, los dos juegos acaban anotados en la misma
/// tabla y cada uno ve las del otro como versiones que le faltan.
///
/// La salida es **no compartir `search_path`**: aplicar estas con una conexión
/// cuyo esquema de trabajo sea `auth`, de modo que el registro viva en
/// `auth._sqlx_migrations` y el del consumidor en el suyo. Es separación de
/// verdad, y no depende de que nadie recuerde poner una bandera.
pub static MIGRACIONES: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Deja la identidad lista sobre un pool que ya existe: crea el administrador
/// inicial si falta y precarga la matriz de permisos.
///
/// La matriz se precarga **antes de atender a nadie** a propósito: así la primera
/// petición no paga la espera, y un problema de conexión se ve en el arranque en
/// vez de disfrazado más tarde de «este usuario no tiene permisos».
///
/// Devuelve la matriz ya envuelta en `web::Data` porque es lo que hay que
/// registrar en la aplicación, y porque clonarla clona el puntero y no el
/// contenido: todos los trabajadores comparten una, que es la que se recarga sola.
pub async fn preparar(pool: &PgPool) -> web::Data<Matriz> {
    bootstrap::crear_admin_si_falta(pool).await;

    let matriz = web::Data::new(Matriz::nueva());
    matriz.precargar(pool).await;
    matriz
}

/// Las rutas que tienen que ser públicas, bajo `/auth`.
///
/// Son públicas porque **su trabajo incluye poder responder que no**: pedir sesión
/// para entrar al login deja fuera justo a quien viene a identificarse.
///
/// Requiere que la aplicación tenga registrados el `PgPool` y la [`Matriz`] que
/// devuelve [`preparar`].
pub fn rutas_sesion(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .configure(user_routes)
            // Solo hace falta cuando este crate corre como servicio suelto y un
            // proxy le pregunta. Integrado no estorba: es la misma respuesta que
            // el servicio ya puede resolver por dentro.
            .route("/verify", web::get().to(auth::handler_auth::verify))
            // Público como el login, y por el mismo motivo: lo consulta la
            // pantalla de sesión de alguien que todavía no ha entrado.
            .route("/destino", web::get().to(servicios::comprobar_destino)),
    );
}

/// Las rutas de perfil y administración de identidad, bajo `/api`, tras sesión.
///
/// El middleware de este ámbito **solo exige sesión**. Los permisos se exigen más
/// adentro, en cada sub-ámbito, porque no todas piden lo mismo: `/api/me/permisos`
/// la usa cualquiera con sesión, y `/api/rbac` solo quien administra permisos.
///
/// Un consumidor que ya tenga su propio `/api` puede no montar esto y quedarse
/// solo con [`rutas_sesion`]: la sesión y los permisos funcionan igual.
pub fn rutas_administracion(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .wrap(AuthMiddleware::sesion())
            .route(
                "/profile",
                web::get().to(users::handler_users::get_user_profile),
            )
            .service(
                web::scope("/me")
                    .route("", web::post().to(users::handler_users::register_employer))
                    .route(
                        "/summary",
                        web::get().to(users::handler_users::get_employees_summary),
                    )
                    .route("/permisos", web::get().to(rbac::handler_rbac::mis_permisos)),
            )
            .route("/servicios", web::get().to(servicios::mis_servicios))
            .configure(rbac_routes),
    );
}
