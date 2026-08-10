use crate::crates::*;
use crate::middleware::AuthMiddleware;
use crate::rbac::handler_rbac;

/// Las rutas de administración del RBAC.
///
/// Cuelgan de `/api` y **nunca de `/auth`**. No es una preferencia de estilo: el
/// middleware trata como público todo lo que empiece por `/auth`, porque ahí
/// viven el login y `verify`, que tienen que poder responder sin sesión. Colgar
/// aquí «conceder rol» lo dejaría abierto a cualquiera que supiera la URL.
///
/// Todas exigen `rbac:administrar`, que es el permiso que concede permisos.
pub fn rbac_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/rbac")
            .wrap(AuthMiddleware::permiso("rbac:administrar"))
            .route("/roles", web::get().to(handler_rbac::listar_roles))
            .route("/usuarios/{id}", web::get().to(handler_rbac::roles_de_usuario))
            .route("/usuarios/{id}/roles", web::post().to(handler_rbac::asignar_rol))
            .route("/usuarios/{id}/roles/{rol}", web::delete().to(handler_rbac::retirar_rol)),
    );
}
