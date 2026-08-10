//! Control de acceso por roles.
//!
//! Hasta hoy el sistema resolvía **quién eres** y no **qué puedes hacer**: las
//! cuatro tablas del RBAC existían vacías desde la migración inicial y ningún
//! fichero las consultaba, así que cualquier sesión válida alcanzaba cualquier
//! ruta protegida. Este módulo es la otra mitad.
//!
//! ## Dónde se resuelven los permisos
//!
//! **Al entrar y al refrescar, no en cada petición.** Los permisos se leen de la
//! base una vez, se firman dentro del JWT y viajan con él. `/auth/verify` —que un
//! proxy inverso consulta en *cada* petición HTTP, imágenes incluidas— solo tiene
//! que comprobar una firma.
//!
//! El precio está aceptado a conciencia: **retirar un permiso tarda hasta lo que
//! dure el token de acceso en surtir efecto** (hoy 10 minutos), porque hasta que
//! no se refresca nadie vuelve a mirar la base. Para un corte inmediato hay que
//! revocar el refresh *y* esperar a que caduque el acceso, o acortar su duración.
//! Es el mismo compromiso que hace Keycloak, y la alternativa —consultar el RBAC
//! en cada petición— convierte cada carga de página en varias consultas a
//! PostgreSQL.

pub mod handler_rbac;
pub mod matriz;
pub mod repositories_rbac;
pub mod routes_rbac;
