use crate::crates::*;
use crate::middleware::Identidad;
use crate::rbac::repositories_rbac as repo;

#[derive(Deserialize)]
pub struct AsignarRol {
    pub rol: String,
}

/// El catálogo de roles disponibles.
pub async fn listar_roles(pool: web::Data<PgPool>) -> HttpResponse {
    match repo::listar_roles(pool.get_ref()).await {
        Ok(roles) => HttpResponse::Ok().json(roles),
        Err(e) => {
            log::error!("listar_roles: {e}");
            HttpResponse::InternalServerError().json("Error en la base de datos")
        }
    }
}

/// Qué es y qué puede hacer un usuario concreto, leído de la base.
///
/// Deliberadamente de la base y no de su token: es la vista de quien administra,
/// y tiene que enseñar **el estado real**, incluido lo que todavía no ha llegado
/// a la sesión de esa persona porque su token aún no se ha refrescado.
pub async fn roles_de_usuario(pool: web::Data<PgPool>, id: web::Path<Uuid>) -> HttpResponse {
    let user_id = id.into_inner();

    match repo::usuario_existe(pool.get_ref(), user_id).await {
        Ok(false) => return HttpResponse::NotFound().json("Ese usuario no existe"),
        Err(e) => {
            log::error!("roles_de_usuario: {e}");
            return HttpResponse::InternalServerError().json("Error en la base de datos");
        }
        Ok(true) => {}
    }

    match repo::cargar(pool.get_ref(), user_id).await {
        Ok(rbac) => HttpResponse::Ok().json(rbac),
        Err(e) => {
            log::error!("roles_de_usuario: {e}");
            HttpResponse::InternalServerError().json("Error en la base de datos")
        }
    }
}

/// Concede un rol.
pub async fn asignar_rol(
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
    body: web::Json<AsignarRol>,
) -> HttpResponse {
    let user_id = id.into_inner();
    let rol = body.rol.trim().to_string();

    match repo::usuario_existe(pool.get_ref(), user_id).await {
        Ok(false) => return HttpResponse::NotFound().json("Ese usuario no existe"),
        Err(e) => {
            log::error!("asignar_rol: {e}");
            return HttpResponse::InternalServerError().json("Error en la base de datos");
        }
        Ok(true) => {}
    }

    match repo::asignar_rol(pool.get_ref(), user_id, &rol).await {
        Ok(true) => {
            log::info!("rol {rol} concedido a {user_id}");
            HttpResponse::Ok().json(serde_json::json!({
                "asignado": rol,
                "aviso": "surte efecto en su proxima sesion o al refrescar el token"
            }))
        }
        Ok(false) => HttpResponse::NotFound().json(format!("El rol {rol} no existe")),
        Err(e) => {
            log::error!("asignar_rol: {e}");
            HttpResponse::InternalServerError().json("Error en la base de datos")
        }
    }
}

/// Retira un rol.
///
/// Con una guarda: **no se puede retirar el último `adm`**. Es el único caso en
/// que este endpoint dice que no a quien tiene permiso de sobra para hacerlo, y
/// la razón es que el error no tiene vuelta atrás por la vía normal — sin ningún
/// administrador no queda nadie capaz de volver a concederlo, y hay que entrar a
/// la base de datos a mano.
pub async fn retirar_rol(pool: web::Data<PgPool>, ruta: web::Path<(Uuid, String)>) -> HttpResponse {
    let (user_id, rol) = ruta.into_inner();

    if rol == "adm" {
        match repo::cuantos_tienen(pool.get_ref(), "adm").await {
            Ok(n) if n <= 1 => {
                return HttpResponse::Conflict().json(
                    "Es el ultimo administrador: concede adm a otra persona antes de retirarselo",
                );
            }
            Err(e) => {
                log::error!("retirar_rol: {e}");
                return HttpResponse::InternalServerError().json("Error en la base de datos");
            }
            Ok(_) => {}
        }
    }

    match repo::retirar_rol(pool.get_ref(), user_id, &rol).await {
        Ok(true) => {
            log::info!("rol {rol} retirado a {user_id}");
            HttpResponse::Ok().json(serde_json::json!({
                "retirado": rol,
                "aviso": "su token actual conserva el permiso hasta que caduque, como mucho 10 minutos"
            }))
        }
        Ok(false) => HttpResponse::NotFound().json("Ese usuario no tenia ese rol"),
        Err(e) => {
            log::error!("retirar_rol: {e}");
            HttpResponse::InternalServerError().json("Error en la base de datos")
        }
    }
}

/// Lo que puede hacer quien pregunta, según su token.
///
/// Sale de los claims y no de la base **a propósito**: es lo que una interfaz
/// necesita para decidir qué botones pinta, y tiene que coincidir con lo que el
/// servidor va a aceptar de esa misma sesión. Si esto consultara la base, la
/// pantalla enseñaría un botón que la petición siguiente rechazaría con 403.
pub async fn mis_permisos(req: HttpRequest) -> HttpResponse {
    let identidad = req.extensions().get::<Identidad>().cloned();

    match identidad {
        Some(i) => HttpResponse::Ok().json(serde_json::json!({
            "user_id": i.user_id,
            "roles": i.roles,
            "permisos": i.permisos,
        })),
        // El middleware la inserta siempre que deja pasar, así que llegar aquí sin
        // ella significa que alguien colgó esta ruta fuera del scope protegido.
        None => HttpResponse::InternalServerError().json("Sin identidad en la peticion"),
    }
}
