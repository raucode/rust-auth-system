use crate::{
    crates::*,
    users::{models_users, service_users},
};

/// Cabeceras que se guardan junto al refresh para poder distinguir sesiones.
///
/// Estaban copiadas en cuatro manejadores; la cuarta copia leía la IP con un
/// nombre distinto. Una función.
fn agente_e_ip(req: &HttpRequest) -> (String, String) {
    let agente = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("")
        .to_string();

    (agente, ip)
}

pub async fn register_user(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    payload: web::Json<models_users::RegisterUserPayload>,
) -> Result<HttpResponse, actix_web::Error> {
    let (agente, ip) = agente_e_ip(&req);

    let response =
        service_users::register_user_service(pool.get_ref(), payload.into_inner(), agente, ip)
            .await?;

    Ok(HttpResponse::Ok()
        .cookie(response.access_cookie)
        .cookie(response.refresh_cookie)
        .json(response.user_json))
}

pub async fn login_user(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    data: web::Json<LoginUser>,
) -> Result<HttpResponse, actix_web::Error> {
    let (agente, ip) = agente_e_ip(&req);

    let response =
        service_users::login_user_service(pool.get_ref(), data.into_inner(), agente, ip).await?;

    Ok(HttpResponse::Ok()
        .cookie(response.access_cookie)
        .cookie(response.refresh_cookie)
        .json(response.user_json))
}

pub async fn get_user_profile(req: HttpRequest, pool: web::Data<PgPool>) -> impl Responder {
    let user_id = match req.extensions().get::<Uuid>() {
        Some(id) => *id,
        None => return HttpResponse::InternalServerError().json("No user_id in request"),
    };

    match service_users::get_user_profile_service(pool.get_ref(), user_id).await {
        Ok(profile) => HttpResponse::Ok().json(profile),
        Err(e) => HttpResponse::InternalServerError().json(e),
    }
}
