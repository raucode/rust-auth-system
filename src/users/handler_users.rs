use crate::{crates::*, users::{models_users, service_users}};

//  imports locals


pub async fn register_user(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    payload: web::Json<models_users::RegisterUserPayload>,
) -> Result<HttpResponse, actix_web::Error> {

    log::info!("REGISTER HIT");
    let agent = req
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

    let response = service_users::register_user_service(
        pool.get_ref(),
        payload.into_inner(),
        agent,
        ip,
        req,
    )
    .await?;

    Ok(HttpResponse::Ok()
        .cookie(response.access_cookie)
        .cookie(response.refresh_cookie)
        .json(response.user_json))
}

pub async fn register_employer(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    payload: web::Json<RegisterUserPayload>,
) -> Result<HttpResponse, actix_web::Error> {

    let agent = req
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

    let response = service_users::register_user_service(
        pool.get_ref(),
        payload.into_inner(),
        agent,
        ip,
        req,
    )
    .await?;

    Ok(HttpResponse::Ok().json(response.user_json))
}

pub async fn get_employees_summary(
    pool: web::Data<PgPool>,
    req: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    // Obtener el restaurant ID del header
    let restaurant_id = req
        .headers()
        .get("x-restaurant-id")
        .ok_or_else(|| actix_web::error::ErrorBadRequest("x-restaurant-id header missing"))?
        .to_str()
        .map_err(|_| actix_web::error::ErrorBadRequest("invalid header value"))?;

    let restaurant_id = Uuid::parse_str(restaurant_id)
        .map_err(|_| actix_web::error::ErrorBadRequest("invalid UUID"))?;

    // Conexión a la DB
    let mut conn = pool.acquire().await
        .map_err(|_| actix_web::error::ErrorInternalServerError("DB connection error"))?;

    // Llamada al repositorio
    let employees = crate::users::repositories_users::get_employees_summary_by_restaurant(&mut conn, restaurant_id).await?;

    Ok(HttpResponse::Ok().json(employees))
}

pub async fn login_user(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    data: web::Json<LoginUser>,
) -> Result<HttpResponse, actix_web::Error> {

    let agent = req.headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let ip = req.connection_info().realip_remote_addr().unwrap_or("").to_string();

    let response = service_users::login_user_service(
        pool.get_ref(),
        data.into_inner(),
        agent,
        ip,
    )
    .await?;

    Ok(HttpResponse::Ok()
        .cookie(response.access_cookie)
        .cookie(response.refresh_cookie)
        .json(response.user_json))
}

pub async fn get_user_profile(
    req: HttpRequest,
    pool: web::Data<PgPool>,
) -> impl Responder {

    let user_id = match req.extensions().get::<Uuid>() {
        Some(id) => *id,
        None => return HttpResponse::InternalServerError().json("No user_id in request"),
    };

    match service_users::get_user_profile_service(pool.get_ref(), user_id).await {
        Ok(profile) => HttpResponse::Ok().json(profile),
        Err(e) => HttpResponse::InternalServerError().json(e),
    }
}