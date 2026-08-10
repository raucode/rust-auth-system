use crate::crates::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,

    // Qué es y qué puede hacer quien trae este token. Se resuelven contra la base
    // al entrar y al refrescar; a partir de ahí viajan firmados aquí dentro y
    // nadie vuelve a consultar el RBAC hasta el siguiente refresco. El porqué y su
    // precio, en la cabecera de `crate::rbac`.
    //
    // `serde(default)` no es adorno: sin él, **todos los tokens emitidos antes de
    // este cambio dejarían de decodificar** y toda sesión abierta se caería a 401
    // en el momento de desplegar. Con él, un token viejo entra con las listas
    // vacías y se completa solo en el primer refresco.
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub perms: Vec<String>,
}

impl Claims {
    /// Si esta sesión tiene un permiso concreto.
    pub fn puede(&self, permiso: &str) -> bool {
        self.perms.iter().any(|p| p == permiso)
    }
}

pub fn create_jwt(
    user_id: Uuid,
    rbac: &crate::rbac::repositories_rbac::Rbac,
) -> Result<String, jsonwebtoken::errors::Error> {
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let now = SystemTime::now();
    let iat = now.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs() as usize;
    let exp = iat + (60 * 10); // 10 minutos

    let claims = Claims {
        sub: user_id,
        iat,
        exp,
        roles: rbac.roles.clone(),
        perms: rbac.permisos.clone(),
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_ref()))
}

/// Responde si la sesión de esta petición es válida. **No sirve contenido.**
///
/// Es la pieza que consume un proxy inverso mediante una subpetición
/// (`auth_request` en nginx, `forwardAuth` en Traefik): antes de servir una ruta
/// protegida el proxy pregunta aquí, y con un `200` deja pasar y con un `401`
/// manda al login.
///
/// Con eso, **un servicio que esté detrás del proxy no necesita saber nada de
/// JWT**: recibe la identidad ya resuelta. El visor de infraestructura no tiene
/// hoy ni una línea de autenticación, y por esta vía sigue sin necesitarla.
///
/// El proxy **tiene que borrar cualquier `X-Auth-*` que llegue de fuera** antes
/// de reenviar la petición: si un cliente pudiera mandarla, se declararía quien
/// quisiera. Esa es la regla que sostiene todo el esquema.
///
/// Vive bajo `/auth`, que el middleware trata como público, porque hace su propia
/// validación y su trabajo es precisamente **poder responder que no**.
pub async fn verify(req: HttpRequest) -> HttpResponse {
    let Some(cookie) = req.cookie("token") else {
        return HttpResponse::Unauthorized().finish();
    };

    match crate::middleware::validar_token(cookie.value()) {
        Ok(claims) => HttpResponse::Ok()
            .insert_header(("X-Auth-User", claims.sub.to_string()))
            // Roles y permisos viajan separados por coma porque una cabecera HTTP
            // es texto plano: es el formato que nginx sabe reenviar tal cual y que
            // cualquier servicio de detrás puede partir sin traerse un parser de
            // JSON. Salen de los claims ya validados, así que esto **no consulta
            // la base** — y este endpoint lo llama el proxy en cada petición.
            .insert_header(("X-Auth-Roles", claims.roles.join(",")))
            .insert_header(("X-Auth-Perms", claims.perms.join(",")))
            .finish(),
        Err(err) => {
            log::debug!("verify rechazado: {err:?}");
            HttpResponse::Unauthorized().finish()
        }
    }
}

pub fn create_auth_cookie(token: &str) -> Cookie<'static> {
    let max_age = TimeDuration::minutes(10);
    let expires = time::OffsetDateTime::now_utc() + max_age;

    Cookie::build("token", token.to_string())
        .path("/")
        .http_only(crate::config::cookie_httponly())
        .secure(crate::config::cookie_secure())
        .same_site(SameSite::Lax)
        .max_age(max_age)
        .expires(expires)
        .finish()
}

// Generar refresh token aleatorio
pub fn generate_refresh_token() -> (String, String) {
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    // `base64::encode` quedó deprecada: en 0.22 se codifica a través de un
    // «engine» explícito, para que el alfabeto y el relleno sean una elección y no
    // un valor por defecto oculto.
    let token = BASE64_STANDARD.encode(bytes);

    let mut hasher = Sha256::new();
    hasher.update(&token);
    let token_hash = format!("{:x}", hasher.finalize());

    (token, token_hash)
}

// Crear cookie de refresh token
pub fn create_refresh_cookie(token: &str) -> Cookie<'static> {
    let max_age = TimeDuration::days(7);
    let expires = time::OffsetDateTime::now_utc() + max_age;

    Cookie::build("refresh_token", token.to_string())
        .path("/")
        .http_only(crate::config::cookie_httponly())
        .secure(crate::config::cookie_secure())
        .same_site(SameSite::Lax)
        .max_age(max_age)
        .expires(expires)
        .finish()
}

// Guardar refresh token en DB
pub async fn store_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: String,
    user_agent:String,
    ip: String,
) -> Result<(), sqlx::Error> {
    let expires_at = Utc::now() + ChronoDuration::days(7);

    sqlx::query!(
        "INSERT INTO auth.refresh_tokens (user_id, token_hash, user_agent, ip, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
        user_id,
        token_hash,
        user_agent,
        ip,
        expires_at
    )
    .execute(pool)
    .await?;

    Ok(())
}

// Funcion para refrescar el token (revisarlaxd)
pub async fn refresh_token(
        req: HttpRequest,
        pool: web::Data<PgPool>
    ) -> Result<HttpResponse, actix_web::Error> {
        let refresh_cookie = req.cookie("refresh_token")
            .ok_or_else(|| actix_web::error::ErrorUnauthorized("No refresh token"))?;
        let refresh_token_value = refresh_cookie.value();

        // Hash del token
        let mut hasher = Sha256::new();
        hasher.update(refresh_token_value);
        let token_hash = format!("{:x}", hasher.finalize());

        // Buscar en DB
        let record = sqlx::query!(
            "SELECT user_id, revoked, expires_at FROM auth.refresh_tokens WHERE token_hash = $1",
            token_hash
        )
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Error en la base de datos al refrescar token: {}", e);
            actix_web::error::ErrorInternalServerError("Error en la base de datos")
        })?;

        match record {
            Some(r) if !r.revoked && r.expires_at > chrono::Utc::now() => {
                // **Aquí es donde un cambio de permisos entra en vigor.** El token
                // de acceso lleva los permisos dentro, así que mientras vive nadie
                // mira la base; al refrescarlo se vuelven a leer. Esa es la razón
                // de que la ventana entre conceder o retirar un permiso y que se
                // note sea, como mucho, lo que dure el acceso.
                let rbac = crate::rbac::repositories_rbac::cargar(pool.get_ref(), r.user_id)
                    .await
                    .map_err(|e| {
                        log::error!("no se pudo cargar el RBAC al refrescar: {e}");
                        actix_web::error::ErrorInternalServerError("Error en la base de datos")
                    })?;

                let access_token = create_jwt(r.user_id, &rbac)
                    .map_err(|_| actix_web::error::ErrorInternalServerError("No se pudo crear el token"))?;

                let access_cookie = create_auth_cookie(&access_token);

                Ok(HttpResponse::Ok().cookie(access_cookie).finish())
            },
            _ => Err(actix_web::error::ErrorUnauthorized("Token de refresco inválido o expirado")),
        }
    }

// Funcion de deslogueo
    pub async fn logout(req: HttpRequest, pool: web::Data<PgPool>) -> HttpResponse {
        if let Some(c) = req.cookie("refresh_token") {
            let mut hasher = Sha256::new();
            hasher.update(c.value());
            let token_hash = format!("{:x}", hasher.finalize());

            let _ = sqlx::query!(
                "UPDATE auth.refresh_tokens SET revoked = true WHERE token_hash = $1",
                token_hash
            )
            .execute(pool.get_ref())
            .await;
        }

        HttpResponse::Ok()
            .cookie(
                Cookie::build("token", "")
                    .path("/")
                    .http_only(crate::config::cookie_httponly())
                    .secure(crate::config::cookie_secure())
                    .same_site(actix_web::cookie::SameSite::Lax)
                    .finish()
            )
            .finish()
    }
