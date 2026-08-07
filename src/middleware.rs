use crate::crates::*;
use actix_web::{
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::Method,
    Error, HttpResponse,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use std::{env, rc::Rc};

#[derive(Clone, Copy)]
pub enum AuthMode {
    Required,
    Optional,
}

/// Valida un token de acceso y devuelve sus claims.
///
/// Estaba escrita dentro de `call`, y ahora vive aquí porque tiene **dos
/// consumidores**: el middleware, que protege las rutas de este servicio, y el
/// endpoint `/auth/verify`, que responde a la pregunta de un proxy inverso.
/// Duplicarla habría dejado dos criterios de «token válido» que pueden divergir
/// — y el día que divergen, una ruta protegida y la puerta de entrada dejan de
/// estar de acuerdo sobre quién puede pasar.
pub fn validar_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    // Las comillas se recortan porque algunos clientes guardan el valor de la
    // cookie entre comillas y el token deja de decodificarse por un carácter.
    let token = token.trim().trim_matches('"');

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 30;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
}

pub struct AuthMiddleware {
    pub mode: AuthMode,
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareInner<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareInner {
            service: Rc::new(service),
            mode: self.mode,
        })
    }
}

pub struct AuthMiddlewareInner<S> {
    service: Rc<S>,
    mode: AuthMode,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareInner<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let mode = self.mode;

        Box::pin(async move {
            let path = req.uri().path();

            //  1) Preflight CORS SIEMPRE permitido
            if req.method() == Method::OPTIONS {
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            //  2) Rutas públicas (sin JWT)
            if path.starts_with("/auth")
                || path.starts_with("/swagger-ui")
                || path.starts_with("/api-docs")
            {
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            // 🔐 3) A partir de aquí, JWT normal
            let token = req.cookie("token").map(|c| c.value().to_string());

            let Some(token) = token else {
                if matches!(mode, AuthMode::Required) {
                    let res = req.into_response(
                        HttpResponse::Unauthorized().body("No token cookie"),
                    );
                    return Ok(res.map_into_right_body());
                }
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            };

            match validar_token(&token) {
                Ok(claims) => {
                    req.extensions_mut().insert(claims.sub);
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                }
                Err(err) => {
                    log::error!("JWT ERROR REAL: {:?}", err);

                    if matches!(mode, AuthMode::Required) {
                        let res = req.into_response(
                            HttpResponse::Unauthorized()
                                .body("Invalid or expired token"),
                        );
                        Ok(res.map_into_right_body())
                    } else {
                        let res = service.call(req).await?;
                        Ok(res.map_into_left_body())
                    }
                }
            }
        })
    }
}