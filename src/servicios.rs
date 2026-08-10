//! Los servicios que confían en este sistema de identidad.
//!
//! Dos consumidores, y hacen preguntas distintas a propósito:
//!
//! * **La pantalla de login**, sin sesión todavía, pregunta *«¿puedo devolver a
//!   esta URL?»*. Responde sí o no, y **no devuelve la lista**: enumerar los
//!   servicios internos de una empresa es justo el trabajo previo de quien quiere
//!   atacarla.
//! * **El portal**, ya con sesión, pide la lista de lo que esa persona puede
//!   abrir. Esa sí, porque ya sabemos quién pregunta.

use crate::crates::*;
use crate::middleware::Identidad;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Servicio {
    pub slug: String,
    pub nombre: String,
    pub descripcion: Option<String>,
    pub origen: String,
    pub ruta_inicio: String,
    pub permiso: Option<String>,
}

impl Servicio {
    /// La URL completa a la que se entra.
    pub fn url(&self) -> String {
        format!("{}{}", self.origen, self.ruta_inicio)
    }
}

/// Extrae el origen de una URL: `http://host:puerto`, sin ruta.
///
/// A mano y sin dependencia nueva, porque solo hace falta esto y el formato es
/// fijo. Lo importante es que **se compara el origen entero**, nunca un prefijo:
/// `http://localhost:8000.sitio-falso.com` empieza igual que el bueno y es otro
/// dominio.
fn origen_de(url: &str) -> Option<String> {
    let (esquema, resto) = url.split_once("://")?;
    if esquema != "http" && esquema != "https" {
        return None;
    }
    // El host acaba en la primera `/`, `?` o `#`. Si no hay ninguna, es todo.
    let fin = resto.find(['/', '?', '#']).unwrap_or(resto.len());
    let host = &resto[..fin];
    if host.is_empty() {
        return None;
    }
    Some(format!("{esquema}://{host}"))
}

/// Los servicios activos, tal cual están en la base.
pub async fn listar(pool: &PgPool) -> Result<Vec<Servicio>, sqlx::Error> {
    sqlx::query_as::<_, Servicio>(
        "SELECT slug, nombre, descripcion, origen, ruta_inicio, permiso
         FROM auth.services WHERE activo ORDER BY nombre",
    )
    .fetch_all(pool)
    .await
}

/// Si ese origen pertenece a un servicio registrado y activo.
pub async fn origen_registrado(pool: &PgPool, origen: &str) -> Result<bool, sqlx::Error> {
    let hay: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM auth.services WHERE origen = $1 AND activo LIMIT 1")
            .bind(origen)
            .fetch_optional(pool)
            .await?;
    Ok(hay.is_some())
}

#[derive(Deserialize)]
pub struct ConsultaDestino {
    pub url: String,
}

/// `GET /auth/destino?url=…` — ¿puede el login devolver a esta URL?
///
/// Público, porque quien pregunta todavía no ha entrado. Responde un booleano y
/// nada más: ni qué servicios hay, ni cuál es cuál.
pub async fn comprobar_destino(
    pool: web::Data<PgPool>,
    consulta: web::Query<ConsultaDestino>,
) -> HttpResponse {
    let Some(origen) = origen_de(&consulta.url) else {
        return HttpResponse::Ok().json(serde_json::json!({ "valido": false }));
    };

    match origen_registrado(pool.get_ref(), &origen).await {
        Ok(valido) => {
            if !valido {
                // Merece log: un destino rechazado es o un servicio sin registrar
                // —y entonces alguien está desconcertado— o un intento de usar el
                // login para llevar gente a otra parte.
                log::warn!("destino de redirect rechazado: {origen}");
            }
            HttpResponse::Ok().json(serde_json::json!({ "valido": valido }))
        }
        Err(e) => {
            log::error!("comprobar_destino: {e}");
            // Ante un fallo de base, **no válido**. Un error no puede acabar
            // abriendo el redirect a cualquier sitio.
            HttpResponse::Ok().json(serde_json::json!({ "valido": false }))
        }
    }
}

/// `GET /api/servicios` — lo que puede abrir quien pregunta.
///
/// Filtra por el permiso declarado de cada servicio. Es para **pintar** el portal:
/// esconder una tarjeta no protege nada, y cada servicio sigue comprobando por su
/// cuenta. Sirve para que nadie se choque contra un 403 evitable.
pub async fn mis_servicios(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let identidad = req.extensions().get::<Identidad>().cloned();
    let Some(identidad) = identidad else {
        return HttpResponse::InternalServerError().json("Sin identidad en la peticion");
    };

    let servicios = match listar(pool.get_ref()).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("mis_servicios: {e}");
            return HttpResponse::InternalServerError().json("Error en la base de datos");
        }
    };

    let lista: Vec<_> = servicios
        .into_iter()
        .map(|s| {
            let permitido = match &s.permiso {
                None => true,
                Some(p) => identidad.permisos.iter().any(|mio| mio == p),
            };
            serde_json::json!({
                "slug": s.slug,
                "nombre": s.nombre,
                "descripcion": s.descripcion,
                "url": s.url(),
                "permiso": s.permiso,
                "permitido": permitido,
            })
        })
        .collect();

    HttpResponse::Ok().json(lista)
}

#[cfg(test)]
mod tests {
    use super::origen_de;

    #[test]
    fn extrae_el_origen_y_descarta_la_ruta() {
        assert_eq!(origen_de("http://localhost:8000/visor/"), Some("http://localhost:8000".into()));
        assert_eq!(origen_de("https://visor.empresa.local"), Some("https://visor.empresa.local".into()));
        assert_eq!(origen_de("http://host:8000/a?b=c#d"), Some("http://host:8000".into()));
    }

    /// La prueba que justifica que esto exista: un dominio que **empieza igual**
    /// que el bueno tiene que salir distinto, porque es de otro.
    #[test]
    fn un_dominio_que_empieza_igual_es_otro_origen() {
        assert_eq!(
            origen_de("http://localhost:8000.sitio-falso.com/robar"),
            Some("http://localhost:8000.sitio-falso.com".into())
        );
    }

    #[test]
    fn rechaza_lo_que_no_es_una_url_http() {
        assert_eq!(origen_de("javascript:alert(1)"), None);
        assert_eq!(origen_de("/solo/una/ruta"), None);
        assert_eq!(origen_de("http://"), None);
        assert_eq!(origen_de(""), None);
    }
}
