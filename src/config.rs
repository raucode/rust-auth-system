//! Configuración desde el entorno.
//!
//! Antes vivía repartida: los orígenes CORS y la dirección de escucha estaban
//! escritos en `main.rs`, y el `secure` de las cookies en tres sitios de
//! `handler_auth.rs`. Eso es lo que impedía sacar el servicio de la máquina de
//! desarrollo: cambiar de entorno obligaba a editar código y recompilar.

use std::env;

/// Dirección en la que escucha el servidor.
///
/// **Por defecto `127.0.0.1:8080`, no `0.0.0.0:8080`.** Antes escuchaba en todas
/// las interfaces, así que cualquiera en la misma red alcanzaba el servicio en
/// cuanto arrancaba — y el mensaje de arranque decía `127.0.0.1`, con lo que ni
/// mirando la consola se notaba.
///
/// Publicarlo hacia fuera es ahora una decisión explícita: `BIND_ADDR=0.0.0.0:8080`.
pub fn bind_addr() -> String {
    env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string())
}

/// Orígenes que se aceptan en CORS, separados por comas.
///
/// Antes eran cuatro literales en el código, dos de ellos IPs de una red
/// doméstica concreta (`192.168.100.5`, `192.168.56.1`). Un origen de CORS es
/// dato de despliegue, no del programa.
pub fn cors_origins() -> Vec<String> {
    env::var("CORS_ORIGINS")
        // El defecto son los dos frontends de `web/`: la pantalla de sesión y el
        // cliente de pruebas. Están en puertos distintos a propósito, para que el
        // CORS con credenciales se ejercite en desarrollo y no en el despliegue.
        .unwrap_or_else(|_| "http://127.0.0.1:5173,http://127.0.0.1:5174".to_string())
        .split(',')
        .map(|o| o.trim().to_string())
        .filter(|o| !o.is_empty())
        .collect()
}

/// Si las cookies de sesión llevan el atributo `Secure`.
///
/// **Por defecto `true`**, y la decisión de qué defecto poner aquí no es de
/// estilo: sin `Secure` la cookie viaja también por HTTP en claro, así que un
/// olvido en producción expone las sesiones, mientras que un olvido en
/// desarrollo solo provoca que el login no funcione — y eso se nota en diez
/// segundos.
///
/// Para trabajar en local sin HTTPS: `COOKIE_SECURE=false`.
pub fn cookie_secure() -> bool {
    bandera("COOKIE_SECURE", true)
}

/// Si las cookies de sesión llevan el atributo `HttpOnly`.
///
/// **Por defecto `true`.** `HttpOnly` es lo que impide que el JavaScript de la
/// página lea la cookie, y con ella la sesión: sin él, cualquier script que se
/// cuele —un XSS, una dependencia comprometida— puede llevarse la sesión de quien
/// esté conectado, y no hay forma de detectarlo desde el servidor.
///
/// Se hace configurable porque a veces se necesita durante el desarrollo, pero
/// conviene saber que **no hace falta para saber si hay sesión**: eso lo resuelve
/// `GET /auth/verify`, que es como lo hacen los dos frontends de `web/` y como lo
/// hará el proxy inverso.
///
/// Para desactivarlo: `COOKIE_HTTPONLY=false`.
pub fn cookie_httponly() -> bool {
    bandera("COOKIE_HTTPONLY", true)
}

/// Lee una bandera del entorno. Todo lo que no sea una negación explícita cuenta
/// como verdadero, para que un `COOKIE_SECURE=si` no desactive nada por sorpresa.
fn bandera(nombre: &str, por_defecto: bool) -> bool {
    match env::var(nombre) {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no"),
        Err(_) => por_defecto,
    }
}

/// Credenciales del administrador inicial, si se han configurado.
///
/// Existe para resolver el problema del primer usuario: sin nadie dado de alta no
/// se puede entrar, y sin entrar no se puede dar de alta a nadie. Ver
/// `crate::bootstrap`.
pub fn admin_inicial() -> Option<(String, String)> {
    let email = env::var("ADMIN_EMAIL").ok()?;
    let password = env::var("ADMIN_PASSWORD").ok()?;
    if email.trim().is_empty() || password.trim().is_empty() {
        return None;
    }
    Some((email.trim().to_string(), password))
}
