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
        .unwrap_or_else(|_| "http://localhost:5173".to_string())
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
    env::var("COOKIE_SECURE")
        .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no"))
        .unwrap_or(true)
}
