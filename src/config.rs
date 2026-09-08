//! Configuración desde el entorno.
//!
//! Antes vivía repartida: los orígenes CORS y la dirección de escucha estaban
//! escritos en `main.rs`, y el `secure` de las cookies en tres sitios de
//! `handler_auth.rs`. Eso es lo que impedía sacar el servicio de la máquina de
//! desarrollo: cambiar de entorno obligaba a editar código y recompilar.

use std::env;

/// Direcciones en las que escucha el servidor, separadas por comas.
///
/// **Por defecto los dos loopbacks, `127.0.0.1:8081` y `[::1]:8081`, y ninguna
/// interfaz de red.** Antes escuchaba en `0.0.0.0`, así que cualquiera en la misma
/// red alcanzaba el servicio en cuanto arrancaba — y el mensaje de arranque decía
/// `127.0.0.1`, con lo que ni mirando la consola se notaba.
///
/// Son **dos** y no una porque en Windows `localhost` resuelve primero a `::1` y
/// después a `127.0.0.1`: escuchando solo en IPv4, un navegador que pida
/// `http://localhost:8081` se encuentra la puerta cerrada sin más explicación que
/// «no se pudo conectar». Cubrir los dos loopbacks no expone nada hacia fuera.
///
/// El 8081 y no el 8080 porque el visor de infraestructura usa el 8080.
/// Publicarlo hacia la red es una decisión explícita: `BIND_ADDR=0.0.0.0:8081`.
pub fn bind_addrs() -> Vec<String> {
    env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8081,[::1]:8081".to_string())
        .split(',')
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect()
}

/// Orígenes que se aceptan en CORS, separados por comas.
///
/// Antes eran cuatro literales en el código, dos de ellos IPs de una red
/// doméstica concreta (`192.168.100.5`, `192.168.56.1`). Un origen de CORS es
/// dato de despliegue, no del programa.
pub fn cors_origins() -> Vec<String> {
    env::var("CORS_ORIGINS")
        // El defecto son los dos frontends de `web/` **por sus dos nombres**: la
        // pantalla de sesión y el cliente de pruebas, en `localhost` y en
        // `127.0.0.1`.
        //
        // Los cuatro y no dos porque para el navegador `http://localhost:5173` y
        // `http://127.0.0.1:5173` son **orígenes distintos**: abrir la página por
        // el nombre que no está en la lista da un fallo de CORS que se parece
        // exactamente a que el servidor esté caído.
        //
        // Están en puertos distintos a propósito, para que el CORS con credenciales
        // se ejercite en desarrollo y no en el despliegue.
        .unwrap_or_else(|_| {
            "http://localhost:5173,http://localhost:5174,\
             http://127.0.0.1:5173,http://127.0.0.1:5174"
                .to_string()
        })
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

/// Las dos claves, y por qué son dos.
///
/// El **token de acceso** es un JWT firmado con `JWT_ACCESS_SECRET`. El **refresh
/// no es un JWT**: son 64 bytes aleatorios que viven en `auth.refresh_tokens`, y lo
/// que se guarda de ellos es un resumen. Ese resumen se calcula ahora con HMAC y
/// `REFRESH_TOKEN_PEPPER`, no con un SHA-256 pelado.
///
/// Así cada clave protege una mitad y **filtrar una no compromete la otra**: con la
/// de acceso se pueden forjar accesos de diez minutos, pero no convertirlos en una
/// sesión duradera, porque un refresh además tiene que existir como fila; y con la
/// del refresh no se firma ningún acceso.
///
/// El pimiento del refresh es defensa en profundidad, no la barrera principal: la
/// barrera es que el token tiene 512 bits de entropía. Lo que añade es que un
/// volcado de la tabla, por sí solo, ya no permite ni siquiera comprobar si un
/// token concreto estuvo ahí.
///
/// ## Por qué no hay valor por defecto para ninguna
///
/// Una clave de reserva es una clave conocida: quien tenga el código firma sus
/// propios tokens y entra como quien quiera. Es preferible no arrancar.
///
/// Se cachean en un `OnceLock` porque se usan en cada petición y `env::var` reserva
/// memoria en cada llamada.
static ACCESO: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
static PIMIENTO_REFRESH: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

/// El mínimo en bytes. HS256 y HMAC-SHA256 usan una clave de 256 bits, así que
/// menos de 32 bytes es una clave más corta que el hash que produce.
const MINIMO: usize = 32;

/// Comprueba que las dos claves están y sirven. **Se llama al arrancar.**
///
/// Devuelve el motivo en vez de abortar para que quien la llame decida: al
/// integrarse en otro binario, quién y cómo se para es cosa suya.
///
/// Se comprueban **las dos** aunque falle la primera... no: se corta en la primera,
/// y a propósito. Un arranque que enumera todo lo que falta suena útil y en la
/// práctica invita a rellenarlas a medias; una cada vez deja el mensaje corto y sin
/// ambigüedad sobre qué toca ahora.
pub fn comprobar_secretos() -> Result<(), String> {
    let acceso = leer_secreto("JWT_ACCESS_SECRET")?;
    let pimiento = leer_secreto("REFRESH_TOKEN_PEPPER")?;

    // Que sean la misma cadena anula el motivo de tenerlas separadas, y es un error
    // fácil de cometer copiando el `.env` de al lado.
    if acceso == pimiento {
        return Err(
            "JWT_ACCESS_SECRET y REFRESH_TOKEN_PEPPER son iguales: separarlas es todo el \
             sentido de que sean dos"
                .to_string(),
        );
    }

    let _ = ACCESO.set(acceso);
    let _ = PIMIENTO_REFRESH.set(pimiento);
    Ok(())
}

fn leer_secreto(nombre: &str) -> Result<Vec<u8>, String> {
    let bruto = env::var(nombre)
        .map_err(|_| format!("falta {nombre}: sin ella no se pueden emitir sesiones"))?;

    let bruto = bruto.trim();
    if bruto.len() < MINIMO {
        return Err(format!(
            "{nombre} tiene {} bytes y hacen falta {MINIMO} como mínimo (openssl rand -base64 48)",
            bruto.len()
        ));
    }

    Ok(bruto.as_bytes().to_vec())
}

/// La clave que firma y verifica el token de acceso, ya comprobada.
///
/// El `expect` solo puede saltar si alguien atiende peticiones sin haber llamado a
/// [`crate::preparar`], que es un error de programación y no de despliegue.
pub fn jwt_access_secret() -> &'static [u8] {
    ACCESO
        .get()
        .expect("jwt_access_secret() antes de preparar(): la clave no se ha comprobado")
}

/// La clave con la que se resume el token de refresco, ya comprobada.
pub fn refresh_pepper() -> &'static [u8] {
    PIMIENTO_REFRESH
        .get()
        .expect("refresh_pepper() antes de preparar(): la clave no se ha comprobado")
}
