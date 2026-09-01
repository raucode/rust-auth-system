//! El auth como **servicio suelto**, para quien no puede importarlo.
//!
//! Todo lo que hace este binario está en la librería de este mismo crate: aquí
//! solo se monta un servidor alrededor. Un servicio en Rust no necesita esto —se
//! trae `core_suite` dentro y se ahorra el salto de red—; esto es para lo que no
//! es Rust y tiene que preguntar por HTTP desde un proxy inverso.
//!
//! Ver la documentación de la librería en `src/lib.rs`.

use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, http, web};
use dotenv::dotenv;
use env_logger::Env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let pool = core_suite::db::connect()
        .await
        .expect("Failed to create database pool.");

    // El administrador inicial y la matriz de permisos, antes de escuchar. Los dos
    // pasos viven en la librería porque un consumidor que la integre necesita
    // exactamente lo mismo, y repetirlo aquí sería tener dos arranques que se
    // separan el día que uno cambie.
    let matriz = core_suite::preparar(&pool).await;

    let direcciones = core_suite::config::bind_addrs();
    let origenes = core_suite::config::cors_origins();

    // El mensaje dice las direcciones reales. Antes decía 127.0.0.1 mientras
    // escuchaba en 0.0.0.0, así que la consola tranquilizaba en falso.
    println!("🚀 Auth escuchando en: {}", direcciones.join(", "));
    println!("   CORS permitido para: {}", origenes.join(", "));
    if !core_suite::config::cookie_secure() {
        println!("   AVISO: COOKIE_SECURE=false — las cookies van sin Secure (solo desarrollo)");
    }
    if !core_suite::config::cookie_httponly() {
        println!(
            "   AVISO: COOKIE_HTTPONLY=false — el JavaScript de la página puede leer la sesión"
        );
    }

    let mut servidor = HttpServer::new(move || {
        // --- CORS ---
        // Los orígenes vienen del entorno: son dato de despliegue, no del
        // programa. Antes estaban escritos aquí, y dos eran IPs de una red
        // doméstica concreta.
        let mut cors = Cors::default();
        for origen in &origenes {
            cors = cors.allowed_origin(origen);
        }
        let cors = cors
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH"])
            .allowed_headers(vec![
                http::header::CONTENT_TYPE,
                http::header::AUTHORIZATION,
                http::header::ACCEPT,
            ])
            .supports_credentials() // MUY IMPORTANTE para el login con cookies
            // Sin exponerla, el navegador recibe el 200 de `/auth/verify` pero
            // no puede leer quién es: CORS oculta por defecto toda cabecera de
            // respuesta que no sea de una lista corta. Un proxy inverso no lo
            // sufre —lee la respuesta directa, sin CORS de por medio— así que
            // esto es solo para que un cliente de navegador pueda usarla.
            .expose_headers(vec!["X-Auth-User", "X-Auth-Roles", "X-Auth-Perms"])
            .max_age(3600);

        App::new()
            // El middleware de CORS primero, para que afecte a todas las rutas.
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            // La misma matriz para todos los trabajadores: `Data` clona el
            // puntero, no el contenido, así que no hay una copia por hilo que
            // caduque por su cuenta.
            .app_data(matriz.clone())
            // Las rutas viven en la librería. Este binario no las declara: si lo
            // hiciera, el servicio suelto y el integrado podrían dejar de exponer
            // lo mismo sin que nadie se entere.
            .configure(core_suite::rutas_sesion)
            .configure(core_suite::rutas_administracion)
    });

    // Se escucha en todas las direcciones configuradas, no en una: los dos
    // loopbacks hacen falta para que `localhost` resuelva a IPv4 o a IPv6, y en
    // Windows resuelve primero a IPv6.
    for direccion in &direcciones {
        servidor = servidor.bind(direccion)?;
    }

    servidor.run().await
}
