    //---------------------------------------------
    //---------------Mods imports------------------
    //---------------------------------------------
    //  Name                //     Descript
    mod auth;               // Autentificacion
    mod bootstrap;          // Administrador inicial
    mod config;             // Configuracion del entorno
    mod users;              // Usuarios
    mod db;                 // DataBase
    mod middleware;         // Middleware
    mod crates;             // Imports Globales

    //---------------------------------------------
    //----------------Use imports------------------
    //---------------------------------------------
    //   Import::name                                        //      Descript
    use actix_web::{App, HttpServer, http, web::{self/* , patch, service*/}};             //Webs Protocols
    use actix_cors::Cors;                                    //Cors impors
    use dotenv::dotenv;                                      //
    use env_logger::Env; 
    use users::routes_users::user_routes;
    use crate::middleware::AuthMiddleware;
    use crate::middleware::AuthMode;                //Middleware

use actix_web::middleware::Logger;
    //---------------------------------------------
    //-----------------Main Logic------------------
    //---------------------------------------------

    #[actix_web::main]
    async fn main() -> std::io::Result<()> {
        dotenv().ok();
        env_logger::init_from_env(Env::default().default_filter_or("info"));

        let pool = db::connect()
            .await
            .expect("Failed to create database pool.");

        // El administrador inicial, antes de escuchar: si hace falta crearlo, mejor
        // que esté antes de que llegue la primera petición de login.
        bootstrap::crear_admin_si_falta(&pool).await;

        let bind_addr = config::bind_addr();
        let origenes = config::cors_origins();

        // El mensaje dice la dirección real. Antes decía 127.0.0.1 mientras
        // escuchaba en 0.0.0.0, así que la consola tranquilizaba en falso.
        println!("🚀 Auth escuchando en http://{bind_addr}");
        println!("   CORS permitido para: {}", origenes.join(", "));
        if !config::cookie_secure() {
            println!("   AVISO: COOKIE_SECURE=false — las cookies van sin Secure (solo desarrollo)");
        }

        HttpServer::new(move || {
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
                .expose_headers(vec!["X-Auth-User"])
                .max_age(3600);

            // Scope para rutas protegidas que requieren autenticación.
            let protected_scope = web::scope("/api")
                .wrap(AuthMiddleware { mode: AuthMode::Required })
                
                .route("/profile", web::get().to(users::handler_users::get_user_profile))
                .service(
                    web::scope("/me")
                        .route("", web::post().to(users::handler_users::register_employer))
                        .route("/summary", web::get().to(users::handler_users::get_employees_summary))
                );
            App::new()
                // 1. Aplicamos el middleware de CORS PRIMERO, para que afecte a todas las rutas.
                .wrap(Logger::default())
                .wrap(cors) 
                .app_data(web::Data::new(pool.clone()))
                
                // Rutas públicas (sin middleware de autenticación)
                .service(
                    web::scope("/auth")
                        .configure(user_routes)
                        // La consulta que hace un proxy inverso antes de servir
                        // una ruta protegida. Va aquí, entre las públicas, porque
                        // valida por su cuenta y su trabajo incluye poder
                        // responder 401.
                        .route("/verify", web::get().to(auth::handler_auth::verify))
                )

                // Registrar el scope de rutas protegidas
                .service(protected_scope)

        })
        .bind(&bind_addr)?
        .run()
        .await
    }