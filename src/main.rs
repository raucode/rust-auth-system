    //---------------------------------------------
    //---------------Mods imports------------------
    //---------------------------------------------
    //  Name                //     Descript
    mod auth;               // Autentificacion
    mod bootstrap;          // Administrador inicial
    mod config;             // Configuracion del entorno
    mod users;              // Usuarios
    mod rbac;               // Roles y permisos
    mod servicios;          // Aplicaciones que confian en este auth
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
    use rbac::routes_rbac::rbac_routes;
    use crate::middleware::AuthMiddleware;

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

        // La matriz rol → permisos, compartida por todo el proceso y cargada antes
        // de atender a nadie: así la primera petición no paga la espera, y un
        // problema de conexión se ve en el arranque en vez de disfrazado más tarde
        // de «este usuario no tiene permisos».
        let matriz = web::Data::new(rbac::matriz::Matriz::nueva());
        matriz.precargar(&pool).await;

        let direcciones = config::bind_addrs();
        let origenes = config::cors_origins();

        // El mensaje dice las direcciones reales. Antes decía 127.0.0.1 mientras
        // escuchaba en 0.0.0.0, así que la consola tranquilizaba en falso.
        println!("🚀 Auth escuchando en: {}", direcciones.join(", "));
        println!("   CORS permitido para: {}", origenes.join(", "));
        if !config::cookie_secure() {
            println!("   AVISO: COOKIE_SECURE=false — las cookies van sin Secure (solo desarrollo)");
        }
        if !config::cookie_httponly() {
            println!("   AVISO: COOKIE_HTTPONLY=false — el JavaScript de la página puede leer la sesión");
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

            // Scope para rutas protegidas que requieren autenticación.
            //
            // El middleware de este scope solo exige sesión. Los permisos se
            // exigen **más adentro**, en cada sub-scope, porque no todas las
            // rutas de `/api` piden lo mismo: `/api/me/permisos` la usa cualquiera
            // con sesión, y `/api/rbac` solo quien administra permisos.
            let protected_scope = web::scope("/api")
                .wrap(AuthMiddleware::sesion())

                .route("/profile", web::get().to(users::handler_users::get_user_profile))
                .service(
                    web::scope("/me")
                        .route("", web::post().to(users::handler_users::register_employer))
                        .route("/summary", web::get().to(users::handler_users::get_employees_summary))
                        .route("/permisos", web::get().to(rbac::handler_rbac::mis_permisos))
                )
                .route("/servicios", web::get().to(servicios::mis_servicios))
                .configure(rbac_routes);
            App::new()
                // 1. Aplicamos el middleware de CORS PRIMERO, para que afecte a todas las rutas.
                .wrap(Logger::default())
                .wrap(cors)
                .app_data(web::Data::new(pool.clone()))
                // La misma matriz para todos los trabajadores: `Data` clona el
                // puntero, no el contenido, así que no hay una copia por hilo que
                // caduque por su cuenta.
                .app_data(matriz.clone())
                
                // Rutas públicas (sin middleware de autenticación)
                .service(
                    web::scope("/auth")
                        .configure(user_routes)
                        // La consulta que hace un proxy inverso antes de servir
                        // una ruta protegida. Va aquí, entre las públicas, porque
                        // valida por su cuenta y su trabajo incluye poder
                        // responder 401.
                        .route("/verify", web::get().to(auth::handler_auth::verify))
                        // Público como el login, y por el mismo motivo: lo
                        // consulta la pantalla de sesión de alguien que todavía
                        // no ha entrado. Solo responde sí o no.
                        .route("/destino", web::get().to(servicios::comprobar_destino))
                )

                // Registrar el scope de rutas protegidas
                .service(protected_scope)

        });

        // Se escucha en todas las direcciones configuradas, no en una: los dos
        // loopbacks hacen falta para que `localhost` funcione resuelva a IPv4 o a
        // IPv6, y en Windows resuelve primero a IPv6.
        for direccion in &direcciones {
            servidor = servidor.bind(direccion)?;
        }

        servidor.run().await
    }