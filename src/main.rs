    //---------------------------------------------
    //---------------Mods imports------------------
    //---------------------------------------------
    //  Name                //     Descript
    mod auth;               // Autentificacion
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

        println!("🚀 Server started successfully at http://127.0.0.1:8080");

        HttpServer::new(move || {
            // --- CONFIGURACIÓN DE CORS ---
            // Se define aquí para ser aplicada a toda la aplicación.
            let cors = Cors::default()
                .allowed_origin("http://localhost:5173")
                .allowed_origin("http://192.168.100.5:5173")
                .allowed_origin("http://192.168.100.5:8080")
                .allowed_origin("http://192.168.56.1:5173") // La URL de tu frontend
                .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH"])
                .allowed_headers(vec![
                http::header::CONTENT_TYPE,
                http::header::AUTHORIZATION,
                http::header::ACCEPT,
            ])
                .supports_credentials() // MUY IMPORTANTE para el login con cookies
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

                )
                
                // Registrar el scope de rutas protegidas
                .service(protected_scope)

        })
        .bind("0.0.0.0:8080")?
        .run()
        .await
    }