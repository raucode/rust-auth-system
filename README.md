# Rust Auth System

Sistema de usuarios con RBAC para servicios en Rust, **como librería**: se importa
y se monta dentro del propio binario del servicio.

- Usuarios, registro e inicio de sesión.
- **RBAC**: roles y permisos resueltos con una matriz en memoria que se recarga
  sola cada treinta segundos.
- **JWT en cookie HTTP-only**, con refresh token persistido y revocable.
- Middleware para rutas protegidas: exigir sesión, o sesión más un permiso.
- PostgreSQL con SQLx, contraseñas con bcrypt.

## Por qué es una librería y no un servicio

Todo servicio interno acaba necesitando lo mismo —quién eres, si tu sesión sigue
viva y qué te deja hacer tu rol—, y escribirlo cada vez es escribir tres veces el
mismo JWT, el mismo refresh y la misma tabla de permisos, equivocándose en sitios
distintos. Esto se escribe una vez y se importa.

```toml
rust_auth_system = { git = "https://github.com/raucode/rust-auth-system" }
```

```rust
// En el arranque del servicio, sobre un pool que ya tienes
rust_auth_system::MIGRACIONES.run(&pool).await?;
let matriz = rust_auth_system::preparar(&pool).await;

HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(pool.clone()))
        .app_data(matriz.clone())
        .configure(rust_auth_system::rutas_sesion)         // públicas: login, refresh…
        .configure(rust_auth_system::rutas_administracion) // protegidas: perfil, RBAC…
})
```

Un servicio que hace eso **no necesita ningún proxy delante para autenticar**, ni
sabe qué es un JWT: pide la identidad y la recibe resuelta.

> Es actix-web. Un servicio en otro framework no puede montar estas rutas.

## Lo que expone

| Elemento | Para qué |
|---|---|
| `MIGRACIONES` | Las migraciones del esquema `auth`, embebidas. `MIGRACIONES.run(&pool)` |
| `preparar(&pool)` | Crea el administrador inicial si falta y precarga la matriz de permisos |
| `rutas_sesion` | Monta `/auth` — login, registro, refresh, logout, `verify`, `destino` |
| `rutas_administracion` | Monta `/api` tras sesión — perfil, empleados, permisos, RBAC |
| `middleware::AuthMiddleware` | Exigir sesión, o sesión más un permiso concreto |
| `rbac::matriz::Matriz` | La matriz rol → permisos compartida por el proceso |

Un consumidor que ya tenga su propio `/api` puede montar solo `rutas_sesion`.
**Si lo monta, que sea después de sus propias rutas**: actix casa por orden de
registro, y un `/api` puesto antes se traga un `/api/v1` entero.

Los permisos van **ya resueltos** y no solo el rol: mandar el rol obligaría a cada
servicio a saber qué concede `user`, y entonces la política estaría repetida en
todos ellos — que es justo lo que un RBAC centralizado existe para evitar.

## Lo que no está aquí

**Integrar esto con plataformas que no son Rust es trabajo del SSO**, que es otro
proyecto y nace de este. Allí vive el servicio suelto que responde
`GET /auth/verify` a un proxy inverso —`auth_request` en nginx, `forwardAuth` en
Traefik— con su web y sus frontends.

Aquí no hay binario a propósito: un componente que además se levanta solo acaba
siendo dos cosas y ninguna del todo.

## La base de datos

Las migraciones crean y usan el esquema **`auth`**, así que conviven con las
tablas de quien las importe sin colisionar por nombre. Dos cosas que hay que
saber si el consumidor tiene sus propias migraciones sobre la misma base:

- **El registro de migraciones sí colisiona.** `sqlx` 0.8 lo escribe siempre en
  `_sqlx_migrations` y **no deja renombrarla** desde el `Migrator` —solo expone
  `set_ignore_missing` y `set_locking`—. Hay que aplicar estas con una conexión
  cuyo `search_path` sea `auth`, para que su registro viva en
  `auth._sqlx_migrations`.
- **Y entonces los tipos también viven ahí.** `user_type_enum` pasa a ser
  `auth.user_type_enum`, y este crate lo declara sin cualificar. El consumidor
  necesita `search_path=public,auth` en su pool, con `public` primero: es quien
  decide dónde nace una tabla que no diga esquema.

## Compilar sin base de datos delante

Las macros de `sqlx` verifican las consultas contra una base **en tiempo de
compilación**. Con la base apagada, `cargo build` falla con
`error communicating with database` aunque el código esté perfecto:

```bash
SQLX_OFFLINE=true cargo check
```

Si cambias o añades una consulta, hay que regenerar la caché de `.sqlx/` con la
base levantada (`cargo sqlx prepare`), o el siguiente compilado sin base fallará
por la consulta nueva.

## Configuración

```env
DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:5432/rust_auth_system
JWT_SECRET=replace-with-a-long-random-secret
ADMIN_EMAIL=...        # opcional: crea el administrador inicial al arrancar
ADMIN_PASSWORD=...
COOKIE_SECURE=true     # false solo en desarrollo
COOKIE_HTTPONLY=true
```

Nunca subas `.env` ni credenciales.

## Estado

**En curso: terminar el RBAC.** La web beta viene después, y no aquí.

Este código nació dentro de `gardenia-restaurantes` y por eso el paquete se
llamaba `core_suite`. Desde septiembre de 2026 es `rust_auth_system` y vive en su propio
repositorio; su primer consumidor es el visor de infraestructura.
