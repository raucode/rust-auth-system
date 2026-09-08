//! Lo que la identidad guarda de una persona.
//!
//! Aquí vivían `UserType`, `Owner`, `Employer`, `Admin` y sus cargas útiles de
//! registro: CPF, fecha de contratación, jerarquía laboral y salario. Fuera desde
//! el 2026-09-08. Eran la ficha de empleado de un SaaS de restaurantes, y en un
//! componente de identidad obligaban a todo consumidor nuevo a declararse dueño,
//! empleado o administrador para poder existir.
//!
//! Antes de eso se fueron `StateEnum` con los 27 estados de Brasil, `state` y
//! `phone` (2026-08-10). La regla que queda es la misma: se guarda lo que hace
//! falta para saber **quién eres** y **qué puedes hacer**. Lo que responda a otra
//! pregunta es de quien la haga.

use crate::crates::*;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,

    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,

    /// Un nombre para mostrar, si lo hay.
    ///
    /// `Option` y no `String` porque exigirlo no aporta nada a la identidad y sí
    /// obliga a inventar relleno: el arranque del administrador inicial escribía
    /// literalmente «Administrador» para poder cumplir un NOT NULL.
    pub full_name: Option<String>,

    pub is_active: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterUserPayload {
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

/// El perfil real, leído de la base.
///
/// `roles` y `permissions` se leen de la base y **no del token**: este endpoint
/// devuelve el estado actual, y un token emitido hace nueve minutos puede no
/// reflejar un cambio reciente.
#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub user: User,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
}
