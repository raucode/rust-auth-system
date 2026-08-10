use crate::crates::*;
use chrono::NaiveDateTime;
use bigdecimal::BigDecimal;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_type_enum", rename_all = "lowercase")]
pub enum UserType {
    Owner,
    Employer,
    Admin,
}

// Aquí vivía `StateEnum` con los 27 estados de Brasil, y `User` tenía `state` y
// `phone`. Fuera desde el 2026-08-10: la identidad guarda lo que hace falta para
// saber quién eres y qué puedes hacer, y ni el estado ni el teléfono responden a
// ninguna de las dos preguntas.

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,

    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,

    pub full_name: String,

    pub user_type: UserType,

    pub is_active: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Owner {
    pub user_id: Uuid,

    pub cpf: String,

    pub is_active: bool,
    pub verified: bool,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Employer {
    pub user_id: Uuid,

    pub owner_id: Uuid,
    pub restaurant_id: Uuid,
    pub cpf: Option<String>,
    pub hire_date: Option<NaiveDateTime>,

    pub role_gerarqui: Option<i32>, // ← rol laboral, NO RBAC
    pub salary: Option<BigDecimal>,

    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct EmployerSummary {
    pub full_name: String,
    pub is_active: bool,
    pub role_gerarqui: Option<i32>,
    pub salary: Option<BigDecimal>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Admin {
    pub user_id: Uuid,

    pub access_level: i32,
    pub internal_note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterUserBase {
    pub user_type: UserType,
    pub email: String,
    pub password: String,
    pub full_name: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterOwner {
    pub cpf: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterEmployer {
    pub cpf: Option<String>,
    pub hire_date: Option<NaiveDateTime>,
    pub role: Option<i32>,
    pub salary: Option<BigDecimal>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAdmin {
    pub access_level: i32,
    pub internal_note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub user: User,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub employer: Option<Employer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin: Option<Admin>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterUserPayload {
    pub base: RegisterUserBase,

    pub owner: Option<RegisterOwner>,
    pub employer: Option<RegisterEmployer>,
    pub admin: Option<RegisterAdmin>,
}