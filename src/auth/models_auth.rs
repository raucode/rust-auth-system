use crate::crates::*;

#[derive(Deserialize)]
pub struct CrearSuscripcionRequest {
    pub tipo: String,   //  ahora es ENUM
    pub metodo_pago: String      // sigue siendo String
}

// Representación de la suscripción en Rust
#[derive(sqlx::FromRow, Debug, Serialize, Deserialize)]
pub struct Suscripcion {
    pub id: Uuid,
    pub user_id: Uuid,
    pub activo: bool,
    pub fecha_inicio: DateTime<Utc>,
    pub fecha_fin: Option<DateTime<Utc>>,
    pub metodo_pago: String,
}

