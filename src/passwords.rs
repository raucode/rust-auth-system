//! Contraseñas: **argon2id**, y bcrypt solo para poder entrar una última vez.
//!
//! ## Por qué se cambió
//!
//! bcrypt tiene dos problemas que no se arreglan subiendo el coste. El primero es
//! que **trunca a 72 bytes**: una frase de paso larga se recorta en silencio y las
//! que compartan los primeros 72 bytes son la misma contraseña. El segundo es que
//! su coste es solo de CPU, así que una GPU o un ASIC lo paralelizan barato.
//!
//! argon2id no trunca y su coste es de **memoria**, que es lo que no se paraleliza
//! bien. `Argon2::default()` son los parámetros recomendados hoy (19 MiB, 2 pasadas,
//! 1 hilo); van en el propio hash, así que subirlos mañana no invalida los de hoy.
//!
//! ## Y por qué bcrypt sigue en el árbol
//!
//! Porque hay hashes viejos. Borrar la verificación obligaría a que todo el mundo
//! restablezca su contraseña, y eso convierte una mejora en una interrupción.
//!
//! [`verificar`] acepta los dos formatos y dice si el que entró **hay que
//! reescribirlo**. Quien la llame graba el hash nuevo. Es la única forma de migrar
//! sin conocer las contraseñas: solo se puede rehashear en el instante en que
//! alguien la escribe bien.

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};

/// El resultado de comprobar una contraseña.
///
/// Un `bool` no bastaba: hay tres respuestas, no dos. La tercera —«correcta, pero
/// el hash es del formato viejo»— es la que permite migrar sola la base.
#[derive(Debug, PartialEq, Eq)]
pub enum Verificacion {
    Incorrecta,
    Correcta,
    /// Correcta, y el hash guardado hay que sustituirlo por el que viene dentro.
    CorrectaYRehecha(String),
}

/// Calcula el hash argon2id de una contraseña nueva.
pub fn cifrar(contrasena: &str) -> Result<String, String> {
    let sal = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(contrasena.as_bytes(), &sal)
        .map(|h| h.to_string())
        .map_err(|e| format!("no se pudo cifrar la contraseña: {e}"))
}

/// Comprueba una contraseña contra el hash guardado, sea del formato que sea.
///
/// **No distingue hacia fuera entre «hash ilegible» e «incorrecta»**: las dos son
/// [`Verificacion::Incorrecta`]. Una fila corrupta no es motivo para contarle a
/// quien intenta entrar nada sobre el estado de la base.
pub fn verificar(contrasena: &str, hash_guardado: &str) -> Verificacion {
    // Los hashes de bcrypt empiezan por `$2a$`, `$2b$` o `$2y$`; los de la familia
    // PHC —argon2 entre ellos— por `$argon2id$`, `$argon2i$`…
    if hash_guardado.starts_with("$2") {
        return match bcrypt::verify(contrasena, hash_guardado) {
            Ok(true) => match cifrar(contrasena) {
                Ok(nuevo) => Verificacion::CorrectaYRehecha(nuevo),
                // La contraseña ERA correcta. Que no se haya podido rehacer el hash
                // no es motivo para no dejar entrar: se deja pasar con el viejo y se
                // reintentará en el siguiente login.
                Err(e) => {
                    log::warn!("no se pudo rehacer un hash de bcrypt: {e}");
                    Verificacion::Correcta
                }
            },
            _ => Verificacion::Incorrecta,
        };
    }

    let Ok(analizado) = PasswordHash::new(hash_guardado) else {
        log::error!("hay un hash de contraseña que no se puede interpretar");
        return Verificacion::Incorrecta;
    };

    match Argon2::default().verify_password(contrasena.as_bytes(), &analizado) {
        Ok(()) => Verificacion::Correcta,
        Err(_) => Verificacion::Incorrecta,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn una_contrasena_correcta_entra_y_una_mala_no() {
        let hash = cifrar("Hola1234").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert_eq!(verificar("Hola1234", &hash), Verificacion::Correcta);
        assert_eq!(verificar("noesesta", &hash), Verificacion::Incorrecta);
    }

    #[test]
    fn dos_hashes_de_la_misma_contrasena_son_distintos() {
        // Si salieran iguales, la sal no estaría haciendo su trabajo y una tabla
        // arcoíris valdría contra toda la base a la vez.
        assert_ne!(cifrar("Hola1234").unwrap(), cifrar("Hola1234").unwrap());
    }

    #[test]
    fn un_hash_de_bcrypt_entra_y_pide_rehacerse() {
        let viejo = bcrypt::hash("Hola1234", 4).unwrap();
        match verificar("Hola1234", &viejo) {
            Verificacion::CorrectaYRehecha(nuevo) => {
                assert!(nuevo.starts_with("$argon2id$"));
                // Y el hash nuevo tiene que servir para el siguiente login.
                assert_eq!(verificar("Hola1234", &nuevo), Verificacion::Correcta);
            }
            otro => panic!("un bcrypt correcto deberia pedir rehacerse, no {otro:?}"),
        }
        assert_eq!(verificar("noesesta", &viejo), Verificacion::Incorrecta);
    }

    #[test]
    fn argon2id_no_trunca_donde_bcrypt_truncaba() {
        // Dos frases que comparten los primeros 72 bytes. Con bcrypt son la misma
        // contraseña; es justo la razón del cambio.
        let larga = "a".repeat(72);
        let uno = format!("{larga}-cuenta-de-raul");
        let dos = format!("{larga}-cuenta-de-otro");
        let hash = cifrar(&uno).unwrap();
        assert_eq!(verificar(&uno, &hash), Verificacion::Correcta);
        assert_eq!(verificar(&dos, &hash), Verificacion::Incorrecta);
    }

    #[test]
    fn un_hash_ilegible_no_deja_entrar_a_nadie() {
        assert_eq!(
            verificar("Hola1234", "esto no es un hash"),
            Verificacion::Incorrecta
        );
        assert_eq!(verificar("", ""), Verificacion::Incorrecta);
    }
}
