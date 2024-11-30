use argon2::Algorithm::Argon2id;
use argon2::Version::{V0x10, V0x13};
use argon2::{Argon2, Params};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};

// exceeding https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
const ARGON2ID_ITERATIONS: u32 = 2;
const ARGON2ID_MEMORY_COST: u32 = 65536;
const ARGON2ID_PARALLELISM: u32 = 1;

pub fn hash_password(
    password: &SecretString,
    salt: Option<[u8; 32]>,
) -> (SecretBox<[u8; 32]>, [u8; 32]) {
    let salt = salt.unwrap_or_else(|| {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt
    });

    let mut hash: SecretBox<[u8; 32]> = SecretBox::default();

    let argon2 = Argon2::new(
        Argon2id,
        V0x13,
        Params::new(
            ARGON2ID_MEMORY_COST,
            ARGON2ID_ITERATIONS,
            ARGON2ID_PARALLELISM,
            Some(32),
        )
        .unwrap(),
    );

    argon2
        .hash_password_into(
            password.expose_secret().as_bytes(),
            salt.as_slice(),
            hash.expose_secret_mut(),
        )
        .unwrap();

    (hash, salt)
}
