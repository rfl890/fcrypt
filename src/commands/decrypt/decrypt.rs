use crate::util::pwdhash::hash_password;
use crate::util::shared::{BLAKE3_CONTEXT_ENCRYPTION, BLAKE3_CONTEXT_HMAC, BUFFER_SIZE};
use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::anyhow;
use blake3::{Hash, Hasher};
use clap::Args;
use rpassword::prompt_password;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

type Aes256Ctr128LE = ctr::Ctr128LE<aes::Aes256>;

#[derive(Args)]
pub struct DecryptArgs {
    /// File to decrypt
    file: PathBuf,

    /// Output file
    output: PathBuf,
}

pub fn decrypt_command(args: &DecryptArgs) -> anyhow::Result<()> {
    // Set up buffers
    let mut input_buffer = SecretBox::new(vec![0u8; BUFFER_SIZE].into_boxed_slice());
    let mut output_buffer = SecretBox::new(vec![0u8; BUFFER_SIZE].into_boxed_slice());

    // Open files
    let mut input_file = File::open(&args.file)?;
    let mut output_file = File::create(&args.output)?;

    let input_file_size = input_file.metadata()?.len() as usize;

    // Extract MAC and salt
    input_file.seek(SeekFrom::End(-64))?;
    let mut salt = [0u8; 32];
    let mut read_mac = [0u8; 32];

    input_file.read(&mut salt)?;
    input_file.read(&mut read_mac)?;

    let read_mac = Hash::from_bytes(read_mac);

    input_file.rewind()?;

    // Derive keys
    let password = SecretString::from(prompt_password("Password: ")?);
    let (key, _) = hash_password(&password, Some(salt));

    let encryption_key: SecretBox<[u8; 32]> =
        SecretBox::init_with(|| blake3::derive_key(BLAKE3_CONTEXT_ENCRYPTION, key.expose_secret()));
    let hmac_key: SecretBox<[u8; 32]> =
        SecretBox::init_with(|| blake3::derive_key(BLAKE3_CONTEXT_HMAC, key.expose_secret()));

    let iv = [0u8; 16];

    // Set up encryption and hashing
    let mut mac = Hasher::new_keyed(hmac_key.expose_secret());
    let mut cipher = Aes256Ctr128LE::new(encryption_key.expose_secret().into(), &iv.into());

    let mut total_bytes_read = 0;
    loop {
        let bytes_read = input_file.read(input_buffer.expose_secret_mut())?;
        total_bytes_read += bytes_read;

        let input_bytes = &input_buffer.expose_secret()[..bytes_read];

        if total_bytes_read == input_file_size {
            let input_bytes = &input_buffer.expose_secret()[..bytes_read - 64];
            mac.update(input_bytes);
            break;
        }

        mac.update(input_bytes);
    }
    let mac = mac.finalize();

    if mac != read_mac {
        Err(anyhow!("MAC mismatch. This could indicate that the file has been tampered with, or that you used the wrong password."))?;
    }

    input_file.rewind()?;

    total_bytes_read = 0;
    loop {
        let bytes_read = input_file.read(input_buffer.expose_secret_mut())?;
        total_bytes_read += bytes_read;

        let input_bytes = &input_buffer.expose_secret()[..bytes_read];
        let output_bytes = &mut output_buffer.expose_secret_mut()[..bytes_read];

        if total_bytes_read == input_file_size {
            let input_bytes = &input_buffer.expose_secret()[..bytes_read - 64];
            let output_bytes = &mut output_buffer.expose_secret_mut()[..bytes_read - 64];
            cipher.apply_keystream_b2b(input_bytes, output_bytes)?;
            output_file.write_all(output_bytes)?;
            break;
        }

        cipher.apply_keystream_b2b(input_bytes, output_bytes)?;
        output_file.write_all(output_bytes)?;
    }

    Ok(())
}
