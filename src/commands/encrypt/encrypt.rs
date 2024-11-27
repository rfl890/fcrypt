use crate::util::pwdhash::hash_password;
use crate::util::shared::{BLAKE3_CONTEXT_ENCRYPTION, BLAKE3_CONTEXT_HMAC, BUFFER_SIZE, GLOBAL_PROGRESS_STYLE};
use aes::cipher::{KeyIvInit, StreamCipher};
use blake3::Hasher;
use clap::Args;
use rpassword::prompt_password;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use indicatif::{ProgressBar, ProgressStyle};

type Aes256Ctr128LE = ctr::Ctr128LE<aes::Aes256>;

#[derive(Args)]
pub struct EncryptArgs {
    /// File to encrypt
    file: PathBuf,

    /// Output file
    output: PathBuf,
}

pub fn encrypt_command(args: &EncryptArgs) -> anyhow::Result<()> {
    // Set up buffers
    let mut input_buffer = SecretBox::new(vec![0u8; BUFFER_SIZE].into_boxed_slice());
    let mut output_buffer = SecretBox::new(vec![0u8; BUFFER_SIZE].into_boxed_slice());

    let input_filename = &args.file;
    let output_filename = &args.output;

    // Open files
    let mut input_file = if input_filename.display().to_string() == "-" {
        unsafe { File::from_raw_fd(0) }
    } else {
        File::open(input_filename)?
    };
    let mut output_file = if output_filename.display().to_string() == "-" {
        unsafe { File::from_raw_fd(1) }
    } else {
        File::create(output_filename)?
    };

    let input_file_size = input_file.metadata()?.len() as usize;

    // Derive keys
    let password = SecretString::from(prompt_password("Password: ")?);
    let (key, salt) = hash_password(&password, None);

    let encryption_key: SecretBox<[u8; 32]> =
        SecretBox::init_with(|| blake3::derive_key(BLAKE3_CONTEXT_ENCRYPTION, key.expose_secret()));
    let hmac_key: SecretBox<[u8; 32]> =
        SecretBox::init_with(|| blake3::derive_key(BLAKE3_CONTEXT_HMAC, key.expose_secret()));

    let iv = [0u8; 16];

    // Set up encryption and hashing
    let bar = ProgressBar::new(input_file_size as u64);
    bar.set_style(GLOBAL_PROGRESS_STYLE()?);
    bar.set_message("Encrypting file...");

    let mut mac = Hasher::new_keyed(hmac_key.expose_secret());
    let mut cipher = Aes256Ctr128LE::new(encryption_key.expose_secret().into(), &iv.into());

    loop {
        let bytes_read = input_file.read(input_buffer.expose_secret_mut())?;
        if bytes_read == 0 {
            break;
        };
        let input_bytes = &input_buffer.expose_secret()[..bytes_read];
        let output_bytes = &mut output_buffer.expose_secret_mut()[..bytes_read];

        cipher.apply_keystream_b2b(input_bytes, output_bytes)?;
        mac.update(output_bytes);
        output_file.write_all(output_bytes)?;
        bar.inc(bytes_read as u64);
    }
    let mac = mac.finalize();

    output_file.write_all(&salt)?;
    output_file.write_all(mac.as_bytes())?;

    bar.finish();

    Ok(())
}
