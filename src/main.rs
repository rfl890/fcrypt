mod commands;
mod util;
pub mod v0_compat;

use crate::commands::decrypt::decrypt::{decrypt_command, DecryptArgs};
use crate::commands::encrypt::encrypt::{encrypt_command, EncryptArgs};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct FcryptCli {
    #[command(subcommand)]
    command: FcryptCommands,
}

#[derive(Subcommand)]
enum FcryptCommands {
    /// Encrypts a file with a password.
    Encrypt(EncryptArgs),
    /// Decrypts a file with a password.
    Decrypt(DecryptArgs),
}

fn main() {
    let cli = FcryptCli::parse();
    match &cli.command {
        FcryptCommands::Encrypt(encrypt_args) => match encrypt_command(encrypt_args) {
            Ok(_) => {
                println!("Encrypted successfully!");
            }
            Err(err) => {
                println!("Error: {err}");
            }
        },
        FcryptCommands::Decrypt(decrypt_args) => match decrypt_command(decrypt_args) {
            Ok(_) => {
                println!("Decrypted successfully!");
            }
            Err(err) => {
                println!("Error: {err}");
            }
        },
    }
}
