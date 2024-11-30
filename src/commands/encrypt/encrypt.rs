use std::path::PathBuf;
use clap::Args;

#[derive(Args)]
pub struct EncryptArgs {
    /// File to encrypt
    file: PathBuf,

    /// Output file
    output: PathBuf,
}

pub fn encrypt_command(args: &EncryptArgs) -> anyhow::Result<()> {
    println!("not implemented");
    Ok(())
}