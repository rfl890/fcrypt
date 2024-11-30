use std::path::PathBuf;
use clap::Args;
use crate::v0_compat::decrypt::decrypt::decrypt_v0;

#[derive(Args)]
pub struct DecryptArgs {
    /// Decrypt a file in V0 (legacy) format
    #[arg(long)]
    pub(crate) v0_compat: bool,

    /// File to decrypt
    pub(crate) file: PathBuf,

    /// Output file
    pub(crate) output: PathBuf,
}

pub fn decrypt(args: &DecryptArgs) -> anyhow::Result<()> {
    println!("not implemented");
    Ok(())
}

pub fn decrypt_command(args: &DecryptArgs) -> anyhow::Result<()> {
    match args.v0_compat {
        true => decrypt_v0(args),
        false => decrypt(args),
    }
}