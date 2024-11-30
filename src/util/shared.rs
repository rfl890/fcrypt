use indicatif::ProgressStyle;

pub const GLOBAL_PROGRESS_STYLE: fn() -> anyhow::Result<ProgressStyle> = || {
    Ok(ProgressStyle::with_template("{msg} [{bar:30}] ({bytes}/{total_bytes}) [{bytes_per_sec}]")?.progress_chars("=> "))
};

pub const BUFFER_SIZE: usize = 1024 * 1024;

// Format

// V0
pub static FORMAT_V0_BLAKE3_CONTEXT_ENCRYPTION: &str = "fcrypt v1.1 [encryption key]";
pub static FORMAT_V0_BLAKE3_CONTEXT_HMAC: &str = "fcrypt v1.1 [hmac key]";

// V1