use indicatif::ProgressStyle;

pub static BLAKE3_CONTEXT_ENCRYPTION: &str = "fcrypt v1.1 [encryption key]";
pub static BLAKE3_CONTEXT_HMAC: &str = "fcrypt v1.1 [hmac key]";

// LLVM please inline this because I have no idea
// how to do this with macros...
// #define is dirty but simple, and would solve this problem
// in a fraction of the cost
pub const GLOBAL_PROGRESS_STYLE: fn() -> anyhow::Result<ProgressStyle> = || {
    Ok(ProgressStyle::with_template("{msg} [{bar:30}] ({bytes}/{total_bytes}) [{bytes_per_sec}]")?.progress_chars("=> "))
};
pub const BUFFER_SIZE: usize = 1024 * 1024;