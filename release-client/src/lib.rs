pub mod depot;
pub mod repository;
pub mod state;
#[cfg(feature = "workload")]
pub mod workload;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
