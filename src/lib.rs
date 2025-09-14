//! SF-CLI - Secure File Encryption CLI/TUI Tool
//!
//! A secure file encryption tool with password protection, supporting both
//! command-line and terminal user interface modes.

pub mod compression;
pub mod crypto;
pub mod file_ops;
pub mod hybrid_crypto;
pub mod models;
pub mod progress;
pub mod ssh_keys;
pub mod tui;
pub mod watch;

pub use models::*;

/// Application result type
pub type Result<T> = anyhow::Result<T>;

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Enable compression along with encryption
    pub compress: bool,
    /// Show progress for operations
    pub show_progress: bool,
    /// Buffer size for file operations (in bytes)
    pub buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            compress: false,
            show_progress: true,
            buffer_size: 64 * 1024, // 64KB buffer
        }
    }
}
