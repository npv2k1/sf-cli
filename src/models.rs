//! Data models for the secure file encryption tool

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Operation type for file processing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationType {
    /// Encrypt files/folders
    Encrypt,
    /// Decrypt files/folders
    Decrypt,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypt => write!(f, "Encrypt"),
            Self::Decrypt => write!(f, "Decrypt"),
        }
    }
}

/// Target type for operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetType {
    /// Single file
    File,
    /// Directory/folder
    Directory,
}

impl std::fmt::Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "File"),
            Self::Directory => write!(f, "Directory"),
        }
    }
}

/// Operation parameters
#[derive(Debug, Clone)]
pub struct OperationParams {
    /// Type of operation (encrypt/decrypt)
    pub operation: OperationType,
    /// Target type (file/directory)
    pub target_type: TargetType,
    /// Source path
    pub source: PathBuf,
    /// Destination path (optional, defaults based on operation)
    pub destination: Option<PathBuf>,
    /// Whether to enable compression
    pub compress: bool,
    /// Whether to show progress
    pub show_progress: bool,
    /// Buffer size for file operations
    pub buffer_size: usize,
    /// Whether to preserve original filename (new feature)
    pub preserve_filename: bool,
    /// Whether to delete source file after operation
    pub delete_source: bool,
    /// Whether to verify checksum after decryption
    pub verify_checksum: bool,
}

impl OperationParams {
    /// Create new operation parameters
    pub fn new(
        operation: OperationType,
        target_type: TargetType,
        source: PathBuf,
    ) -> Self {
        Self {
            operation,
            target_type,
            source,
            destination: None,
            compress: false,
            show_progress: true,
            buffer_size: 64 * 1024, // 64KB
            preserve_filename: true, // Default to preserving filenames
            delete_source: false,    // Default to keeping source files
            verify_checksum: true,   // Default to verifying checksums
        }
    }

    /// Set destination path
    pub fn with_destination(mut self, destination: PathBuf) -> Self {
        self.destination = Some(destination);
        self
    }

    /// Enable compression
    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Set progress visibility
    pub fn with_progress(mut self, show_progress: bool) -> Self {
        self.show_progress = show_progress;
        self
    }

    /// Set buffer size
    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = buffer_size;
        self
    }

    /// Set filename preservation
    pub fn with_preserve_filename(mut self, preserve_filename: bool) -> Self {
        self.preserve_filename = preserve_filename;
        self
    }

    /// Set source deletion after operation
    pub fn with_delete_source(mut self, delete_source: bool) -> Self {
        self.delete_source = delete_source;
        self
    }

    /// Set checksum verification
    pub fn with_verify_checksum(mut self, verify_checksum: bool) -> Self {
        self.verify_checksum = verify_checksum;
        self
    }

    /// Get the default destination path based on source and operation
    pub fn get_destination(&self) -> PathBuf {
        if let Some(dest) = &self.destination {
            dest.clone()
        } else {
            match self.operation {
                OperationType::Encrypt => {
                    if self.preserve_filename {
                        // Keep original filename, just add .sf extension
                        let original_ext = self.source.extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string();
                        
                        if self.compress {
                            if original_ext.is_empty() {
                                self.source.with_extension("sf")
                            } else {
                                self.source.with_extension(format!("{}.sf", original_ext))
                            }
                        } else {
                            if original_ext.is_empty() {
                                self.source.with_extension("sf")
                            } else {
                                self.source.with_extension(format!("{}.sf", original_ext))
                            }
                        }
                    } else {
                        // Legacy behavior
                        if self.compress {
                            self.source.with_extension("sf.gz")
                        } else {
                            self.source.with_extension("sf")
                        }
                    }
                }
                OperationType::Decrypt => {
                    if self.preserve_filename {
                        // Will be determined from metadata during decryption
                        // For now, just remove .sf or .sf.gz extension
                        let source_str = self.source.to_string_lossy();
                        if source_str.ends_with(".sf.gz") {
                            PathBuf::from(source_str.trim_end_matches(".sf.gz"))
                        } else if source_str.ends_with(".sf") {
                            PathBuf::from(source_str.trim_end_matches(".sf"))
                        } else {
                            self.source.with_extension("decrypted")
                        }
                    } else {
                        // Legacy behavior
                        let source_str = self.source.to_string_lossy();
                        if source_str.ends_with(".sf.gz") {
                            PathBuf::from(source_str.trim_end_matches(".sf.gz"))
                        } else if source_str.ends_with(".sf") {
                            PathBuf::from(source_str.trim_end_matches(".sf"))
                        } else {
                            self.source.with_extension("decrypted")
                        }
                    }
                }
            }
        }
    }
}

/// Result of a file operation
#[derive(Debug, Clone)]
pub struct OperationResult {
    /// Whether the operation was successful
    pub success: bool,
    /// Source path that was processed
    pub source: PathBuf,
    /// Destination path where result was saved
    pub destination: PathBuf,
    /// Number of bytes processed
    pub bytes_processed: u64,
    /// Error message if operation failed
    pub error: Option<String>,
    /// Operation type that was performed
    pub operation: OperationType,
    /// Whether compression was used
    pub compressed: bool,
    /// Original filename (for decryption operations)
    pub original_filename: Option<String>,
    /// Whether checksum verification passed (for decryption)
    pub checksum_verified: Option<bool>,
}

impl OperationResult {
    /// Create a successful operation result
    pub fn success(
        source: PathBuf,
        destination: PathBuf,
        bytes_processed: u64,
        operation: OperationType,
        compressed: bool,
    ) -> Self {
        Self {
            success: true,
            source,
            destination,
            bytes_processed,
            error: None,
            operation,
            compressed,
            original_filename: None,
            checksum_verified: None,
        }
    }

    /// Create a successful operation result with metadata
    pub fn success_with_metadata(
        source: PathBuf,
        destination: PathBuf,
        bytes_processed: u64,
        operation: OperationType,
        compressed: bool,
        original_filename: Option<String>,
        checksum_verified: Option<bool>,
    ) -> Self {
        Self {
            success: true,
            source,
            destination,
            bytes_processed,
            error: None,
            operation,
            compressed,
            original_filename,
            checksum_verified,
        }
    }

    /// Create a failed operation result
    pub fn failure(
        source: PathBuf,
        operation: OperationType,
        error: String,
    ) -> Self {
        Self {
            success: false,
            source,
            destination: PathBuf::new(),
            bytes_processed: 0,
            error: Some(error),
            operation,
            compressed: false,
            original_filename: None,
            checksum_verified: None,
        }
    }
}

impl std::fmt::Display for OperationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.success {
            let mut result = format!(
                "✓ {} {} -> {} ({} bytes{})",
                self.operation,
                self.source.display(),
                self.destination.display(),
                self.bytes_processed,
                if self.compressed { ", compressed" } else { "" }
            );

            if let Some(filename) = &self.original_filename {
                result.push_str(&format!(", original: {}", filename));
            }

            if let Some(verified) = self.checksum_verified {
                result.push_str(&format!(", checksum: {}", if verified { "✓" } else { "✗" }));
            }

            write!(f, "{}", result)
        } else {
            write!(
                f,
                "✗ {} {} failed: {}",
                self.operation,
                self.source.display(),
                self.error.as_ref().unwrap_or(&"Unknown error".to_string())
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_params() {
        let params = OperationParams::new(
            OperationType::Encrypt,
            TargetType::File,
            PathBuf::from("test.txt"),
        );

        assert_eq!(params.operation, OperationType::Encrypt);
        assert_eq!(params.target_type, TargetType::File);
        assert_eq!(params.source, PathBuf::from("test.txt"));
        assert!(!params.compress);
        assert!(params.show_progress);
    }

    #[test]
    fn test_destination_generation() {
        // Test encryption destination with filename preservation (new default behavior)
        let params = OperationParams::new(
            OperationType::Encrypt,
            TargetType::File,
            PathBuf::from("test.txt"),
        );
        assert_eq!(params.get_destination(), PathBuf::from("test.txt.sf"));

        // Test encryption with compression and filename preservation
        let params = params.with_compression(true);
        assert_eq!(params.get_destination(), PathBuf::from("test.txt.sf"));

        // Test legacy behavior (no filename preservation)
        let params = params.with_preserve_filename(false);
        assert_eq!(params.get_destination(), PathBuf::from("test.sf.gz"));

        // Test decryption
        let params = OperationParams::new(
            OperationType::Decrypt,
            TargetType::File,
            PathBuf::from("test.txt.sf"),
        );
        assert_eq!(params.get_destination(), PathBuf::from("test.txt"));

        // Test legacy decryption
        let params = OperationParams::new(
            OperationType::Decrypt,
            TargetType::File,
            PathBuf::from("test.sf.gz"),
        );
        assert_eq!(params.get_destination(), PathBuf::from("test"));
    }

    #[test]
    fn test_operation_result() {
        let success = OperationResult::success(
            PathBuf::from("source.txt"),
            PathBuf::from("dest.sf"),
            1024,
            OperationType::Encrypt,
            false,
        );

        assert!(success.success);
        assert_eq!(success.bytes_processed, 1024);
        assert!(success.error.is_none());

        let failure = OperationResult::failure(
            PathBuf::from("source.txt"),
            OperationType::Encrypt,
            "Test error".to_string(),
        );

        assert!(!failure.success);
        assert_eq!(failure.bytes_processed, 0);
        assert_eq!(failure.error.as_ref().unwrap(), "Test error");
    }
}