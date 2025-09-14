//! File and folder operations for encryption/decryption

use crate::{
    compression::{CompressionEngine, CompressionError},
    crypto::{CryptoEngine, CryptoError, FileMetadata},
    hybrid_crypto::{HybridCryptoEngine, HybridCryptoError},
    models::{OperationParams, OperationResult, OperationType, TargetType},
    progress::ProgressTracker,
};
use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::Path,
};
use thiserror::Error;

/// File operation errors
#[derive(Error, Debug)]
pub enum FileOperationError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Hybrid crypto error: {0}")]
    HybridCryptoError(#[from] HybridCryptoError),
    #[error("Compression error: {0}")]
    CompressionError(#[from] CompressionError),
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    #[error("Path does not exist: {0}")]
    PathNotFound(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

/// File operations engine
pub struct FileOperator {
    crypto: CryptoEngine,
    hybrid_crypto: HybridCryptoEngine,
    compression: CompressionEngine,
}

impl Default for FileOperator {
    fn default() -> Self {
        Self::new()
    }
}

impl FileOperator {
    /// Create a new file operator
    pub fn new() -> Self {
        Self {
            crypto: CryptoEngine::new(),
            hybrid_crypto: HybridCryptoEngine::new(),
            compression: CompressionEngine::new(),
        }
    }

    /// Process a file or directory based on operation parameters
    pub async fn process(&self, params: &OperationParams, password: &str) -> OperationResult {
        let source = &params.source;

        // Validate source path
        if !source.exists() {
            return OperationResult::failure(
                source.clone(),
                params.operation.clone(),
                format!("Source path does not exist: {}", source.display()),
            );
        }

        match params.target_type {
            TargetType::File => self.process_file(params, password).await,
            TargetType::Directory => self.process_directory(params, password).await,
        }
    }

    /// Process a single file
    async fn process_file(&self, params: &OperationParams, password: &str) -> OperationResult {
        let source = &params.source;
        let destination = params.get_destination();

        // Ensure destination directory exists
        if let Some(parent) = destination.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                return OperationResult::failure(
                    source.clone(),
                    params.operation.clone(),
                    format!("Failed to create destination directory: {}", e),
                );
            }
        }

        let result = match params.operation {
            OperationType::Encrypt => {
                match self
                    .encrypt_file(source, &destination, password, params)
                    .await
                {
                    Ok(bytes_processed) => OperationResult::success(
                        source.clone(),
                        destination,
                        bytes_processed,
                        params.operation.clone(),
                        params.compress,
                    ),
                    Err(e) => OperationResult::failure(
                        source.clone(),
                        params.operation.clone(),
                        e.to_string(),
                    ),
                }
            }
            OperationType::Decrypt => {
                match self
                    .decrypt_file(source, &destination, password, params)
                    .await
                {
                    Ok((bytes_processed, metadata, checksum_verified)) => {
                        OperationResult::success_with_metadata(
                            source.clone(),
                            destination,
                            bytes_processed,
                            params.operation.clone(),
                            metadata.compressed,
                            Some(metadata.filename),
                            Some(checksum_verified),
                        )
                    }
                    Err(e) => OperationResult::failure(
                        source.clone(),
                        params.operation.clone(),
                        e.to_string(),
                    ),
                }
            }
            OperationType::HybridEncrypt => {
                match self.hybrid_encrypt_file(source, &destination, params).await {
                    Ok(bytes_processed) => OperationResult::success(
                        source.clone(),
                        destination,
                        bytes_processed,
                        params.operation.clone(),
                        params.compress,
                    ),
                    Err(e) => OperationResult::failure(
                        source.clone(),
                        params.operation.clone(),
                        e.to_string(),
                    ),
                }
            }
            OperationType::HybridDecrypt => {
                match self.hybrid_decrypt_file(source, &destination, params).await {
                    Ok((bytes_processed, metadata)) => OperationResult::success_with_metadata(
                        source.clone(),
                        destination,
                        bytes_processed,
                        params.operation.clone(),
                        metadata.compressed,
                        Some(metadata.filename),
                        Some(true), // Assume checksum is verified for hybrid decryption
                    ),
                    Err(e) => OperationResult::failure(
                        source.clone(),
                        params.operation.clone(),
                        e.to_string(),
                    ),
                }
            }
        };

        result
    }

    /// Process a directory (compress to tar.gz then encrypt/decrypt)
    async fn process_directory(&self, params: &OperationParams, password: &str) -> OperationResult {
        let source = &params.source;
        let destination = params.get_destination();

        match params.operation {
            OperationType::Encrypt => {
                // For directories, we always compress (tar.gz) before encrypting
                match self
                    .encrypt_directory(source, &destination, password, params)
                    .await
                {
                    Ok(bytes_processed) => OperationResult::success(
                        source.clone(),
                        destination,
                        bytes_processed,
                        params.operation.clone(),
                        true, // Always compressed for directories
                    ),
                    Err(e) => OperationResult::failure(
                        source.clone(),
                        params.operation.clone(),
                        e.to_string(),
                    ),
                }
            }
            OperationType::Decrypt => {
                match self
                    .decrypt_directory(&source, &destination, password, params)
                    .await
                {
                    Ok(bytes_processed) => OperationResult::success(
                        source.clone(),
                        destination,
                        bytes_processed,
                        params.operation.clone(),
                        true, // Always compressed for directories
                    ),
                    Err(e) => OperationResult::failure(
                        source.clone(),
                        params.operation.clone(),
                        e.to_string(),
                    ),
                }
            }
            OperationType::HybridEncrypt => {
                // Hybrid directory encryption
                println!("📁 Hybrid Directory Encryption");
                println!("==============================");
                println!("🔑 This will compress the directory and encrypt with hybrid encryption");

                OperationResult::failure(
                    source.clone(),
                    params.operation.clone(),
                    "Hybrid directory encryption implementation pending".to_string(),
                )
            }
            OperationType::HybridDecrypt => {
                // Hybrid directory decryption
                println!("📁 Hybrid Directory Decryption");
                println!("==============================");

                OperationResult::failure(
                    source.clone(),
                    params.operation.clone(),
                    "Hybrid directory decryption implementation pending".to_string(),
                )
            }
        }
    }

    /// Encrypt a single file
    async fn encrypt_file(
        &self,
        source: &Path,
        destination: &Path,
        password: &str,
        params: &OperationParams,
    ) -> Result<u64, FileOperationError> {
        let file_size = fs::metadata(source)?.len();
        let progress = if params.show_progress {
            Some(ProgressTracker::new(file_size, "Encrypting"))
        } else {
            None
        };

        let mut input = BufReader::new(File::open(source)?);
        let mut file_data = Vec::new();

        // Read entire file
        input.read_to_end(&mut file_data)?;

        // Apply compression if requested
        let data_to_encrypt = if params.compress {
            progress.as_ref().map(|p| p.set_message("Compressing..."));
            self.compression.compress(&file_data)?
        } else {
            file_data.clone()
        };

        // Create metadata
        let metadata = FileMetadata::from_file(source, &file_data, params.compress);

        // Encrypt the data
        progress.as_ref().map(|p| p.set_message("Encrypting..."));
        let encrypted_data = self.crypto.encrypt(&data_to_encrypt, password, metadata)?;

        // Write to destination
        let mut output = BufWriter::new(File::create(destination)?);
        output.write_all(&encrypted_data)?;
        output.flush()?;

        if let Some(progress) = &progress {
            progress.inc(file_size);
            progress.finish("Encryption complete");
        }

        // Delete source file if requested
        if params.delete_source {
            fs::remove_file(source)?;
        }

        Ok(encrypted_data.len() as u64)
    }

    /// Encrypt a single file using hybrid encryption
    async fn hybrid_encrypt_file(
        &self,
        source: &Path,
        destination: &Path,
        params: &OperationParams,
    ) -> Result<u64, FileOperationError> {
        // Display helpful message about SSH keys and show discovered keys
        println!("🔑 Hybrid Encryption Mode");
        println!("=========================");

        let file_size = fs::metadata(source)?.len();
        let progress = if params.show_progress {
            Some(ProgressTracker::new(file_size, "Hybrid Encrypting"))
        } else {
            None
        };

        let mut input = BufReader::new(File::open(source)?);
        let mut file_data = Vec::new();

        // Read entire file
        input.read_to_end(&mut file_data)?;

        // Apply compression if requested
        let data_to_encrypt = if params.compress {
            progress.as_ref().map(|p| p.set_message("Compressing..."));
            self.compression.compress(&file_data)?
        } else {
            file_data.clone()
        };

        // Create metadata
        let metadata = FileMetadata::from_file(source, &file_data, params.compress);

        // Encrypt the data using hybrid encryption
        progress
            .as_ref()
            .map(|p| p.set_message("Hybrid encrypting..."));
        let encrypted_data = self.hybrid_crypto.encrypt(
            &data_to_encrypt,
            params.public_key_path.as_deref(),
            metadata,
        )?;

        // Create destination with .hsf extension
        let final_destination = if destination.extension().is_none() {
            destination.with_extension("hsf")
        } else {
            destination.to_path_buf()
        };

        // Write to destination
        let mut output = BufWriter::new(File::create(&final_destination)?);
        output.write_all(&encrypted_data)?;
        output.flush()?;

        if let Some(progress) = &progress {
            progress.inc(file_size);
            progress.finish("Hybrid encryption complete");
        }

        // Show success message
        println!("✅ Successfully encrypted file using hybrid encryption");
        println!("📁 Output: {}", final_destination.display());

        // Delete source file if requested
        if params.delete_source {
            fs::remove_file(source)?;
        }

        Ok(encrypted_data.len() as u64)
    }

    /// Decrypt a hybrid encrypted file
    async fn hybrid_decrypt_file(
        &self,
        source: &Path,
        destination: &Path,
        params: &OperationParams,
    ) -> Result<(u64, FileMetadata), FileOperationError> {
        // Display helpful message about hybrid decryption
        println!("🔓 Hybrid Decryption Mode");
        println!("=========================");

        let file_size = fs::metadata(source)?.len();
        let progress = if params.show_progress {
            Some(ProgressTracker::new(file_size, "Hybrid Decrypting"))
        } else {
            None
        };

        // Read the encrypted file
        let mut input = BufReader::new(File::open(source)?);
        let mut encrypted_data = Vec::new();
        input.read_to_end(&mut encrypted_data)?;

        // Decrypt the data using hybrid decryption
        progress
            .as_ref()
            .map(|p| p.set_message("Hybrid decrypting..."));
        let (decrypted_data, metadata) = self
            .hybrid_crypto
            .decrypt(&encrypted_data, params.private_key_path.as_deref())?;

        // Apply decompression if the data was compressed
        let final_data = if metadata.compressed {
            progress.as_ref().map(|p| p.set_message("Decompressing..."));
            self.compression.decompress(&decrypted_data)?
        } else {
            decrypted_data
        };

        // Create destination (remove .hsf extension if present)
        let final_destination = if source.extension() == Some(std::ffi::OsStr::new("hsf")) {
            destination.with_file_name(source.file_stem().unwrap_or(source.as_os_str()))
        } else {
            destination.to_path_buf()
        };

        // Write to destination
        let mut output = BufWriter::new(File::create(&final_destination)?);
        output.write_all(&final_data)?;
        output.flush()?;

        if let Some(progress) = &progress {
            progress.inc(file_size);
            progress.finish("Hybrid decryption complete");
        }

        // Show success message
        println!("✅ Successfully decrypted file using hybrid decryption");
        println!("📁 Output: {}", final_destination.display());

        // Delete source file if requested
        if params.delete_source {
            fs::remove_file(source)?;
        }

        Ok((final_data.len() as u64, metadata))
    }

    /// Decrypt a single file
    async fn decrypt_file(
        &self,
        source: &Path,
        destination: &Path,
        password: &str,
        params: &OperationParams,
    ) -> Result<(u64, FileMetadata, bool), FileOperationError> {
        let file_size = fs::metadata(source)?.len();
        let progress = if params.show_progress {
            Some(ProgressTracker::new(file_size, "Decrypting"))
        } else {
            None
        };

        let mut input = BufReader::new(File::open(source)?);
        let mut encrypted_data = Vec::new();

        // Read the encrypted file
        input.read_to_end(&mut encrypted_data)?;

        if let Some(progress) = &progress {
            progress.inc(file_size);
            progress.set_message("Decrypting...");
        }

        // Try new format first, fall back to legacy if needed
        let (decrypted_data, metadata) = match self.crypto.decrypt(&encrypted_data, password) {
            Ok((data, meta)) => (data, Some(meta)),
            Err(_) => {
                // Try legacy format
                let data = self.crypto.decrypt_legacy(&encrypted_data, password)?;
                (data, None)
            }
        };

        // Decompress if needed
        let final_data = if let Some(ref meta) = metadata {
            if meta.compressed {
                if let Some(progress) = &progress {
                    progress.set_message("Decompressing...");
                }
                self.compression.decompress(&decrypted_data)?
            } else {
                decrypted_data
            }
        } else if params.compress {
            // Legacy: try decompression based on params
            if let Some(progress) = &progress {
                progress.set_message("Decompressing...");
            }
            match self.compression.decompress(&decrypted_data) {
                Ok(decompressed) => decompressed,
                Err(_) => decrypted_data, // Not compressed, use as-is
            }
        } else {
            decrypted_data
        };

        // Write the final data
        let mut output = BufWriter::new(File::create(destination)?);
        output.write_all(&final_data)?;
        output.flush()?;

        if let Some(progress) = &progress {
            progress.finish("Decryption complete");
        }

        // Delete source file if requested
        if params.delete_source {
            fs::remove_file(source)?;
        }

        // Verify checksum if metadata is available and verification is enabled
        let checksum_verified = if let Some(ref meta) = metadata {
            if params.verify_checksum {
                meta.verify_checksum(&final_data)
            } else {
                true // Skip verification if disabled
            }
        } else {
            true // Legacy format, no checksum available
        };

        let result_metadata = metadata.unwrap_or_else(|| {
            // Create placeholder metadata for legacy files
            FileMetadata::new("unknown".to_string(), [0u8; 32], params.compress)
        });

        Ok((final_data.len() as u64, result_metadata, checksum_verified))
    }

    /// Encrypt a directory (tar.gz then encrypt)
    async fn encrypt_directory(
        &self,
        source: &Path,
        destination: &Path,
        password: &str,
        params: &OperationParams,
    ) -> Result<u64, FileOperationError> {
        let progress = if params.show_progress {
            Some(ProgressTracker::new_spinner("Encrypting directory"))
        } else {
            None
        };

        // Create a tar.gz archive of the directory in memory
        progress
            .as_ref()
            .map(|p| p.set_message("Creating archive..."));
        let archive_data = self.create_directory_archive(source)?;

        // Create metadata for directory
        let metadata = FileMetadata::from_file(source, &archive_data, true); // Always compressed for directories

        // Encrypt the archive
        progress
            .as_ref()
            .map(|p| p.set_message("Encrypting archive..."));
        let encrypted_data = self.crypto.encrypt(&archive_data, password, metadata)?;

        // Write encrypted data to destination
        let mut output = BufWriter::new(File::create(destination)?);
        output.write_all(&encrypted_data)?;
        output.flush()?;

        if let Some(progress) = &progress {
            progress.finish("Directory encryption complete");
        }

        Ok(encrypted_data.len() as u64)
    }

    /// Decrypt a directory (decrypt then extract tar.gz)
    async fn decrypt_directory(
        &self,
        source: &Path,
        destination: &Path,
        password: &str,
        params: &OperationParams,
    ) -> Result<u64, FileOperationError> {
        let progress = if params.show_progress {
            Some(ProgressTracker::new_spinner("Decrypting directory"))
        } else {
            None
        };

        // Read and decrypt the file
        progress
            .as_ref()
            .map(|p| p.set_message("Reading encrypted file..."));
        let mut encrypted_data = Vec::new();
        let mut input = BufReader::new(File::open(source)?);
        input.read_to_end(&mut encrypted_data)?;

        progress.as_ref().map(|p| p.set_message("Decrypting..."));
        let (archive_data, _metadata) = match self.crypto.decrypt(&encrypted_data, password) {
            Ok((data, meta)) => (data, Some(meta)),
            Err(_) => {
                // Try legacy format
                let data = self.crypto.decrypt_legacy(&encrypted_data, password)?;
                (data, None)
            }
        };

        // Extract the archive
        progress
            .as_ref()
            .map(|p| p.set_message("Extracting archive..."));
        self.extract_directory_archive(&archive_data, destination)?;

        if let Some(progress) = &progress {
            progress.finish("Directory decryption complete");
        }

        Ok(archive_data.len() as u64)
    }

    /// Create a tar.gz archive of a directory
    fn create_directory_archive(&self, source: &Path) -> Result<Vec<u8>, FileOperationError> {
        use flate2::write::GzEncoder;

        let archive_buffer = Vec::new();
        let encoder = GzEncoder::new(archive_buffer, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);

        // Add the directory to the tar archive
        tar.append_dir_all(".", source)
            .map_err(|e| FileOperationError::IoError(e))?;

        let encoder = tar
            .into_inner()
            .map_err(|e| FileOperationError::IoError(e))?;

        let archive_data = encoder
            .finish()
            .map_err(|e| FileOperationError::IoError(e))?;

        Ok(archive_data)
    }

    /// Extract a tar.gz archive to a directory
    fn extract_directory_archive(
        &self,
        archive_data: &[u8],
        destination: &Path,
    ) -> Result<(), FileOperationError> {
        use flate2::read::GzDecoder;

        // Create destination directory
        fs::create_dir_all(destination)?;

        let decoder = GzDecoder::new(archive_data);
        let mut archive = tar::Archive::new(decoder);

        archive
            .unpack(destination)
            .map_err(|e| FileOperationError::IoError(e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_encryption_decryption() {
        let temp_dir = TempDir::new().unwrap();
        let source_file = temp_dir.path().join("test.txt");
        let encrypted_file = temp_dir.path().join("test.sf");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");

        // Create test file
        fs::write(&source_file, b"Hello, World! This is a test file.").unwrap();

        let operator = FileOperator::new();
        let password = "test_password_123";

        // Encrypt
        let encrypt_params = OperationParams::new(
            OperationType::Encrypt,
            TargetType::File,
            source_file.clone(),
        )
        .with_destination(encrypted_file.clone())
        .with_progress(false);

        let result = operator.process(&encrypt_params, password).await;
        assert!(result.success, "Encryption failed: {:?}", result.error);
        assert!(encrypted_file.exists());

        // Decrypt
        let decrypt_params =
            OperationParams::new(OperationType::Decrypt, TargetType::File, encrypted_file)
                .with_destination(decrypted_file.clone())
                .with_progress(false);

        let result = operator.process(&decrypt_params, password).await;
        assert!(result.success, "Decryption failed: {:?}", result.error);
        assert!(decrypted_file.exists());

        // Verify content
        let original_content = fs::read(&source_file).unwrap();
        let decrypted_content = fs::read(&decrypted_file).unwrap();
        assert_eq!(original_content, decrypted_content);
    }

    #[tokio::test]
    async fn test_file_encryption_with_compression() {
        let temp_dir = TempDir::new().unwrap();
        let source_file = temp_dir.path().join("test.txt");
        let encrypted_file = temp_dir.path().join("test.sf.gz");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");

        // Create test file with repetitive content (compresses well)
        let content = "Hello, World! ".repeat(1000);
        fs::write(&source_file, content.as_bytes()).unwrap();

        let operator = FileOperator::new();
        let password = "test_password_123";

        // Encrypt with compression
        let encrypt_params = OperationParams::new(
            OperationType::Encrypt,
            TargetType::File,
            source_file.clone(),
        )
        .with_destination(encrypted_file.clone())
        .with_compression(true)
        .with_progress(false);

        let result = operator.process(&encrypt_params, password).await;
        assert!(result.success);
        assert!(encrypted_file.exists());

        // Decrypt with compression
        let decrypt_params =
            OperationParams::new(OperationType::Decrypt, TargetType::File, encrypted_file)
                .with_destination(decrypted_file.clone())
                .with_compression(true)
                .with_progress(false);

        let result = operator.process(&decrypt_params, password).await;
        assert!(result.success);
        assert!(decrypted_file.exists());

        // Verify content
        let original_content = fs::read(&source_file).unwrap();
        let decrypted_content = fs::read(&decrypted_file).unwrap();
        assert_eq!(original_content, decrypted_content);
    }

    #[tokio::test]
    async fn test_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let source_file = temp_dir.path().join("test.txt");
        let encrypted_file = temp_dir.path().join("test.sf");

        fs::write(&source_file, b"Secret content").unwrap();

        let operator = FileOperator::new();

        // Encrypt with one password
        let encrypt_params =
            OperationParams::new(OperationType::Encrypt, TargetType::File, source_file)
                .with_destination(encrypted_file.clone())
                .with_progress(false);

        let result = operator.process(&encrypt_params, "correct_password").await;
        assert!(result.success);

        // Try to decrypt with wrong password
        let decrypt_params =
            OperationParams::new(OperationType::Decrypt, TargetType::File, encrypted_file)
                .with_progress(false);

        let result = operator.process(&decrypt_params, "wrong_password").await;
        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
