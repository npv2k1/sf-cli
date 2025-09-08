//! File and folder operations for encryption/decryption

use crate::{
    compression::{CompressionEngine, CompressionError},
    crypto::{CryptoEngine, CryptoError},
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
                self.encrypt_file(source, &destination, password, params).await
            }
            OperationType::Decrypt => {
                self.decrypt_file(source, &destination, password, params).await
            }
        };

        match result {
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

    /// Process a directory (compress to tar.gz then encrypt/decrypt)
    async fn process_directory(&self, params: &OperationParams, password: &str) -> OperationResult {
        let source = &params.source;
        let destination = params.get_destination();

        match params.operation {
            OperationType::Encrypt => {
                // For directories, we always compress (tar.gz) before encrypting
                match self.encrypt_directory(source, &destination, password, params).await {
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
                match self.decrypt_directory(&source, &destination, password, params).await {
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
        let mut output = BufWriter::new(File::create(destination)?);

        let mut buffer = vec![0u8; params.buffer_size];
        let mut total_bytes = 0u64;
        let mut file_data = Vec::new();

        // Read entire file into memory for small files, or process in chunks for large files
        if file_size <= 1024 * 1024 * 100 { // 100MB threshold
            input.read_to_end(&mut file_data)?;
            
            // Apply compression if requested
            let data_to_encrypt = if params.compress {
                progress.as_ref().map(|p| p.set_message("Compressing..."));
                self.compression.compress(&file_data)?
            } else {
                file_data
            };

            // Encrypt the data
            progress.as_ref().map(|p| p.set_message("Encrypting..."));
            let encrypted_data = self.crypto.encrypt(&data_to_encrypt, password)?;
            
            output.write_all(&encrypted_data)?;
            total_bytes = encrypted_data.len() as u64;
            
            if let Some(progress) = &progress {
                progress.inc(file_size);
            }
        } else {
            // For large files, we need a streaming approach
            // This is a simplified version - in practice, you'd want to implement
            // authenticated encryption with associated data (AEAD) streaming
            loop {
                let bytes_read = input.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                file_data.extend_from_slice(&buffer[..bytes_read]);
                
                if let Some(progress) = &progress {
                    progress.inc(bytes_read as u64);
                }
            }

            // Process the complete file data
            let data_to_encrypt = if params.compress {
                self.compression.compress(&file_data)?
            } else {
                file_data
            };

            let encrypted_data = self.crypto.encrypt(&data_to_encrypt, password)?;
            output.write_all(&encrypted_data)?;
            total_bytes = encrypted_data.len() as u64;
        }

        output.flush()?;
        
        if let Some(progress) = &progress {
            progress.finish("Encryption complete");
        }

        Ok(total_bytes)
    }

    /// Decrypt a single file
    async fn decrypt_file(
        &self,
        source: &Path,
        destination: &Path,
        password: &str,
        params: &OperationParams,
    ) -> Result<u64, FileOperationError> {
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

        // Decrypt the data
        let decrypted_data = self.crypto.decrypt(&encrypted_data, password)?;
        
        // Decompress if the file was compressed (detect by trying decompression)
        let final_data = if params.compress {
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

        Ok(final_data.len() as u64)
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
        progress.as_ref().map(|p| p.set_message("Creating archive..."));
        let archive_data = self.create_directory_archive(source)?;
        
        // Encrypt the archive
        progress.as_ref().map(|p| p.set_message("Encrypting archive..."));
        let encrypted_data = self.crypto.encrypt(&archive_data, password)?;
        
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
        progress.as_ref().map(|p| p.set_message("Reading encrypted file..."));
        let mut encrypted_data = Vec::new();
        let mut input = BufReader::new(File::open(source)?);
        input.read_to_end(&mut encrypted_data)?;

        progress.as_ref().map(|p| p.set_message("Decrypting..."));
        let archive_data = self.crypto.decrypt(&encrypted_data, password)?;

        // Extract the archive
        progress.as_ref().map(|p| p.set_message("Extracting archive..."));
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

        let encoder = tar.into_inner()
            .map_err(|e| FileOperationError::IoError(e))?;
        
        let archive_data = encoder.finish()
            .map_err(|e| FileOperationError::IoError(e))?;

        Ok(archive_data)
    }

    /// Extract a tar.gz archive to a directory
    fn extract_directory_archive(&self, archive_data: &[u8], destination: &Path) -> Result<(), FileOperationError> {
        use flate2::read::GzDecoder;

        // Create destination directory
        fs::create_dir_all(destination)?;

        let decoder = GzDecoder::new(archive_data);
        let mut archive = tar::Archive::new(decoder);
        
        archive.unpack(destination)
            .map_err(|e| FileOperationError::IoError(e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

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
        ).with_destination(encrypted_file.clone())
         .with_progress(false);

        let result = operator.process(&encrypt_params, password).await;
        assert!(result.success, "Encryption failed: {:?}", result.error);
        assert!(encrypted_file.exists());

        // Decrypt
        let decrypt_params = OperationParams::new(
            OperationType::Decrypt,
            TargetType::File,
            encrypted_file,
        ).with_destination(decrypted_file.clone())
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
        ).with_destination(encrypted_file.clone())
         .with_compression(true)
         .with_progress(false);

        let result = operator.process(&encrypt_params, password).await;
        assert!(result.success);
        assert!(encrypted_file.exists());

        // Decrypt with compression
        let decrypt_params = OperationParams::new(
            OperationType::Decrypt,
            TargetType::File,
            encrypted_file,
        ).with_destination(decrypted_file.clone())
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
        let encrypt_params = OperationParams::new(
            OperationType::Encrypt,
            TargetType::File,
            source_file,
        ).with_destination(encrypted_file.clone())
         .with_progress(false);

        let result = operator.process(&encrypt_params, "correct_password").await;
        assert!(result.success);

        // Try to decrypt with wrong password
        let decrypt_params = OperationParams::new(
            OperationType::Decrypt,
            TargetType::File,
            encrypted_file,
        ).with_progress(false);

        let result = operator.process(&decrypt_params, "wrong_password").await;
        assert!(!result.success);
        assert!(result.error.is_some());
    }
}