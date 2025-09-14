//! Cryptographic operations for secure file encryption

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Invalid encrypted data format")]
    InvalidFormat,
}

/// Secure key material that is zeroized on drop
pub struct SecureKey {
    key: [u8; 32], // 256-bit key for AES-256
}

impl SecureKey {
    /// Create a new secure key from raw bytes
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Get key bytes for cryptographic operations
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Salt for key derivation
pub const SALT_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const CHECKSUM_SIZE: usize = 32; // SHA-256 hash

/// File metadata stored with encrypted data
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Original filename with extension
    pub filename: String,
    /// File checksum (SHA-256)
    pub checksum: [u8; CHECKSUM_SIZE],
    /// Whether the data was compressed
    pub compressed: bool,
}

impl FileMetadata {
    /// Create new file metadata
    pub fn new(filename: String, checksum: [u8; CHECKSUM_SIZE], compressed: bool) -> Self {
        Self {
            filename,
            checksum,
            compressed,
        }
    }

    /// Create metadata from file path and data
    pub fn from_file(file_path: &Path, data: &[u8], compressed: bool) -> Self {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum: [u8; CHECKSUM_SIZE] = hasher.finalize().into();

        Self::new(filename, checksum, compressed)
    }

    /// Serialize metadata to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let filename_bytes = self.filename.as_bytes();
        let filename_len = filename_bytes.len() as u16;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&filename_len.to_le_bytes());
        bytes.extend_from_slice(filename_bytes);
        bytes.extend_from_slice(&self.checksum);
        bytes.push(if self.compressed { 1 } else { 0 });

        bytes
    }

    /// Deserialize metadata from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), CryptoError> {
        if bytes.len() < 2 {
            return Err(CryptoError::InvalidFormat);
        }

        let filename_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let required_size = 2 + filename_len + CHECKSUM_SIZE + 1;

        if bytes.len() < required_size {
            return Err(CryptoError::InvalidFormat);
        }

        let filename = String::from_utf8(bytes[2..2 + filename_len].to_vec())
            .map_err(|_| CryptoError::InvalidFormat)?;

        let mut checksum = [0u8; CHECKSUM_SIZE];
        checksum.copy_from_slice(&bytes[2 + filename_len..2 + filename_len + CHECKSUM_SIZE]);

        let compressed = bytes[2 + filename_len + CHECKSUM_SIZE] != 0;

        Ok((Self::new(filename, checksum, compressed), required_size))
    }

    /// Verify checksum against data
    pub fn verify_checksum(&self, data: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let computed_checksum: [u8; CHECKSUM_SIZE] = hasher.finalize().into();
        computed_checksum == self.checksum
    }
}

/// Encryption parameters stored with encrypted data
#[derive(Debug)]
pub struct EncryptionHeader {
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub metadata: FileMetadata,
}

impl EncryptionHeader {
    /// Create new encryption header with metadata
    pub fn new(metadata: FileMetadata) -> Self {
        let mut salt = [0u8; SALT_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];

        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        Self {
            salt,
            nonce,
            metadata,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);

        let metadata_bytes = self.metadata.to_bytes();
        let metadata_len = metadata_bytes.len() as u32;
        bytes.extend_from_slice(&metadata_len.to_le_bytes());
        bytes.extend_from_slice(&metadata_bytes);

        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), CryptoError> {
        let min_size = SALT_SIZE + NONCE_SIZE + 4; // +4 for metadata length
        if bytes.len() < min_size {
            return Err(CryptoError::InvalidFormat);
        }

        let mut salt = [0u8; SALT_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];

        salt.copy_from_slice(&bytes[..SALT_SIZE]);
        nonce.copy_from_slice(&bytes[SALT_SIZE..SALT_SIZE + NONCE_SIZE]);

        let metadata_len_offset = SALT_SIZE + NONCE_SIZE;
        let metadata_len = u32::from_le_bytes([
            bytes[metadata_len_offset],
            bytes[metadata_len_offset + 1],
            bytes[metadata_len_offset + 2],
            bytes[metadata_len_offset + 3],
        ]) as usize;

        let metadata_start = metadata_len_offset + 4;
        if bytes.len() < metadata_start + metadata_len {
            return Err(CryptoError::InvalidFormat);
        }

        let (metadata, _) =
            FileMetadata::from_bytes(&bytes[metadata_start..metadata_start + metadata_len])?;
        let total_size = metadata_start + metadata_len;

        Ok((
            Self {
                salt,
                nonce,
                metadata,
            },
            total_size,
        ))
    }
}

/// Crypto engine for encryption/decryption operations
pub struct CryptoEngine {
    argon2: Argon2<'static>,
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoEngine {
    /// Create a new crypto engine with secure defaults
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Derive a secure key from password and salt using Argon2
    pub fn derive_key(
        &self,
        password: &str,
        salt: &[u8; SALT_SIZE],
    ) -> Result<SecureKey, CryptoError> {
        let mut key = [0u8; 32];
        self.argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        Ok(SecureKey::new(key))
    }

    /// Encrypt data with password and metadata
    pub fn encrypt(
        &self,
        data: &[u8],
        password: &str,
        metadata: FileMetadata,
    ) -> Result<Vec<u8>, CryptoError> {
        let header = EncryptionHeader::new(metadata);
        let key = self.derive_key(password, &header.salt)?;

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&header.nonce);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let header_bytes = header.to_bytes();
        let mut result = Vec::with_capacity(header_bytes.len() + ciphertext.len());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with password, returning both data and metadata
    pub fn decrypt(
        &self,
        encrypted_data: &[u8],
        password: &str,
    ) -> Result<(Vec<u8>, FileMetadata), CryptoError> {
        if encrypted_data.len() < SALT_SIZE + NONCE_SIZE + 4 {
            return Err(CryptoError::InvalidFormat);
        }

        let (header, header_size) = EncryptionHeader::from_bytes(encrypted_data)?;
        let ciphertext = &encrypted_data[header_size..];

        let key = self.derive_key(password, &header.salt)?;

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&header.nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::InvalidPassword)?;

        Ok((plaintext, header.metadata))
    }

    /// Legacy decrypt method for backward compatibility
    pub fn decrypt_legacy(
        &self,
        encrypted_data: &[u8],
        password: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        const LEGACY_HEADER_SIZE: usize = SALT_SIZE + NONCE_SIZE;

        if encrypted_data.len() < LEGACY_HEADER_SIZE {
            return Err(CryptoError::InvalidFormat);
        }

        // Try to detect if this is legacy format (fixed header size)
        let is_legacy = encrypted_data.len() >= LEGACY_HEADER_SIZE && {
            // Check if the metadata length field would be reasonable for new format
            if encrypted_data.len() > SALT_SIZE + NONCE_SIZE + 4 {
                let metadata_len_offset = SALT_SIZE + NONCE_SIZE;
                let metadata_len = u32::from_le_bytes([
                    encrypted_data[metadata_len_offset],
                    encrypted_data[metadata_len_offset + 1],
                    encrypted_data[metadata_len_offset + 2],
                    encrypted_data[metadata_len_offset + 3],
                ]) as usize;

                // If metadata length is unreasonably large, assume legacy format
                metadata_len > 1024 || metadata_len_offset + 4 + metadata_len > encrypted_data.len()
            } else {
                true
            }
        };

        if is_legacy {
            let mut salt = [0u8; SALT_SIZE];
            let mut nonce = [0u8; NONCE_SIZE];

            salt.copy_from_slice(&encrypted_data[..SALT_SIZE]);
            nonce.copy_from_slice(&encrypted_data[SALT_SIZE..LEGACY_HEADER_SIZE]);

            let ciphertext = &encrypted_data[LEGACY_HEADER_SIZE..];

            let key = self.derive_key(password, &salt)?;

            let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

            let nonce_obj = Nonce::from_slice(&nonce);
            let plaintext = cipher
                .decrypt(nonce_obj, ciphertext)
                .map_err(|_| CryptoError::InvalidPassword)?;

            Ok(plaintext)
        } else {
            // Use new format
            let (plaintext, _) = self.decrypt(encrypted_data, password)?;
            Ok(plaintext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let engine = CryptoEngine::new();
        let data = b"Hello, World! This is a test message.";
        let password = "strong_password_123";
        let metadata = FileMetadata::new("test.txt".to_string(), [0u8; 32], false);

        let encrypted = engine.encrypt(data, password, metadata.clone()).unwrap();
        assert_ne!(encrypted.as_slice(), data);
        assert!(encrypted.len() > data.len());

        let (decrypted, recovered_metadata) = engine.decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted.as_slice(), data);
        assert_eq!(recovered_metadata.filename, metadata.filename);
        assert_eq!(recovered_metadata.compressed, metadata.compressed);
    }

    #[test]
    fn test_wrong_password() {
        let engine = CryptoEngine::new();
        let data = b"Secret message";
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let metadata = FileMetadata::new("secret.txt".to_string(), [0u8; 32], false);

        let encrypted = engine.encrypt(data, password, metadata).unwrap();
        let result = engine.decrypt(&encrypted, wrong_password);

        assert!(matches!(result, Err(CryptoError::InvalidPassword)));
    }

    #[test]
    fn test_legacy_format_compatibility() {
        let engine = CryptoEngine::new();
        let _data = b"Legacy test data";
        let password = "test_password";

        // This test would require creating legacy format data
        // For now, we'll test that legacy detection doesn't break
        let result = engine.decrypt_legacy(b"invalid_short_data", password);
        assert!(matches!(result, Err(CryptoError::InvalidFormat)));
    }

    #[test]
    fn test_file_metadata() {
        use std::path::Path;

        let data = b"Test file content";
        let path = Path::new("test.txt");
        let metadata = FileMetadata::from_file(path, data, false);

        assert_eq!(metadata.filename, "test.txt");
        assert!(!metadata.compressed);
        assert!(metadata.verify_checksum(data));

        // Test serialization
        let bytes = metadata.to_bytes();
        let (recovered, size) = FileMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(size, bytes.len());
        assert_eq!(recovered.filename, metadata.filename);
        assert_eq!(recovered.checksum, metadata.checksum);
        assert_eq!(recovered.compressed, metadata.compressed);
    }

    #[test]
    fn test_invalid_format() {
        let engine = CryptoEngine::new();
        let invalid_data = b"not_encrypted_data";
        let password = "password";

        let result = engine.decrypt(invalid_data, password);
        assert!(matches!(result, Err(CryptoError::InvalidFormat)));
    }

    #[test]
    fn test_encryption_header() {
        let metadata = FileMetadata::new("test.txt".to_string(), [42u8; 32], true);
        let header = EncryptionHeader::new(metadata.clone());

        // Test serialization/deserialization
        let bytes = header.to_bytes();
        let (deserialized, size) = EncryptionHeader::from_bytes(&bytes).unwrap();

        assert_eq!(size, bytes.len());
        assert_eq!(header.salt, deserialized.salt);
        assert_eq!(header.nonce, deserialized.nonce);
        assert_eq!(header.metadata.filename, deserialized.metadata.filename);
        assert_eq!(header.metadata.checksum, deserialized.metadata.checksum);
        assert_eq!(header.metadata.compressed, deserialized.metadata.compressed);
    }

    #[test]
    fn test_secure_key_zeroization() {
        let key_bytes = [42u8; 32];
        let key = SecureKey::new(key_bytes);
        assert_eq!(key.as_bytes(), &key_bytes);

        // Key should be zeroized when dropped
        drop(key);
        // Note: We can't test zeroization directly as the memory is freed
    }
}
