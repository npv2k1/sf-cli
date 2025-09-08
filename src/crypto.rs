//! Cryptographic operations for secure file encryption

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
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

/// Encryption parameters stored with encrypted data
#[derive(Debug)]
pub struct EncryptionHeader {
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
}

impl EncryptionHeader {
    /// Size of the header in bytes
    pub const SIZE: usize = SALT_SIZE + NONCE_SIZE;

    /// Create new random encryption header
    pub fn new() -> Self {
        let mut salt = [0u8; SALT_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        Self { salt, nonce }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..SALT_SIZE].copy_from_slice(&self.salt);
        bytes[SALT_SIZE..].copy_from_slice(&self.nonce);
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidFormat);
        }

        let mut salt = [0u8; SALT_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        
        salt.copy_from_slice(&bytes[..SALT_SIZE]);
        nonce.copy_from_slice(&bytes[SALT_SIZE..]);

        Ok(Self { salt, nonce })
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
    pub fn derive_key(&self, password: &str, salt: &[u8; SALT_SIZE]) -> Result<SecureKey, CryptoError> {
        let mut key = [0u8; 32];
        self.argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        Ok(SecureKey::new(key))
    }

    /// Encrypt data with password
    pub fn encrypt(&self, data: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
        let header = EncryptionHeader::new();
        let key = self.derive_key(password, &header.salt)?;
        
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&header.nonce);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(EncryptionHeader::SIZE + ciphertext.len());
        result.extend_from_slice(&header.to_bytes());
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with password
    pub fn decrypt(&self, encrypted_data: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
        if encrypted_data.len() < EncryptionHeader::SIZE {
            return Err(CryptoError::InvalidFormat);
        }

        let header = EncryptionHeader::from_bytes(&encrypted_data[..EncryptionHeader::SIZE])?;
        let ciphertext = &encrypted_data[EncryptionHeader::SIZE..];

        let key = self.derive_key(password, &header.salt)?;
        
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&header.nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::InvalidPassword)?;

        Ok(plaintext)
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

        let encrypted = engine.encrypt(data, password).unwrap();
        assert_ne!(encrypted.as_slice(), data);
        assert!(encrypted.len() > data.len());

        let decrypted = engine.decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_wrong_password() {
        let engine = CryptoEngine::new();
        let data = b"Secret message";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = engine.encrypt(data, password).unwrap();
        let result = engine.decrypt(&encrypted, wrong_password);
        
        assert!(matches!(result, Err(CryptoError::InvalidPassword)));
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
        let header1 = EncryptionHeader::new();
        let header2 = EncryptionHeader::new();

        // Headers should be different (different random values)
        assert_ne!(header1.salt, header2.salt);
        assert_ne!(header1.nonce, header2.nonce);

        // Test serialization/deserialization
        let bytes = header1.to_bytes();
        let deserialized = EncryptionHeader::from_bytes(&bytes).unwrap();
        
        assert_eq!(header1.salt, deserialized.salt);
        assert_eq!(header1.nonce, deserialized.nonce);
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