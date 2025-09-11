//! Hybrid encryption module combining asymmetric and symmetric cryptography

use crate::{
    crypto::{CryptoEngine, CryptoError, FileMetadata},
    ssh_keys::{HybridPublicKey, KeyAlgorithm, SshKeyDiscovery, SshKeyError},
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use p256::{
    ecdh::EphemeralSecret,
    PublicKey as P256PublicKey,
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::Sha256;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

/// Hybrid encryption errors
#[derive(Error, Debug)]
pub enum HybridCryptoError {
    #[error("SSH key error: {0}")]
    SshKeyError(#[from] SshKeyError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("RSA encryption error: {0}")]
    RsaError(#[from] rsa::Error),
    #[error("ECDSA error: {0}")]
    EcdsaError(String),
    #[error("Invalid hybrid file format")]
    InvalidFormat,
    #[error("Unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Invalid encrypted session key length")]
    InvalidSessionKeyLength,
}

/// Size constants for hybrid encryption
pub const SESSION_KEY_SIZE: usize = 32; // 256 bits for AES-256
pub const NONCE_SIZE: usize = 12; // 96 bits for GCM
pub const RSA_MIN_KEY_SIZE: usize = 2048; // Minimum RSA key size in bits

/// Hybrid encryption header containing encrypted session key and metadata
#[derive(Debug)]
pub struct HybridHeader {
    /// Algorithm used for session key encryption
    pub key_algorithm: KeyAlgorithm,
    /// Encrypted session key
    pub encrypted_session_key: Vec<u8>,
    /// Nonce for AES-GCM encryption
    pub nonce: [u8; NONCE_SIZE],
    /// File metadata
    pub metadata: FileMetadata,
}

impl HybridHeader {
    /// Create a new hybrid header
    pub fn new(
        key_algorithm: KeyAlgorithm,
        encrypted_session_key: Vec<u8>,
        nonce: [u8; NONCE_SIZE],
        metadata: FileMetadata,
    ) -> Self {
        Self {
            key_algorithm,
            encrypted_session_key,
            nonce,
            metadata,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Algorithm type (1 byte)
        let alg_byte = match self.key_algorithm {
            KeyAlgorithm::Rsa => 0x01,
            KeyAlgorithm::EcdsaP256 => 0x02,
        };
        bytes.push(alg_byte);
        
        // Encrypted session key length (4 bytes)
        let key_len = self.encrypted_session_key.len() as u32;
        bytes.extend_from_slice(&key_len.to_le_bytes());
        
        // Encrypted session key
        bytes.extend_from_slice(&self.encrypted_session_key);
        
        // Nonce
        bytes.extend_from_slice(&self.nonce);
        
        // Metadata
        let metadata_bytes = self.metadata.to_bytes();
        let metadata_len = metadata_bytes.len() as u32;
        bytes.extend_from_slice(&metadata_len.to_le_bytes());
        bytes.extend_from_slice(&metadata_bytes);
        
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), HybridCryptoError> {
        if bytes.len() < 1 + 4 + NONCE_SIZE + 4 {
            return Err(HybridCryptoError::InvalidFormat);
        }

        let mut offset = 0;
        
        // Algorithm type
        let alg_byte = bytes[offset];
        offset += 1;
        let key_algorithm = match alg_byte {
            0x01 => KeyAlgorithm::Rsa,
            0x02 => KeyAlgorithm::EcdsaP256,
            _ => return Err(HybridCryptoError::UnsupportedAlgorithm(format!("Unknown algorithm byte: {}", alg_byte))),
        };
        
        // Encrypted session key length
        if bytes.len() < offset + 4 {
            return Err(HybridCryptoError::InvalidFormat);
        }
        let key_len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        
        // Encrypted session key
        if bytes.len() < offset + key_len {
            return Err(HybridCryptoError::InvalidFormat);
        }
        let encrypted_session_key = bytes[offset..offset + key_len].to_vec();
        offset += key_len;
        
        // Nonce
        if bytes.len() < offset + NONCE_SIZE {
            return Err(HybridCryptoError::InvalidFormat);
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;
        
        // Metadata length
        if bytes.len() < offset + 4 {
            return Err(HybridCryptoError::InvalidFormat);
        }
        let metadata_len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        
        // Metadata
        if bytes.len() < offset + metadata_len {
            return Err(HybridCryptoError::InvalidFormat);
        }
        let (metadata, _) = FileMetadata::from_bytes(&bytes[offset..offset + metadata_len])?;
        offset += metadata_len;
        
        Ok((Self::new(key_algorithm, encrypted_session_key, nonce, metadata), offset))
    }
}

/// Hybrid crypto engine for encryption/decryption operations
pub struct HybridCryptoEngine {
    crypto: CryptoEngine,
    ssh_discovery: SshKeyDiscovery,
}

impl Default for HybridCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridCryptoEngine {
    /// Create a new hybrid crypto engine
    pub fn new() -> Self {
        Self {
            crypto: CryptoEngine::new(),
            ssh_discovery: SshKeyDiscovery::new(),
        }
    }

    /// Create a new hybrid crypto engine with custom SSH directory
    pub fn with_ssh_dir<P: AsRef<Path>>(ssh_dir: P) -> Self {
        Self {
            crypto: CryptoEngine::new(),
            ssh_discovery: SshKeyDiscovery::with_ssh_dir(ssh_dir),
        }
    }

    /// Generate a random session key for AES-256
    fn generate_session_key() -> [u8; SESSION_KEY_SIZE] {
        let mut key = [0u8; SESSION_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt session key with RSA public key
    fn encrypt_session_key_rsa(
        &self,
        _session_key: &[u8; SESSION_KEY_SIZE],
        _public_key: &HybridPublicKey,
    ) -> Result<Vec<u8>, HybridCryptoError> {
        // Placeholder implementation - requires proper SSH key format handling
        Err(HybridCryptoError::EcdsaError(
            "RSA encryption not yet fully implemented - requires SSH key format conversion".to_string()
        ))
    }

    /// Encrypt session key with ECDSA P-256 public key using ECDH
    fn encrypt_session_key_ecdsa(
        &self,
        _session_key: &[u8; SESSION_KEY_SIZE],
        _public_key: &HybridPublicKey,
    ) -> Result<Vec<u8>, HybridCryptoError> {
        // Placeholder implementation - requires proper SSH key format handling
        Err(HybridCryptoError::EcdsaError(
            "ECDSA encryption not yet fully implemented - requires SSH key format conversion".to_string()
        ))
    }

    /// Encrypt data with hybrid encryption
    pub fn encrypt(
        &self,
        data: &[u8],
        public_key_path: Option<&Path>,
        metadata: FileMetadata,
    ) -> Result<Vec<u8>, HybridCryptoError> {
        // Discover or load public key
        let public_key = match public_key_path {
            Some(path) => self.ssh_discovery.load_public_key_from_path(path)?,
            None => self.ssh_discovery.get_default_key()?,
        };

        // Generate session key and nonce
        let session_key = Self::generate_session_key();
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt session key with public key
        let encrypted_session_key = match public_key.algorithm {
            KeyAlgorithm::Rsa => self.encrypt_session_key_rsa(&session_key, &public_key)?,
            KeyAlgorithm::EcdsaP256 => self.encrypt_session_key_ecdsa(&session_key, &public_key)?,
        };

        // Encrypt data with AES-256-GCM using session key
        let cipher = Aes256Gcm::new_from_slice(&session_key)
            .map_err(|e| HybridCryptoError::CryptoError(CryptoError::EncryptionFailed(e.to_string())))?;
        
        let nonce_obj = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_obj, data)
            .map_err(|e| HybridCryptoError::CryptoError(CryptoError::EncryptionFailed(e.to_string())))?;

        // Create header
        let header = HybridHeader::new(
            public_key.algorithm,
            encrypted_session_key,
            nonce,
            metadata,
        );

        // Combine header and ciphertext
        let header_bytes = header.to_bytes();
        let mut result = Vec::with_capacity(header_bytes.len() + ciphertext.len());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Placeholder for hybrid decryption (requires private key handling)
    pub fn decrypt(
        &self,
        _encrypted_data: &[u8],
        _private_key_path: Option<&Path>,
    ) -> Result<(Vec<u8>, FileMetadata), HybridCryptoError> {
        // This is a placeholder implementation
        // Real implementation would need private key handling
        // For now, return an error
        Err(HybridCryptoError::EcdsaError(
            "Hybrid decryption not yet implemented - requires private key support".to_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_session_key_generation() {
        let key1 = HybridCryptoEngine::generate_session_key();
        let key2 = HybridCryptoEngine::generate_session_key();
        
        // Keys should be different
        assert_ne!(key1, key2);
        
        // Keys should be the right size
        assert_eq!(key1.len(), SESSION_KEY_SIZE);
        assert_eq!(key2.len(), SESSION_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_header_serialization() {
        let metadata = FileMetadata::new("test.txt".to_string(), [42u8; 32], false);
        let encrypted_key = vec![1, 2, 3, 4]; // Dummy encrypted key
        let nonce = [5u8; NONCE_SIZE];
        
        let header = HybridHeader::new(
            KeyAlgorithm::Rsa,
            encrypted_key.clone(),
            nonce,
            metadata.clone(),
        );
        
        let bytes = header.to_bytes();
        let (recovered, size) = HybridHeader::from_bytes(&bytes).unwrap();
        
        assert_eq!(size, bytes.len());
        assert_eq!(recovered.key_algorithm, KeyAlgorithm::Rsa);
        assert_eq!(recovered.encrypted_session_key, encrypted_key);
        assert_eq!(recovered.nonce, nonce);
        assert_eq!(recovered.metadata.filename, metadata.filename);
    }

    #[test]
    fn test_hybrid_crypto_engine_creation() {
        let engine = HybridCryptoEngine::new();
        
        // Just test that it was created successfully
        // We can't test much more without actual SSH keys
        assert!(true);
    }

    #[test]
    fn test_invalid_hybrid_format() {
        let invalid_data = b"not_hybrid_data";
        let result = HybridHeader::from_bytes(invalid_data);
        assert!(matches!(result, Err(HybridCryptoError::InvalidFormat)));
    }
}