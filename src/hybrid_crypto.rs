//! Hybrid encryption module combining asymmetric and symmetric cryptography

use crate::{
    crypto::{CryptoEngine, CryptoError, FileMetadata},
    ssh_keys::{HybridPrivateKey, HybridPublicKey, KeyAlgorithm, SshKeyDiscovery, SshKeyError},
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey as P256PublicKey,
};
use rand::RngCore;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::path::Path;
use thiserror::Error;

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
            KeyAlgorithm::Ed25519 => 0x03,
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
            0x03 => KeyAlgorithm::Ed25519,
            _ => {
                return Err(HybridCryptoError::UnsupportedAlgorithm(format!(
                    "Unknown algorithm byte: {}",
                    alg_byte
                )))
            }
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

        Ok((
            Self::new(key_algorithm, encrypted_session_key, nonce, metadata),
            offset,
        ))
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
        session_key: &[u8; SESSION_KEY_SIZE],
        public_key: &HybridPublicKey,
    ) -> Result<Vec<u8>, HybridCryptoError> {
        // Convert SSH key to OpenSSH format and then parse manually
        let openssh_str = public_key
            .ssh_key
            .to_openssh()
            .map_err(|e| HybridCryptoError::SshKeyError(SshKeyError::SshKeyError(e)))?;

        // For SSH RSA keys, we need to extract the RSA public key components
        // The SSH key format is: algorithm_name public_key_blob comment
        // The public_key_blob is base64 encoded and contains:
        // - algorithm name (string)
        // - public exponent e (mpint)
        // - modulus n (mpint)

        let parts: Vec<&str> = openssh_str.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid SSH key format".to_string(),
            ));
        }

        if parts[0] != "ssh-rsa" {
            return Err(HybridCryptoError::UnsupportedAlgorithm(format!(
                "Expected ssh-rsa but got {}",
                parts[0]
            )));
        }

        // Decode the base64 blob
        let blob = general_purpose::STANDARD.decode(parts[1]).map_err(|e| {
            HybridCryptoError::UnsupportedAlgorithm(format!("Failed to decode SSH key blob: {}", e))
        })?;

        // Parse the SSH wire format
        let mut offset = 0;

        // Skip algorithm name (string)
        if blob.len() < offset + 4 {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let name_len = u32::from_be_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as usize;
        offset += 4 + name_len;

        // Read public exponent e (mpint)
        if blob.len() < offset + 4 {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let e_len = u32::from_be_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as usize;
        offset += 4;
        if blob.len() < offset + e_len {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let e_bytes = &blob[offset..offset + e_len];
        let e = rsa::BigUint::from_bytes_be(e_bytes);
        offset += e_len;

        // Read modulus n (mpint)
        if blob.len() < offset + 4 {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let n_len = u32::from_be_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as usize;
        offset += 4;
        if blob.len() < offset + n_len {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let n_bytes = &blob[offset..offset + n_len];
        let n = rsa::BigUint::from_bytes_be(n_bytes);

        // Create RSA public key
        let rsa_key = RsaPublicKey::new(n, e).map_err(|e| HybridCryptoError::RsaError(e))?;

        // Encrypt session key using PKCS#1 v1.5 padding
        let mut rng = OsRng;
        let encrypted_key = rsa_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, session_key)
            .map_err(|e| HybridCryptoError::RsaError(e))?;

        Ok(encrypted_key)
    }

    /// Encrypt session key with ECDSA P-256 public key using ECDH
    fn encrypt_session_key_ecdsa(
        &self,
        session_key: &[u8; SESSION_KEY_SIZE],
        public_key: &HybridPublicKey,
    ) -> Result<Vec<u8>, HybridCryptoError> {
        // Convert SSH key to OpenSSH format and parse ECDSA key
        let openssh_str = public_key
            .ssh_key
            .to_openssh()
            .map_err(|e| HybridCryptoError::SshKeyError(SshKeyError::SshKeyError(e)))?;

        let parts: Vec<&str> = openssh_str.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid SSH key format".to_string(),
            ));
        }

        if !parts[0].starts_with("ecdsa-sha2-") {
            return Err(HybridCryptoError::UnsupportedAlgorithm(format!(
                "Expected ecdsa-sha2-* but got {}",
                parts[0]
            )));
        }

        // Decode the base64 blob
        let blob = general_purpose::STANDARD.decode(parts[1]).map_err(|e| {
            HybridCryptoError::UnsupportedAlgorithm(format!("Failed to decode SSH key blob: {}", e))
        })?;

        // Parse the SSH wire format for ECDSA
        let mut offset = 0;

        // Skip algorithm name (string)
        if blob.len() < offset + 4 {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let name_len = u32::from_be_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as usize;
        offset += 4 + name_len;

        // Read curve name (string)
        if blob.len() < offset + 4 {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let curve_len = u32::from_be_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as usize;
        offset += 4;
        if blob.len() < offset + curve_len {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let curve_name = std::str::from_utf8(&blob[offset..offset + curve_len]).map_err(|e| {
            HybridCryptoError::UnsupportedAlgorithm(format!("Invalid curve name: {}", e))
        })?;
        offset += curve_len;

        if curve_name != "nistp256" {
            return Err(HybridCryptoError::UnsupportedAlgorithm(format!(
                "Unsupported ECDSA curve: {}",
                curve_name
            )));
        }

        // Read public key point (string)
        if blob.len() < offset + 4 {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let point_len = u32::from_be_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as usize;
        offset += 4;
        if blob.len() < offset + point_len {
            return Err(HybridCryptoError::UnsupportedAlgorithm(
                "Invalid blob format".to_string(),
            ));
        }
        let point_bytes = &blob[offset..offset + point_len];

        // Parse the P-256 public key from the uncompressed point format
        let p256_key = P256PublicKey::from_sec1_bytes(point_bytes)
            .map_err(|e| HybridCryptoError::EcdsaError(format!("Invalid P-256 point: {}", e)))?;

        // Generate ephemeral key pair for ECDH
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = ephemeral_secret.public_key();

        // Perform ECDH to get shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(&p256_key);

        // Use HKDF to derive key encryption key from shared secret
        let hk = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
        let mut kek = [0u8; 32]; // Key encryption key
        hk.expand(b"sf-cli-hybrid-v1", &mut kek)
            .map_err(|e| HybridCryptoError::EcdsaError(format!("HKDF expansion failed: {}", e)))?;

        // Encrypt session key with AES-256
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&kek).map_err(|e| {
            HybridCryptoError::CryptoError(CryptoError::EncryptionFailed(e.to_string()))
        })?;

        // Generate nonce for session key encryption
        let mut key_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut key_nonce);

        let nonce_obj = aes_gcm::Nonce::from_slice(&key_nonce);
        let encrypted_session_key =
            cipher
                .encrypt(nonce_obj, session_key.as_ref())
                .map_err(|e| {
                    HybridCryptoError::CryptoError(CryptoError::EncryptionFailed(e.to_string()))
                })?;

        // Return: ephemeral_public_key (33 bytes) + nonce (12 bytes) + encrypted_session_key
        let ephemeral_point = ephemeral_public.to_encoded_point(true); // Compressed format
        let mut result = Vec::with_capacity(33 + 12 + encrypted_session_key.len());
        result.extend_from_slice(ephemeral_point.as_bytes());
        result.extend_from_slice(&key_nonce);
        result.extend_from_slice(&encrypted_session_key);

        Ok(result)
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
            Some(path) => {
                println!("🔑 Using public key from: {}", path.display());
                self.ssh_discovery.load_public_key_from_path(path)?
            }
            None => {
                println!("🔍 Auto-discovering public keys...");
                self.ssh_discovery.select_public_key_interactive()?
            }
        };

        // Generate session key and nonce
        let session_key = Self::generate_session_key();
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt session key with public key
        let encrypted_session_key = match public_key.algorithm {
            KeyAlgorithm::Rsa => self.encrypt_session_key_rsa(&session_key, &public_key)?,
            KeyAlgorithm::EcdsaP256 => self.encrypt_session_key_ecdsa(&session_key, &public_key)?,
            KeyAlgorithm::Ed25519 => {
                return Err(HybridCryptoError::UnsupportedAlgorithm(
                    "Ed25519 encryption not yet implemented".to_string(),
                ));
            }
        };

        // Encrypt data with AES-256-GCM using session key
        let cipher = Aes256Gcm::new_from_slice(&session_key).map_err(|e| {
            HybridCryptoError::CryptoError(CryptoError::EncryptionFailed(e.to_string()))
        })?;

        let nonce_obj = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce_obj, data).map_err(|e| {
            HybridCryptoError::CryptoError(CryptoError::EncryptionFailed(e.to_string()))
        })?;

        // Create header
        let header =
            HybridHeader::new(public_key.algorithm, encrypted_session_key, nonce, metadata);

        // Combine header and ciphertext
        let header_bytes = header.to_bytes();
        let mut result = Vec::with_capacity(header_bytes.len() + ciphertext.len());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Hybrid decryption functionality
    pub fn decrypt(
        &self,
        encrypted_data: &[u8],
        private_key_path: Option<&Path>,
    ) -> Result<(Vec<u8>, FileMetadata), HybridCryptoError> {
        // Parse the header first
        let (header, header_size) = HybridHeader::from_bytes(encrypted_data)?;

        // The remaining data is the encrypted content
        let ciphertext = &encrypted_data[header_size..];

        // Discover or load private key
        let private_key = match private_key_path {
            Some(path) => {
                println!("🔑 Using private key from: {}", path.display());
                self.ssh_discovery.load_private_key_from_path(path)?
            }
            None => {
                println!("🔍 Auto-discovering private keys...");
                self.ssh_discovery.select_private_key_interactive()?
            }
        };

        // Verify that the private key algorithm matches the header
        if private_key.algorithm != header.key_algorithm {
            return Err(HybridCryptoError::UnsupportedAlgorithm(format!(
                "Private key algorithm ({}) does not match encrypted file algorithm ({})",
                private_key.algorithm, header.key_algorithm
            )));
        }

        println!("🔓 Decrypting with key: {}", private_key.display_name());

        // Decrypt session key using private key
        let session_key = match header.key_algorithm {
            KeyAlgorithm::Rsa => {
                self.decrypt_session_key_rsa(&header.encrypted_session_key, &private_key)?
            }
            KeyAlgorithm::EcdsaP256 => {
                self.decrypt_session_key_ecdsa(&header.encrypted_session_key, &private_key)?
            }
            KeyAlgorithm::Ed25519 => {
                return Err(HybridCryptoError::UnsupportedAlgorithm(
                    "Ed25519 decryption not yet implemented".to_string(),
                ));
            }
        };

        // Decrypt data with AES-256-GCM using session key
        let cipher = Aes256Gcm::new_from_slice(&session_key).map_err(|e| {
            HybridCryptoError::CryptoError(CryptoError::DecryptionFailed(e.to_string()))
        })?;

        let nonce_obj = Nonce::from_slice(&header.nonce);
        let plaintext = cipher.decrypt(nonce_obj, ciphertext).map_err(|e| {
            HybridCryptoError::CryptoError(CryptoError::DecryptionFailed(e.to_string()))
        })?;

        Ok((plaintext, header.metadata))
    }

    /// Decrypt session key with RSA private key
    fn decrypt_session_key_rsa(
        &self,
        encrypted_session_key: &[u8],
        private_key: &HybridPrivateKey,
    ) -> Result<[u8; SESSION_KEY_SIZE], HybridCryptoError> {
        // Convert SSH private key to RSA format
        let _openssh_str = private_key
            .ssh_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|e| HybridCryptoError::SshKeyError(SshKeyError::SshKeyError(e)))?;

        // For SSH RSA private keys, we need to extract the components
        let ssh_private_key = &private_key.ssh_key;

        // Get the RSA key data from the SSH private key
        // We'll use the ssh-key crate's built-in conversion capabilities
        match ssh_private_key.key_data() {
            ssh_key::private::KeypairData::Rsa(rsa_keypair) => {
                // Extract RSA components
                let n = rsa::BigUint::from_bytes_be(rsa_keypair.public.n.as_bytes());
                let e = rsa::BigUint::from_bytes_be(rsa_keypair.public.e.as_bytes());
                let d = rsa::BigUint::from_bytes_be(rsa_keypair.private.d.as_bytes());
                let primes = vec![
                    rsa::BigUint::from_bytes_be(rsa_keypair.private.p.as_bytes()),
                    rsa::BigUint::from_bytes_be(rsa_keypair.private.q.as_bytes()),
                ];

                // Create RSA private key
                let rsa_private_key = RsaPrivateKey::from_components(n, e, d, primes)
                    .map_err(|e| HybridCryptoError::RsaError(e))?;

                // Decrypt session key using PKCS#1 v1.5 padding
                let decrypted_key = rsa_private_key
                    .decrypt(Pkcs1v15Encrypt, encrypted_session_key)
                    .map_err(|e| HybridCryptoError::RsaError(e))?;

                if decrypted_key.len() != SESSION_KEY_SIZE {
                    return Err(HybridCryptoError::InvalidSessionKeyLength);
                }

                let mut session_key = [0u8; SESSION_KEY_SIZE];
                session_key.copy_from_slice(&decrypted_key);
                Ok(session_key)
            }
            _ => Err(HybridCryptoError::UnsupportedAlgorithm(
                "Expected RSA private key".to_string(),
            )),
        }
    }

    /// Decrypt session key with ECDSA P-256 private key using ECDH
    fn decrypt_session_key_ecdsa(
        &self,
        encrypted_data: &[u8],
        private_key: &HybridPrivateKey,
    ) -> Result<[u8; SESSION_KEY_SIZE], HybridCryptoError> {
        // Extract ephemeral public key (33 bytes) + nonce (12 bytes) + encrypted session key
        if encrypted_data.len() < 33 + 12 {
            return Err(HybridCryptoError::InvalidFormat);
        }

        let ephemeral_public_bytes = &encrypted_data[0..33];
        let _key_nonce = &encrypted_data[33..45];
        let _encrypted_session_key = &encrypted_data[45..];

        // Parse ephemeral public key
        let _ephemeral_public =
            P256PublicKey::from_sec1_bytes(ephemeral_public_bytes).map_err(|e| {
                HybridCryptoError::EcdsaError(format!("Invalid ephemeral public key: {}", e))
            })?;

        // Get our private key
        match private_key.ssh_key.key_data() {
            ssh_key::private::KeypairData::Ecdsa(_ecdsa_keypair) => {
                // For now, return an error until we can properly access the private key
                return Err(HybridCryptoError::EcdsaError(
                    "ECDSA private key access needs to be implemented with correct field names"
                        .to_string(),
                ));
            }
            _ => Err(HybridCryptoError::UnsupportedAlgorithm(
                "Expected ECDSA private key".to_string(),
            )),
        }
    }

    /// Extract public key information from an encrypted file
    pub fn extract_public_key_info(
        &self,
        encrypted_data: &[u8],
    ) -> Result<(KeyAlgorithm, String), HybridCryptoError> {
        let (header, _) = HybridHeader::from_bytes(encrypted_data)?;

        // Create a description of the key used for encryption
        let key_description = match header.key_algorithm {
            KeyAlgorithm::Rsa => "RSA public key".to_string(),
            KeyAlgorithm::EcdsaP256 => "ECDSA P-256 public key".to_string(),
            KeyAlgorithm::Ed25519 => "Ed25519 public key".to_string(),
        };

        Ok((header.key_algorithm, key_description))
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
