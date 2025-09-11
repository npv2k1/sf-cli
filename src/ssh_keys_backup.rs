//! SSH key discovery and management for hybrid encryption

use ssh_key::{PublicKey as SshPublicKey, PrivateKey as SshPrivateKey, Algorithm};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// SSH key errors
#[derive(Error, Debug)]
pub enum SshKeyError {
    #[error("No SSH directory found")]
    NoSshDirectory,
    #[error("No suitable public keys found")]
    NoPublicKeysFound,
    #[error("Invalid public key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("SSH key parsing error: {0}")]
    SshKeyError(#[from] ssh_key::Error),
}

/// Supported key algorithms for hybrid encryption
#[derive(Debug, Clone, PartialEq)]
pub enum KeyAlgorithm {
    Rsa,
    EcdsaP256,
    Ed25519,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Rsa => write!(f, "RSA"),
            KeyAlgorithm::EcdsaP256 => write!(f, "ECDSA-P256"),
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

/// SSH public key wrapper for hybrid encryption
#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    /// The raw SSH public key
    pub ssh_key: SshPublicKey,
    /// The algorithm type
    pub algorithm: KeyAlgorithm,
    /// The file path where this key was found
    pub file_path: PathBuf,
    /// Key comment/identifier
    pub comment: String,
}

impl HybridPublicKey {
    /// Create a new hybrid public key
    pub fn new(ssh_key: SshPublicKey, file_path: PathBuf) -> Result<Self, SshKeyError> {
        let algorithm = match ssh_key.algorithm() {
            Algorithm::Rsa { .. } => KeyAlgorithm::Rsa,
            Algorithm::Ecdsa { curve } => {
                match curve.as_str() {
                    "nistp256" => KeyAlgorithm::EcdsaP256,
                    _ => return Err(SshKeyError::UnsupportedAlgorithm(curve.to_string())),
                }
            }
            Algorithm::Ed25519 => KeyAlgorithm::Ed25519,
            alg => return Err(SshKeyError::UnsupportedAlgorithm(alg.to_string())),
        };

        let comment = ssh_key.comment().to_string();

        Ok(Self {
            ssh_key,
            algorithm,
            file_path,
            comment,
        })
    }

    /// Get a display name for this key
    pub fn display_name(&self) -> String {
        let filename = self.file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        if self.comment.is_empty() {
            format!("{} ({})", filename, self.algorithm)
        } else {
            format!("{} ({}) - {}", filename, self.algorithm, self.comment)
        }
    }
}

/// SSH private key wrapper for hybrid decryption
#[derive(Debug, Clone)]
pub struct HybridPrivateKey {
    /// The raw SSH private key
    pub ssh_key: SshPrivateKey,
    /// The algorithm type
    pub algorithm: KeyAlgorithm,
    /// The file path where this key was found
    pub file_path: PathBuf,
    /// Key comment/identifier
    pub comment: String,
}

impl HybridPrivateKey {
    /// Create a new hybrid private key
    pub fn new(ssh_key: SshPrivateKey, file_path: PathBuf) -> Result<Self, SshKeyError> {
        let algorithm = match ssh_key.algorithm() {
            Algorithm::Rsa { .. } => KeyAlgorithm::Rsa,
            Algorithm::Ecdsa { curve } => {
                match curve.as_str() {
                    "nistp256" => KeyAlgorithm::EcdsaP256,
                    _ => return Err(SshKeyError::UnsupportedAlgorithm(curve.to_string())),
                }
            }
            Algorithm::Ed25519 => KeyAlgorithm::Ed25519,
            alg => return Err(SshKeyError::UnsupportedAlgorithm(alg.to_string())),
        };

        let comment = ssh_key.comment().to_string();

        Ok(Self {
            ssh_key,
            algorithm,
            file_path,
            comment,
        })
    }

    /// Get a display name for this key
    pub fn display_name(&self) -> String {
        let filename = self.file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        if self.comment.is_empty() {
            format!("{} ({})", filename, self.algorithm)
        } else {
            format!("{} ({}) - {}", filename, self.algorithm, self.comment)
        }
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> HybridPublicKey {
        let public_ssh_key = self.ssh_key.public_key();
        // This should not fail since we already validated the algorithm in new()
        HybridPublicKey::new(public_ssh_key, self.file_path.clone())
            .expect("Failed to create public key from validated private key")
    }
}

/// SSH key discovery engine
pub struct SshKeyDiscovery {
    ssh_dir: PathBuf,
}

impl Default for SshKeyDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl SshKeyDiscovery {
    /// Create a new SSH key discovery engine with default SSH directory
    pub fn new() -> Self {
        let ssh_dir = dirs::home_dir()
            .map(|home| home.join(".ssh"))
            .unwrap_or_else(|| PathBuf::from(".ssh"));
        
        Self { ssh_dir }
    }

    /// Create a new SSH key discovery engine with custom SSH directory
    pub fn with_ssh_dir<P: AsRef<Path>>(ssh_dir: P) -> Self {
        Self {
            ssh_dir: ssh_dir.as_ref().to_path_buf(),
        }
    }

    /// Discover all suitable public keys in the SSH directory
    pub fn discover_keys(&self) -> Result<Vec<HybridPublicKey>, SshKeyError> {
        if !self.ssh_dir.exists() {
            return Err(SshKeyError::NoSshDirectory);
        }

        let mut keys = Vec::new();
        let entries = fs::read_dir(&self.ssh_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            // Look for .pub files
            if let Some(extension) = path.extension() {
                if extension == "pub" {
                    match self.load_public_key(&path) {
                        Ok(key) => {
                            println!("🔑 Found public key: {}", key.display_name());
                            keys.push(key);
                        },
                        Err(e) => {
                            // Log warning but continue with other keys
                            eprintln!("Warning: Failed to load key {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        if keys.is_empty() {
            return Err(SshKeyError::NoPublicKeysFound);
        }

        // Sort by algorithm preference (RSA first, then ECDSA, then Ed25519)
        keys.sort_by(|a, b| {
            match (&a.algorithm, &b.algorithm) {
                (KeyAlgorithm::Rsa, KeyAlgorithm::EcdsaP256) => std::cmp::Ordering::Less,
                (KeyAlgorithm::Rsa, KeyAlgorithm::Ed25519) => std::cmp::Ordering::Less,
                (KeyAlgorithm::EcdsaP256, KeyAlgorithm::Rsa) => std::cmp::Ordering::Greater,
                (KeyAlgorithm::EcdsaP256, KeyAlgorithm::Ed25519) => std::cmp::Ordering::Less,
                (KeyAlgorithm::Ed25519, KeyAlgorithm::Rsa) => std::cmp::Ordering::Greater,
                (KeyAlgorithm::Ed25519, KeyAlgorithm::EcdsaP256) => std::cmp::Ordering::Greater,
                _ => a.file_path.cmp(&b.file_path),
            }
        });

        Ok(keys)
    }

    /// Discover all suitable private keys in the SSH directory
    pub fn discover_private_keys(&self) -> Result<Vec<HybridPrivateKey>, SshKeyError> {
        if !self.ssh_dir.exists() {
            return Err(SshKeyError::NoSshDirectory);
        }

        let mut keys = Vec::new();
        let entries = fs::read_dir(&self.ssh_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            // Look for files without .pub extension (private keys)
            if path.is_file() && !path.extension().map_or(false, |ext| ext == "pub") {
                // Skip known non-key files
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                
                if filename.starts_with("known_hosts") || 
                   filename.starts_with("config") ||
                   filename.starts_with("authorized_keys") {
                    continue;
                }

                match self.load_private_key(&path) {
                    Ok(key) => {
                        println!("🔑 Found private key: {}", key.display_name());
                        keys.push(key);
                    },
                    Err(e) => {
                        // Log warning but continue with other keys
                        eprintln!("Warning: Failed to load private key {}: {}", path.display(), e);
                    }
                }
            }
        }

        if keys.is_empty() {
            return Err(SshKeyError::NoPublicKeysFound);
        }

        // Sort by algorithm preference (RSA first, then ECDSA, then Ed25519)
        keys.sort_by(|a, b| {
            match (&a.algorithm, &b.algorithm) {
                (KeyAlgorithm::Rsa, KeyAlgorithm::EcdsaP256) => std::cmp::Ordering::Less,
                (KeyAlgorithm::Rsa, KeyAlgorithm::Ed25519) => std::cmp::Ordering::Less,
                (KeyAlgorithm::EcdsaP256, KeyAlgorithm::Rsa) => std::cmp::Ordering::Greater,
                (KeyAlgorithm::EcdsaP256, KeyAlgorithm::Ed25519) => std::cmp::Ordering::Less,
                (KeyAlgorithm::Ed25519, KeyAlgorithm::Rsa) => std::cmp::Ordering::Greater,
                (KeyAlgorithm::Ed25519, KeyAlgorithm::EcdsaP256) => std::cmp::Ordering::Greater,
                _ => a.file_path.cmp(&b.file_path),
            }
        });

        Ok(keys)
    }

    /// Load a specific public key from file path
    pub fn load_public_key_from_path<P: AsRef<Path>>(&self, path: P) -> Result<HybridPublicKey, SshKeyError> {
        self.load_public_key(path.as_ref())
    }

    /// Load a public key from a file path
    fn load_public_key(&self, path: &Path) -> Result<HybridPublicKey, SshKeyError> {
        let content = fs::read_to_string(path)?;
        let ssh_key = SshPublicKey::from_openssh(&content)
            .map_err(|e| SshKeyError::InvalidKeyFormat(format!("{}: {}", path.display(), e)))?;
        
        HybridPublicKey::new(ssh_key, path.to_path_buf())
    }

    /// Get the default/preferred public key (first RSA key, or first available)
    pub fn get_default_key(&self) -> Result<HybridPublicKey, SshKeyError> {
        let keys = self.discover_keys()?;
        
        // Prefer RSA keys first, then ECDSA, then any other key
        if let Some(rsa_key) = keys.iter().find(|k| k.algorithm == KeyAlgorithm::Rsa) {
            Ok(rsa_key.clone())
        } else if let Some(ecdsa_key) = keys.iter().find(|k| k.algorithm == KeyAlgorithm::EcdsaP256) {
            Ok(ecdsa_key.clone())
        } else if let Some(first_key) = keys.into_iter().next() {
            Ok(first_key)
        } else {
            Err(SshKeyError::NoPublicKeysFound)
        }
    }

    /// Find keys by algorithm
    pub fn find_keys_by_algorithm(&self, algorithm: KeyAlgorithm) -> Result<Vec<HybridPublicKey>, SshKeyError> {
        let keys = self.discover_keys()?;
        let filtered: Vec<_> = keys.into_iter()
            .filter(|k| k.algorithm == algorithm)
            .collect();
        
        if filtered.is_empty() {
            Err(SshKeyError::NoPublicKeysFound)
        } else {
            Ok(filtered)
        }
    }

    /// Load a specific private key from file path
    pub fn load_private_key_from_path<P: AsRef<Path>>(&self, path: P) -> Result<HybridPrivateKey, SshKeyError> {
        self.load_private_key(path.as_ref())
    }

    /// Discover all suitable private keys in the SSH directory
    pub fn discover_private_keys(&self) -> Result<Vec<HybridPrivateKey>, SshKeyError> {
        if !self.ssh_dir.exists() {
            return Err(SshKeyError::NoSshDirectory);
        }

        let mut keys = Vec::new();
        let entries = fs::read_dir(&self.ssh_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            // Look for files without .pub extension (private keys)
            if path.is_file() && !path.extension().map_or(false, |ext| ext == "pub") {
                // Skip known non-key files
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                
                if filename.starts_with("known_hosts") || 
                   filename.starts_with("config") ||
                   filename.starts_with("authorized_keys") {
                    continue;
                }

                match self.load_private_key(&path) {
                    Ok(key) => {
                        println!("🔑 Found private key: {}", key.display_name());
                        keys.push(key);
                    },
                    Err(e) => {
                        // Log warning but continue with other keys
                        eprintln!("Warning: Failed to load private key {}: {}", path.display(), e);
                    }
                }
            }
        }

        if keys.is_empty() {
            return Err(SshKeyError::NoPublicKeysFound);
        }

        // Sort by algorithm preference (RSA first, then ECDSA, then Ed25519)
        keys.sort_by(|a, b| {
            match (&a.algorithm, &b.algorithm) {
                (KeyAlgorithm::Rsa, KeyAlgorithm::EcdsaP256) => std::cmp::Ordering::Less,
                (KeyAlgorithm::Rsa, KeyAlgorithm::Ed25519) => std::cmp::Ordering::Less,
                (KeyAlgorithm::EcdsaP256, KeyAlgorithm::Rsa) => std::cmp::Ordering::Greater,
                (KeyAlgorithm::EcdsaP256, KeyAlgorithm::Ed25519) => std::cmp::Ordering::Less,
                (KeyAlgorithm::Ed25519, KeyAlgorithm::Rsa) => std::cmp::Ordering::Greater,
                (KeyAlgorithm::Ed25519, KeyAlgorithm::EcdsaP256) => std::cmp::Ordering::Greater,
                _ => a.file_path.cmp(&b.file_path),
            }
        });

        Ok(keys)
    }

    /// Load a private key from a file path
    fn load_private_key(&self, path: &Path) -> Result<HybridPrivateKey, SshKeyError> {
        let content = fs::read_to_string(path)?;
        
        // Try to parse as SSH private key
        let ssh_key = SshPrivateKey::from_openssh(&content)
            .map_err(|e| SshKeyError::InvalidKeyFormat(format!("{}: {}", path.display(), e)))?;
        
        HybridPrivateKey::new(ssh_key, path.to_path_buf())
    }

    /// Get the default/preferred private key (first RSA key, or first available)
    pub fn get_default_private_key(&self) -> Result<HybridPrivateKey, SshKeyError> {
        let keys = self.discover_private_keys()?;
        
        // Prefer RSA keys first, then ECDSA, then any other key
        if let Some(rsa_key) = keys.iter().find(|k| k.algorithm == KeyAlgorithm::Rsa) {
            Ok(rsa_key.clone())
        } else if let Some(ecdsa_key) = keys.iter().find(|k| k.algorithm == KeyAlgorithm::EcdsaP256) {
            Ok(ecdsa_key.clone())
        } else if let Some(first_key) = keys.into_iter().next() {
            Ok(first_key)
        } else {
            Err(SshKeyError::NoPublicKeysFound)
        }
    }

    /// Find private keys by algorithm
    pub fn find_private_keys_by_algorithm(&self, algorithm: KeyAlgorithm) -> Result<Vec<HybridPrivateKey>, SshKeyError> {
        let keys = self.discover_private_keys()?;
        let filtered: Vec<_> = keys.into_iter()
            .filter(|k| k.algorithm == algorithm)
            .collect();
        
        if filtered.is_empty() {
            Err(SshKeyError::NoPublicKeysFound)
        } else {
            Ok(filtered)
        }
    }
    pub fn discover_keys(&self) -> Result<Vec<HybridPublicKey>, SshKeyError> {
        if !self.ssh_dir.exists() {
            return Err(SshKeyError::NoSshDirectory);
        }

        let mut keys = Vec::new();
        let entries = fs::read_dir(&self.ssh_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            // Look for .pub files
            if let Some(extension) = path.extension() {
                if extension == "pub" {
                    match self.load_public_key(&path) {
                        Ok(key) => keys.push(key),
                        Err(e) => {
                            // Log warning but continue with other keys
                            eprintln!("Warning: Failed to load key {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        if keys.is_empty() {
            return Err(SshKeyError::NoPublicKeysFound);
        }

        // Sort by algorithm preference (RSA first, then ECDSA)
        keys.sort_by(|a, b| {
            match (&a.algorithm, &b.algorithm) {
                (KeyAlgorithm::Rsa, KeyAlgorithm::EcdsaP256) => std::cmp::Ordering::Less,
                (KeyAlgorithm::EcdsaP256, KeyAlgorithm::Rsa) => std::cmp::Ordering::Greater,
                _ => a.file_path.cmp(&b.file_path),
            }
        });

        Ok(keys)
    }

    /// Load a specific public key from file path
    pub fn load_public_key_from_path<P: AsRef<Path>>(&self, path: P) -> Result<HybridPublicKey, SshKeyError> {
        self.load_public_key(path.as_ref())
    }

    /// Load a public key from a file path
    fn load_public_key(&self, path: &Path) -> Result<HybridPublicKey, SshKeyError> {
        let content = fs::read_to_string(path)?;
        let ssh_key = SshPublicKey::from_openssh(&content)
            .map_err(|e| SshKeyError::InvalidKeyFormat(format!("{}: {}", path.display(), e)))?;
        
        HybridPublicKey::new(ssh_key, path.to_path_buf())
    }

    /// Get the default/preferred public key (first RSA key, or first available)
    pub fn get_default_key(&self) -> Result<HybridPublicKey, SshKeyError> {
        let keys = self.discover_keys()?;
        
        // Prefer RSA keys first, then any other key
        if let Some(rsa_key) = keys.iter().find(|k| k.algorithm == KeyAlgorithm::Rsa) {
            Ok(rsa_key.clone())
        } else if let Some(first_key) = keys.into_iter().next() {
            Ok(first_key)
        } else {
            Err(SshKeyError::NoPublicKeysFound)
        }
    }

    /// Find keys by algorithm
    pub fn find_keys_by_algorithm(&self, algorithm: KeyAlgorithm) -> Result<Vec<HybridPublicKey>, SshKeyError> {
        let keys = self.discover_keys()?;
        let filtered: Vec<_> = keys.into_iter()
            .filter(|k| k.algorithm == algorithm)
            .collect();
        
        if filtered.is_empty() {
            Err(SshKeyError::NoPublicKeysFound)
        } else {
            Ok(filtered)
        }
    }

    /// Check if SSH directory exists and is accessible
    pub fn check_ssh_directory(&self) -> Result<(), SshKeyError> {
        if !self.ssh_dir.exists() {
            return Err(SshKeyError::NoSshDirectory);
        }

        // Try to read the directory to check permissions
        fs::read_dir(&self.ssh_dir)?;
        Ok(())
    }
}

// Add dirs dependency for home directory detection
// We'll need to add this to Cargo.toml as well

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_ssh_key_discovery_no_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent_ssh_dir = temp_dir.path().join("nonexistent");
        
        let discovery = SshKeyDiscovery::with_ssh_dir(nonexistent_ssh_dir);
        let result = discovery.discover_keys();
        
        assert!(matches!(result, Err(SshKeyError::NoSshDirectory)));
    }

    #[test]
    fn test_ssh_key_discovery_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        fs::create_dir(&ssh_dir).unwrap();
        
        let discovery = SshKeyDiscovery::with_ssh_dir(ssh_dir);
        let result = discovery.discover_keys();
        
        assert!(matches!(result, Err(SshKeyError::NoPublicKeysFound)));
    }

    #[test]
    fn test_key_algorithm_display() {
        assert_eq!(KeyAlgorithm::Rsa.to_string(), "RSA");
        assert_eq!(KeyAlgorithm::EcdsaP256.to_string(), "ECDSA-P256");
    }

    #[test]
    fn test_check_ssh_directory() {
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        fs::create_dir(&ssh_dir).unwrap();
        
        let discovery = SshKeyDiscovery::with_ssh_dir(&ssh_dir);
        assert!(discovery.check_ssh_directory().is_ok());
        
        let nonexistent = temp_dir.path().join("nonexistent");
        let discovery2 = SshKeyDiscovery::with_ssh_dir(nonexistent);
        assert!(matches!(discovery2.check_ssh_directory(), Err(SshKeyError::NoSshDirectory)));
    }

    // Note: We can't easily test actual SSH key loading without creating valid keys
    // This would require more complex test setup with actual key generation
}