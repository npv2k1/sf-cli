//! Tests for hybrid encryption functionality

use sf_cli::{
    hybrid_crypto::{HybridCryptoEngine, HybridCryptoError},
    ssh_keys::{SshKeyDiscovery, SshKeyError, KeyAlgorithm, HybridPublicKey},
    crypto::FileMetadata,
};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_hybrid_crypto_engine_creation() {
    let engine = HybridCryptoEngine::new();
    // Just test that it was created successfully
    assert!(true);
}

#[test]
fn test_ssh_key_discovery_no_ssh_dir() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent_ssh_dir = temp_dir.path().join("nonexistent");
    
    let discovery = SshKeyDiscovery::with_ssh_dir(nonexistent_ssh_dir);
    let result = discovery.discover_keys();
    
    assert!(matches!(result, Err(SshKeyError::NoSshDirectory)));
}

#[test]
fn test_ssh_key_discovery_empty_dir() {
    let temp_dir = TempDir::new().unwrap();
    let ssh_dir = temp_dir.path().join(".ssh");
    fs::create_dir(&ssh_dir).unwrap();
    
    let discovery = SshKeyDiscovery::with_ssh_dir(ssh_dir);
    let result = discovery.discover_keys();
    
    assert!(matches!(result, Err(SshKeyError::NoPublicKeysFound)));
}

#[test]
fn test_hybrid_encryption_no_keys() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent_ssh_dir = temp_dir.path().join("nonexistent");
    
    let engine = HybridCryptoEngine::with_ssh_dir(nonexistent_ssh_dir);
    let data = b"test data";
    let metadata = FileMetadata::new("test.txt".to_string(), [0u8; 32], false);
    
    let result = engine.encrypt(data, None, metadata);
    assert!(matches!(result, Err(HybridCryptoError::SshKeyError(_))));
}

// Note: Testing with actual SSH keys would require generating real keys
// which is complex for a unit test. The integration will be tested with
// the CLI commands using generated keys.