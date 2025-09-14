//! Tests for hybrid encryption functionality

use sf_cli::{
    crypto::FileMetadata,
    hybrid_crypto::{HybridCryptoEngine, HybridCryptoError},
    ssh_keys::{HybridPublicKey, KeyAlgorithm, SshKeyDiscovery, SshKeyError},
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

#[test]
fn test_hybrid_round_trip_with_test_keys() {
    use std::process::Command;

    // Create a temporary directory for test keys
    let temp_dir = TempDir::new().unwrap();
    let ssh_dir = temp_dir.path().join(".ssh");
    fs::create_dir(&ssh_dir).unwrap();

    // Generate test RSA key
    let key_path = ssh_dir.join("test_key");
    let pub_key_path = ssh_dir.join("test_key.pub");

    let output = Command::new("ssh-keygen")
        .args(&["-t", "rsa", "-b", "2048", "-f"])
        .arg(&key_path)
        .args(&["-N", "", "-C", "test-hybrid"])
        .output();

    if output.is_err() || !output.unwrap().status.success() {
        // Skip test if ssh-keygen is not available
        return;
    }

    // Test with the generated keys
    let engine = HybridCryptoEngine::with_ssh_dir(&ssh_dir);
    let test_data = b"Hello, hybrid encryption!";
    let metadata = FileMetadata::new("test.txt".to_string(), [0u8; 32], false);

    // Encrypt with public key
    let encrypted = engine
        .encrypt(test_data, Some(&pub_key_path), metadata.clone())
        .unwrap();

    // Decrypt with private key
    let (decrypted, recovered_metadata) = engine.decrypt(&encrypted, Some(&key_path)).unwrap();

    assert_eq!(test_data, decrypted.as_slice());
    assert_eq!(metadata.filename, recovered_metadata.filename);
}

#[test]
fn test_extract_public_key_info() {
    use sf_cli::hybrid_crypto::HybridHeader;

    // Create test encrypted data (just a header for this test)
    let metadata = FileMetadata::new("test.txt".to_string(), [0u8; 32], false);
    let header = HybridHeader::new(
        KeyAlgorithm::Rsa,
        vec![1, 2, 3, 4], // dummy encrypted key
        [5u8; 12],        // dummy nonce
        metadata,
    );

    let header_bytes = header.to_bytes();

    let engine = HybridCryptoEngine::new();
    let (algorithm, description) = engine.extract_public_key_info(&header_bytes).unwrap();

    assert_eq!(algorithm, KeyAlgorithm::Rsa);
    assert_eq!(description, "RSA public key");
}

// Note: Testing with actual SSH keys would require generating real keys
// which is complex for a unit test. The integration will be tested with
// the CLI commands using generated keys.
