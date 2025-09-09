//! Integration tests for watch functionality

use sf_cli::watch::{FileWatcher, WatchConfig};
use sf_cli::models::OperationType;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_watch_encrypt_basic() {
    let temp_dir = TempDir::new().unwrap();
    let watch_dir = temp_dir.path().join("source");
    let target_dir = temp_dir.path().join("encrypted");
    
    // Create directories
    std::fs::create_dir_all(&watch_dir).unwrap();
    std::fs::create_dir_all(&target_dir).unwrap();
    
    // Create config for encryption watching
    let config = WatchConfig::new(
        watch_dir.clone(),
        OperationType::Encrypt,
        "test_password_123".to_string(),
    )
    .with_target_dir(target_dir.clone())
    .with_process_existing(true)
    .with_delete_source(false); // Keep source for verification
    
    // Create a test file
    let test_file = watch_dir.join("test.txt");
    std::fs::write(&test_file, b"Hello, watch encryption!").unwrap();
    
    // Create watcher and process existing files
    let watcher = FileWatcher::new(config);
    
    // Test processing existing files
    // We can't easily test the full watch loop in a unit test, but we can test
    // the core functionality through process_existing_files
    let config_test = WatchConfig::new(
        watch_dir.clone(),
        OperationType::Encrypt,
        "test_password_123".to_string(),
    )
    .with_target_dir(target_dir.clone())
    .with_process_existing(true);
    
    let test_watcher = FileWatcher::new(config_test);
    
    // Unfortunately, process_existing_files is private, so we'll test the public API
    // by checking that the should_process_file logic works correctly
    assert!(test_watcher.config().should_process_by_operation(&test_file));
    assert!(test_watcher.config().should_process_file(&test_file));
}

#[tokio::test]
async fn test_watch_decrypt_basic() {
    let temp_dir = TempDir::new().unwrap();
    let watch_dir = temp_dir.path().join("encrypted");
    let target_dir = temp_dir.path().join("decrypted");
    
    // Create directories
    std::fs::create_dir_all(&watch_dir).unwrap();
    std::fs::create_dir_all(&target_dir).unwrap();
    
    // Create config for decryption watching
    let config = WatchConfig::new(
        watch_dir.clone(),
        OperationType::Decrypt,
        "test_password_123".to_string(),
    )
    .with_target_dir(target_dir.clone())
    .with_process_existing(true);
    
    // Create a test encrypted file (just for testing file filtering)
    let test_file = watch_dir.join("test.sf");
    std::fs::write(&test_file, b"fake encrypted content").unwrap();
    
    let watcher = FileWatcher::new(config);
    
    // Test that it correctly identifies encrypted files
    assert!(watcher.config().should_process_by_operation(&test_file));
    assert!(watcher.config().should_process_file(&test_file));
    
    // Test that it doesn't process regular files
    let regular_file = watch_dir.join("test.txt");
    std::fs::write(&regular_file, b"regular content").unwrap();
    assert!(!watcher.config().should_process_by_operation(&regular_file));
}

#[tokio::test]
async fn test_watch_extension_filtering() {
    let temp_dir = TempDir::new().unwrap();
    let watch_dir = temp_dir.path().join("source");
    std::fs::create_dir_all(&watch_dir).unwrap();
    
    // Create config with extension filtering
    let config = WatchConfig::new(
        watch_dir.clone(),
        OperationType::Encrypt,
        "password".to_string(),
    )
    .with_extensions(vec!["txt".to_string(), "doc".to_string()]);
    
    let watcher = FileWatcher::new(config);
    
    // Test files that should be processed
    assert!(watcher.config().should_process_file(&watch_dir.join("test.txt")));
    assert!(watcher.config().should_process_file(&watch_dir.join("document.doc")));
    
    // Test files that should not be processed
    assert!(!watcher.config().should_process_file(&watch_dir.join("image.jpg")));
    assert!(!watcher.config().should_process_file(&watch_dir.join("video.mp4")));
}

#[test]
fn test_watch_config_builder() {
    let config = WatchConfig::new(
        PathBuf::from("/tmp/watch"),
        OperationType::Encrypt,
        "password123".to_string(),
    )
    .with_target_dir(PathBuf::from("/tmp/encrypted"))
    .with_delete_source(true)
    .with_compression(true)
    .with_extensions(vec!["txt".to_string()])
    .with_process_existing(true)
    .with_debounce_ms(2000);
    
    assert_eq!(config.watch_dir, PathBuf::from("/tmp/watch"));
    assert_eq!(config.target_dir, Some(PathBuf::from("/tmp/encrypted")));
    assert_eq!(config.operation, OperationType::Encrypt);
    assert_eq!(config.password, "password123");
    assert!(config.delete_source);
    assert!(config.compress);
    assert_eq!(config.watch_extensions, Some(vec!["txt".to_string()]));
    assert!(config.process_existing);
    assert_eq!(config.debounce_ms, 2000);
}