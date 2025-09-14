//! Integration tests for sf-cli

use sf_cli::{
    file_ops::FileOperator,
    models::{OperationParams, OperationType, TargetType},
};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_file_encryption_integration() {
    let temp_dir = TempDir::new().unwrap();
    let source_file = temp_dir.path().join("test.txt");
    let encrypted_file = temp_dir.path().join("test.sf");

    // Create test file
    fs::write(&source_file, b"Integration test content").unwrap();

    let operator = FileOperator::new();
    let password = "integration_test_password";

    // Test encryption
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

    // Test decryption
    let decrypted_file = temp_dir.path().join("test_decrypted.txt");
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
async fn test_directory_encryption_integration() {
    let temp_dir = TempDir::new().unwrap();
    let source_dir = temp_dir.path().join("test_dir");
    let encrypted_file = temp_dir.path().join("test_dir.sf");

    // Create test directory with files
    fs::create_dir(&source_dir).unwrap();
    fs::write(source_dir.join("file1.txt"), b"Content 1").unwrap();
    fs::write(source_dir.join("file2.txt"), b"Content 2").unwrap();

    let operator = FileOperator::new();
    let password = "directory_test_password";

    // Test directory encryption
    let encrypt_params = OperationParams::new(
        OperationType::Encrypt,
        TargetType::Directory,
        source_dir.clone(),
    )
    .with_destination(encrypted_file.clone())
    .with_progress(false);

    let result = operator.process(&encrypt_params, password).await;
    assert!(
        result.success,
        "Directory encryption failed: {:?}",
        result.error
    );
    assert!(encrypted_file.exists());

    // Test directory decryption
    let decrypted_dir = temp_dir.path().join("test_dir_decrypted");
    let decrypt_params = OperationParams::new(
        OperationType::Decrypt,
        TargetType::Directory,
        encrypted_file,
    )
    .with_destination(decrypted_dir.clone())
    .with_progress(false);

    let result = operator.process(&decrypt_params, password).await;
    assert!(
        result.success,
        "Directory decryption failed: {:?}",
        result.error
    );
    assert!(decrypted_dir.exists());

    // Verify files exist and have correct content
    assert!(decrypted_dir.join("file1.txt").exists());
    assert!(decrypted_dir.join("file2.txt").exists());

    let content1 = fs::read(decrypted_dir.join("file1.txt")).unwrap();
    let content2 = fs::read(decrypted_dir.join("file2.txt")).unwrap();

    assert_eq!(content1, b"Content 1");
    assert_eq!(content2, b"Content 2");
}

#[tokio::test]
async fn test_wrong_password_integration() {
    let temp_dir = TempDir::new().unwrap();
    let source_file = temp_dir.path().join("test.txt");
    let encrypted_file = temp_dir.path().join("test.sf");

    // Create and encrypt file
    fs::write(&source_file, b"Secret content").unwrap();

    let operator = FileOperator::new();

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
