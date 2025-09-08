//! Basic usage example for sf-cli

use sf_cli::{
    file_ops::FileOperator,
    models::{OperationParams, OperationType, TargetType},
};
use std::{fs, path::PathBuf};
use tempfile::TempDir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for this example
    let temp_dir = TempDir::new()?;
    let source_file = temp_dir.path().join("example.txt");
    
    // Create a sample file
    fs::write(&source_file, b"This is an example file for encryption.")?;
    println!("Created example file: {}", source_file.display());

    // Initialize the file operator
    let operator = FileOperator::new();
    let password = "example_password_123";

    // Example 1: Encrypt a file
    println!("\n=== File Encryption Example ===");
    let encrypt_params = OperationParams::new(
        OperationType::Encrypt,
        TargetType::File,
        source_file.clone(),
    );

    let result = operator.process(&encrypt_params, password).await;
    if result.success {
        println!("✓ Encryption successful: {}", result);
    } else {
        println!("✗ Encryption failed: {:?}", result.error);
        return Ok(());
    }

    // Example 2: Decrypt the file
    println!("\n=== File Decryption Example ===");
    let encrypted_file = encrypt_params.get_destination();
    let decrypt_params = OperationParams::new(
        OperationType::Decrypt,
        TargetType::File,
        encrypted_file,
    );

    let result = operator.process(&decrypt_params, password).await;
    if result.success {
        println!("✓ Decryption successful: {}", result);
        
        // Verify the decrypted content
        let decrypted_content = fs::read(&result.destination)?;
        let original_content = fs::read(&source_file)?;
        
        if decrypted_content == original_content {
            println!("✓ Content verification passed!");
        } else {
            println!("✗ Content verification failed!");
        }
    } else {
        println!("✗ Decryption failed: {:?}", result.error);
    }

    // Example 3: Encrypt with compression
    println!("\n=== File Encryption with Compression Example ===");
    let compress_file = temp_dir.path().join("large_example.txt");
    
    // Create a larger file that will benefit from compression
    let large_content = "This is a repeated line that should compress well.\n".repeat(1000);
    fs::write(&compress_file, large_content.as_bytes())?;
    
    let compress_params = OperationParams::new(
        OperationType::Encrypt,
        TargetType::File,
        compress_file.clone(),
    ).with_compression(true);

    let result = operator.process(&compress_params, password).await;
    if result.success {
        println!("✓ Compression + Encryption successful: {}", result);
        
        // Show compression benefit
        let original_size = fs::metadata(&compress_file)?.len();
        let compressed_encrypted_size = fs::metadata(&result.destination)?.len();
        let ratio = compressed_encrypted_size as f64 / original_size as f64;
        println!("  Original size: {} bytes", original_size);
        println!("  Compressed+Encrypted size: {} bytes", compressed_encrypted_size);
        println!("  Ratio: {:.2}", ratio);
    } else {
        println!("✗ Compression + Encryption failed: {:?}", result.error);
    }

    // Example 4: Directory encryption
    println!("\n=== Directory Encryption Example ===");
    let test_dir = temp_dir.path().join("test_directory");
    fs::create_dir(&test_dir)?;
    
    // Create some files in the directory
    fs::write(test_dir.join("file1.txt"), b"Content of file 1")?;
    fs::write(test_dir.join("file2.txt"), b"Content of file 2")?;
    
    let dir_params = OperationParams::new(
        OperationType::Encrypt,
        TargetType::Directory,
        test_dir.clone(),
    );

    let result = operator.process(&dir_params, password).await;
    if result.success {
        println!("✓ Directory encryption successful: {}", result);
    } else {
        println!("✗ Directory encryption failed: {:?}", result.error);
    }

    println!("\n=== Examples completed! ===");
    println!("Temporary files are in: {}", temp_dir.path().display());
    println!("Note: Temporary directory will be cleaned up when this program exits.");

    Ok(())
}
