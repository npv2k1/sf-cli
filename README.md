# SF-CLI - Secure File Encryption CLI/TUI Tool

A secure file encryption tool with password protection, supporting both command-line and terminal user interface modes.

## Features

- 🔐 **Secure Encryption**: AES-256-GCM encryption with Argon2 key derivation
- 📁 **File & Directory Support**: Encrypt/decrypt individual files or entire directories
- 🗜️ **Compression**: Built-in gzip compression for space efficiency
- 📊 **Progress Tracking**: Real-time progress bars for large file operations
- 🖥️ **Dual Interface**: Both CLI and interactive TUI modes
- 🔒 **Memory Safety**: Secure key handling with automatic zeroization
- ⚡ **High Performance**: Optimized for large files with streaming operations
- 🧪 **Well Tested**: Comprehensive unit and integration tests

## Installation

### From Source

```bash
git clone https://github.com/npv2k1/sf-cli.git
cd sf-cli
cargo build --release
```

### From Releases

Download the latest binary from the [Releases](https://github.com/npv2k1/sf-cli/releases) page.

## Usage

### Command Line Interface

```bash
# Show help
./sf-cli --help

# Encrypt a file with password prompt
./sf-cli encrypt secret.txt

# Encrypt with compression and custom output
./sf-cli encrypt data.txt -c -o data.sf.gz

# Encrypt with password from command line (not recommended for production)
./sf-cli encrypt file.txt -p mypassword

# Decrypt a file
./sf-cli decrypt secret.sf

# Decrypt with compression
./sf-cli decrypt data.sf.gz -c

# Encrypt an entire directory
./sf-cli encrypt my_folder/

# Decrypt a directory
./sf-cli decrypt my_folder.sf
```

### Terminal User Interface (TUI)

Start the interactive mode:

```bash
./sf-cli tui
# or simply
./sf-cli
```

#### TUI Controls:
- `1` - Encrypt file/directory
- `2` - Decrypt file/directory  
- `Enter` - Confirm input
- `Esc` - Return to main menu
- `q` - Quit application

## Security Features

### Encryption
- **Algorithm**: AES-256-GCM (Authenticated encryption)
- **Key Derivation**: Argon2 with random salt
- **Random Nonce**: Generated for each encryption operation
- **Memory Security**: Keys are zeroized after use

### File Format
Encrypted files contain:
1. **Salt** (32 bytes): Random salt for key derivation
2. **Nonce** (12 bytes): Random nonce for AES-GCM
3. **Ciphertext**: Encrypted data with authentication tag

### Compression
- **Algorithm**: gzip compression
- **When Applied**: Before encryption for maximum security
- **Benefits**: Significant space savings for repetitive data

## Examples

### Basic File Encryption

```bash
# Create a test file
echo "This is sensitive data" > secret.txt

# Encrypt it
./sf-cli encrypt secret.txt
# Output: ✓ Encrypt secret.txt -> secret.sf (83 bytes)

# Decrypt it
./sf-cli decrypt secret.sf  
# Output: ✓ Decrypt secret.sf -> secret (23 bytes)
```

### Compression Example

```bash
# Create a large repetitive file
python3 -c "print('repeated data ' * 10000)" > large.txt

# Encrypt with compression
./sf-cli encrypt large.txt -c
# Achieves 95%+ compression ratio on repetitive data
```

### Directory Encryption

```bash
# Create a directory with files
mkdir my_docs
echo "Document 1" > my_docs/doc1.txt
echo "Document 2" > my_docs/doc2.txt

# Encrypt the entire directory
./sf-cli encrypt my_docs/
# Output: ✓ Encrypt my_docs -> my_docs.sf (218 bytes, compressed)

# Decrypt the directory
./sf-cli decrypt my_docs.sf
# Restores the complete directory structure
```

## Performance

- **Large Files**: Streaming operations with progress tracking
- **Memory Usage**: Efficient buffering (64KB default buffer size)
- **Compression Ratios**: Up to 99%+ for repetitive data
- **Speed**: Optimized Rust implementation

## Project Structure

```
sf-cli/
├── src/
│   ├── crypto.rs          # Encryption/decryption engine
│   ├── compression.rs     # Compression utilities
│   ├── file_ops.rs        # File and directory operations
│   ├── progress.rs        # Progress tracking
│   ├── models.rs          # Data structures
│   ├── tui.rs             # Terminal user interface
│   ├── lib.rs             # Library root
│   └── main.rs            # CLI application
├── tests/                 # Integration tests
├── examples/              # Usage examples
└── docs/                  # Documentation
```

## Development

### Prerequisites

- Rust 1.70 or later

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Running Examples

```bash
cargo run --example basic_usage
```

### Running Clippy (Linter)

```bash
cargo clippy -- -D warnings
```

### Formatting Code

```bash
cargo fmt
```

## Security Considerations

- **Password Strength**: Use strong, unique passwords
- **Key Storage**: Passwords are not stored; enter each time
- **Temp Files**: No temporary files created during encryption
- **Memory**: Sensitive data is zeroized after use
- **Verification**: Always verify decrypted data integrity

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Changelog

### v0.1.0
- Initial release
- AES-256-GCM encryption with Argon2 key derivation
- File and directory encryption/decryption
- gzip compression support
- CLI and TUI interfaces
- Progress tracking for large files
- Comprehensive test suite
