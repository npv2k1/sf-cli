# SF-CLI - Secure File Encryption CLI/TUI Tool

[![CI](https://github.com/npv2k1/sf-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/npv2k1/sf-cli/actions/workflows/ci.yml)
[![Release](https://github.com/npv2k1/sf-cli/actions/workflows/release.yml/badge.svg)](https://github.com/npv2k1/sf-cli/actions/workflows/release.yml)
[![Security](https://github.com/npv2k1/sf-cli/actions/workflows/security.yml/badge.svg)](https://github.com/npv2k1/sf-cli/actions/workflows/security.yml)

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
- 👀 **Watch Mode**: Automatic encryption/decryption of new files in monitored directories
- 🎯 **Smart Filtering**: Process only specific file extensions or patterns
- 🗑️ **Auto-cleanup**: Optionally delete source files after processing

## Installation

### From Source

```bash
git clone https://github.com/npv2k1/sf-cli.git
cd sf-cli
cargo build --release
```

### From Releases

Download the latest binary from the [Releases](https://github.com/npv2k1/sf-cli/releases) page.

- **Latest Development Build**: Automatically updated with every push to main branch
- **Stable Releases**: Created when version tags (e.g., v1.0.0) are pushed

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

### Watch Mode (Auto-encrypt/decrypt)

Watch mode monitors directories for file changes and automatically processes them:

```bash
# Watch directory and auto-encrypt new files
./sf-cli watch-encrypt /path/to/source --password mypass

# Watch with target directory and delete source files
./sf-cli watch-encrypt /path/to/source -t /path/to/encrypted -d --password mypass

# Watch with file extension filtering (only .txt and .doc files)
./sf-cli watch-encrypt /path/to/source -e "txt,doc" --password mypass

# Process existing files on startup
./sf-cli watch-encrypt /path/to/source --process-existing --password mypass

# Watch directory and auto-decrypt encrypted files
./sf-cli watch-decrypt /path/to/encrypted -t /path/to/decrypted --password mypass

# Watch decrypt with compression and delete source
./sf-cli watch-decrypt /path/to/encrypted -c -d --password mypass
```

#### Watch Mode Features:
- **Auto-encryption**: Monitors a directory and encrypts new files automatically
- **Auto-decryption**: Monitors a directory and decrypts encrypted files automatically  
- **Password once**: Set password once at startup, no need to re-enter
- **Target directory**: Specify different output directory (defaults to same directory)
- **Delete source**: Optionally delete source files after processing
- **Extension filtering**: Only process files with specific extensions
- **Process existing**: Process files that already exist in the directory
- **Compression support**: Enable compression for encrypted files
- **Live monitoring**: Real-time file system watching with debouncing

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

### Watch Mode Examples

```bash
# Setup watch directories
mkdir -p /tmp/documents /tmp/encrypted /tmp/decrypted

# Start watching for new documents to encrypt
./sf-cli watch-encrypt /tmp/documents -t /tmp/encrypted -p mypassword &

# Add files to watch - they will be automatically encrypted
echo "Confidential report" > /tmp/documents/report.txt
echo "Meeting notes" > /tmp/documents/notes.txt
# Files automatically encrypted to /tmp/encrypted/

# Start watching encrypted directory for auto-decryption
./sf-cli watch-decrypt /tmp/encrypted -t /tmp/decrypted -p mypassword &

# Any new .sf files in /tmp/encrypted will be auto-decrypted to /tmp/decrypted/
```

### Advanced Watch Usage

```bash
# Watch only specific file types and delete originals
./sf-cli watch-encrypt /home/user/documents \
  --target-dir /backup/encrypted \
  --extensions "txt,doc,pdf" \
  --delete-source \
  --process-existing \
  --password mypassword

# Watch with compression
./sf-cli watch-encrypt /data/logs \
  --compress \
  --delete-source \
  --password logpass
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

## CI/CD

This project uses GitHub Actions for continuous integration and deployment:

### Workflows

- **CI**: Runs on every push and pull request to main
  - Tests, linting (clippy), formatting checks
  - Multi-platform builds (Linux, Windows, macOS)

- **Release**: Automatically creates releases
  - **Latest Development Builds**: Created on every push to main branch as pre-release
  - **Stable Releases**: Created when version tags (v*.*.*)  are pushed
  - Multi-platform binaries included in all releases

- **Security**: Weekly security audits and checks on main branch

### Release Types

1. **Development Releases** (automatic):
   - Triggered by pushes to main branch
   - Tagged as "latest" (replaces previous latest)
   - Marked as pre-release
   - Contains binaries for Linux x86_64, Windows x86_64, macOS x86_64

2. **Stable Releases** (manual):
   - Triggered by pushing version tags (e.g., `git tag v1.0.0 && git push origin v1.0.0`)
   - Tagged with the version number
   - Not marked as pre-release
   - Contains binaries for all platforms

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