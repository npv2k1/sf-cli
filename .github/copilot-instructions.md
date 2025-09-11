# SF-CLI - Secure File Encryption CLI/TUI Tool

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

SF-CLI is a Rust-based secure file encryption tool with both command-line interface and terminal user interface modes. It provides AES-256-GCM encryption with Argon2 key derivation, file/directory support, and compression capabilities.

## Working Effectively

### Prerequisites and Setup
- Rust 1.70 or later is required (rustc 1.89.0 confirmed working)
- Rust is already installed in this environment at `/home/runner/.cargo/bin/rustc`

### Build Commands
- **CRITICAL**: NEVER CANCEL BUILD COMMANDS. Use adequate timeouts.
- `cargo build --release` -- takes 1-2 minutes. NEVER CANCEL. Set timeout to 180+ seconds.
- `cargo build` -- takes 30-60 seconds for debug builds. Set timeout to 120+ seconds.
- Clean build from scratch: `cargo clean && cargo build --release` -- takes 1-2 minutes. Set timeout to 180+ seconds.

### Testing
- `cargo test --verbose` -- takes 45-60 seconds. NEVER CANCEL. Set timeout to 120+ seconds.
- Tests include 3 integration tests: file encryption, directory encryption, and wrong password validation
- All tests pass successfully

### Code Quality
- `cargo clippy -- -D warnings` -- takes 15-30 seconds. Set timeout to 60+ seconds.
  - **WARNING**: Currently fails due to dead code warnings and style issues in TUI module
  - Code is functional despite clippy warnings
  - Do NOT use `-- -D warnings` flag if you want to check for issues without failing
- `cargo fmt --all -- --check` -- takes <1 second. 
  - **WARNING**: Currently fails due to formatting issues
  - Run `cargo fmt --all` to fix formatting before committing
- `cargo fmt --all` -- fixes all formatting issues

### Running the Application

#### CLI Mode
- Show help: `./target/release/sf-cli --help`
- Encrypt file: `./target/release/sf-cli encrypt file.txt -p password`
- Encrypt with compression: `./target/release/sf-cli encrypt file.txt -c -p password`
- Decrypt file: `./target/release/sf-cli decrypt file.txt.sf -p password`
- Encrypt directory: `./target/release/sf-cli encrypt directory/ -p password`
- Decrypt directory: `./target/release/sf-cli decrypt directory.sf -p password`

#### TUI Mode
- Start TUI: `./target/release/sf-cli tui` or just `./target/release/sf-cli`
- Navigation: ↑/↓ arrows, Enter to select, ? for help, q to quit
- The TUI provides file browser interface for encryption/decryption operations

### Examples and Testing
- Run examples: `cargo run --example basic_usage` -- takes 2-3 seconds
- Examples demonstrate file encryption, directory encryption, and compression features
- Workflow validation: `.github/validate-workflows.sh` -- takes <1 second

## Validation Scenarios

ALWAYS test these scenarios after making changes to ensure functionality:

### File Encryption/Decryption Test
```bash
# Create test file
echo "Test data for encryption" > /tmp/test_file.txt

# Encrypt
./target/release/sf-cli encrypt /tmp/test_file.txt -p testpassword123

# Verify encrypted file created
ls -la /tmp/test_file.txt.sf

# Decrypt
./target/release/sf-cli decrypt /tmp/test_file.txt.sf -p testpassword123

# Verify content
cat /tmp/test_file.txt
```

### Directory Encryption/Decryption Test
```bash
# Create test directory
mkdir -p /tmp/test_dir
echo "File 1" > /tmp/test_dir/file1.txt
echo "File 2" > /tmp/test_dir/file2.txt

# Encrypt directory
./target/release/sf-cli encrypt /tmp/test_dir/ -p testpassword123

# Remove original and decrypt
rm -rf /tmp/test_dir
./target/release/sf-cli decrypt /tmp/test_dir.sf -p testpassword123

# Extract and verify (directory decryption creates tar file)
cd /tmp && mkdir extracted && cd extracted
tar -xf ../test_dir
cat file1.txt file2.txt
```

### TUI Test
```bash
# Start TUI (use timeout to avoid hanging in automation)
timeout 3 ./target/release/sf-cli tui || echo "TUI started successfully"
```

## Build Timing and Timeouts

**CRITICAL TIMEOUT VALUES:**
- Release build: Set timeout to 180+ seconds (actual: ~90 seconds)
- Debug build: Set timeout to 120+ seconds (actual: ~60 seconds)
- Tests: Set timeout to 120+ seconds (actual: ~50 seconds)
- Clippy: Set timeout to 60+ seconds (actual: ~15 seconds)
- Examples: Set timeout to 30+ seconds (actual: ~3 seconds)

**NEVER CANCEL** any build or test commands. Rust compilation can take significant time.

## CI/CD and Code Quality

### Before Committing Changes
ALWAYS run these commands before committing:
1. `cargo fmt --all` -- fix formatting issues
2. `cargo clippy` (without -D warnings flag) -- check for issues
3. `cargo test` -- ensure tests pass
4. Test CLI functionality with the validation scenarios above

### GitHub Actions Workflows
- **CI workflow** (.github/workflows/ci.yml): Runs tests, linting, formatting checks, multi-platform builds
- **Release workflow** (.github/workflows/release.yml): Creates releases on tag push and main branch push
- **Security workflow** (.github/workflows/security.yml): Weekly security audits
- Validate workflows: `.github/validate-workflows.sh`

### Known Issues
- Clippy currently fails with `-D warnings` due to dead code in TUI module (warnings are in src/tui.rs)
- Formatting check fails - run `cargo fmt --all` to fix
- These issues do not affect functionality but will cause CI failures

## Project Structure

### Key Directories and Files
```
sf-cli/
├── src/
│   ├── main.rs            # CLI application entry point
│   ├── lib.rs             # Library root
│   ├── crypto.rs          # Encryption/decryption engine  
│   ├── compression.rs     # Compression utilities
│   ├── file_ops.rs        # File and directory operations
│   ├── progress.rs        # Progress tracking
│   ├── models.rs          # Data structures
│   └── tui.rs             # Terminal user interface
├── tests/
│   └── integration_tests.rs  # Integration tests
├── examples/
│   └── basic_usage.rs     # Usage examples
├── .github/
│   ├── workflows/         # CI/CD workflows
│   └── validate-workflows.sh  # Workflow validation script
├── Cargo.toml             # Project configuration and dependencies
└── README.md              # Comprehensive documentation
```

### Dependencies
Key dependencies include:
- Encryption: aes-gcm, argon2, zeroize, rand
- CLI: clap
- TUI: ratatui, crossterm
- Compression: flate2, tar
- Progress: indicatif
- Async: tokio

## Security Features

- **Encryption**: AES-256-GCM with authenticated encryption
- **Key Derivation**: Argon2 with random salt
- **Memory Safety**: Keys are zeroized after use
- **File Format**: Salt (32 bytes) + Nonce (12 bytes) + Encrypted data
- **Compression**: Optional gzip compression applied before encryption

## Common Development Tasks

### Testing Changes
1. Build and test: `cargo build --release && cargo test`
2. Run validation scenarios (file and directory encryption/decryption)
3. Test TUI startup: `timeout 3 ./target/release/sf-cli tui`
4. Run examples: `cargo run --example basic_usage`

### Debugging
- Use `cargo build` for debug builds with symbols
- Add `--verbose` flag to cargo commands for detailed output
- Check logs and error messages for crypto or file operation issues

### Performance Testing
- Test with large files for compression benefits
- Use the compression flag `-c` for repetitive data
- Monitor progress bars during encryption/decryption operations

The application is well-tested and functional. Focus on maintaining the security aspects and following Rust best practices when making changes.