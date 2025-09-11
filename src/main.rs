use clap::{Parser, Subcommand};
use sf_cli::{
    file_ops::FileOperator,
    models::{OperationParams, OperationType, TargetType},
    tui::App,
    watch::{FileWatcher, WatchConfig},
    ssh_keys::SshKeyDiscovery,
};
use std::path::PathBuf;

/// Secure file encryption CLI/TUI tool with password protection
#[derive(Parser)]
#[command(name = "sf-cli")]
#[command(about = "A secure file encryption tool with password protection")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the interactive TUI
    Tui,
    /// Encrypt a file or directory
    Encrypt {
        /// File or directory path to encrypt
        path: PathBuf,
        /// Output path (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Enable compression
        #[arg(short, long)]
        compress: bool,
        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Decrypt a file or directory
    Decrypt {
        /// File or directory path to decrypt
        path: PathBuf,
        /// Output path (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Enable compression/decompression
        #[arg(short, long)]
        compress: bool,
        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Watch a directory and automatically encrypt new files
    WatchEncrypt {
        /// Directory to watch for new files
        watch_dir: PathBuf,
        /// Target directory for encrypted files (optional, defaults to same directory)
        #[arg(short, long)]
        target_dir: Option<PathBuf>,
        /// Password for encryption (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
        /// Delete source files after encryption
        #[arg(short, long)]
        delete_source: bool,
        /// Enable compression
        #[arg(short, long)]
        compress: bool,
        /// File extensions to watch (comma-separated, e.g., "txt,doc")
        #[arg(short, long)]
        extensions: Option<String>,
        /// Process existing files in directory on startup
        #[arg(long)]
        process_existing: bool,
    },
    /// Watch a directory and automatically decrypt encrypted files
    WatchDecrypt {
        /// Directory to watch for encrypted files
        watch_dir: PathBuf,
        /// Target directory for decrypted files (optional, defaults to same directory)
        #[arg(short, long)]
        target_dir: Option<PathBuf>,
        /// Password for decryption (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
        /// Delete encrypted files after decryption
        #[arg(short, long)]
        delete_source: bool,
        /// Enable compression/decompression
        #[arg(short, long)]
        compress: bool,
        /// Process existing encrypted files in directory on startup
        #[arg(long)]
        process_existing: bool,
    },
    /// Encrypt a file or directory using hybrid encryption (public key + AES)
    HybridEncrypt {
        /// File or directory path to encrypt
        path: PathBuf,
        /// Output path (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Enable compression
        #[arg(short, long)]
        compress: bool,
        /// Public key file path (optional, will auto-discover from ~/.ssh if not provided)
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
    /// Decrypt a file or directory using hybrid encryption (private key + AES)
    HybridDecrypt {
        /// File or directory path to decrypt
        path: PathBuf,
        /// Output path (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Enable compression/decompression
        #[arg(short, long)]
        compress: bool,
        /// Private key file path (optional, will auto-discover from ~/.ssh if not provided)
        #[arg(long)]
        private_key: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Tui) | None => {
            // Default to TUI mode
            let mut app = App::new();
            app.run().await?;
        }
        Some(Commands::Encrypt { path, output, compress, password }) => {
            let password = get_password(password)?;
            let target_type = if path.is_dir() {
                TargetType::Directory
            } else {
                TargetType::File
            };

            let mut params = OperationParams::new(
                OperationType::Encrypt,
                target_type,
                path.clone(),
            ).with_compression(compress);

            if let Some(output) = output {
                params = params.with_destination(output);
            }

            let operator = FileOperator::new();
            let result = operator.process(&params, &password).await;

            if result.success {
                println!("{}", result);
            } else {
                eprintln!("Error: {}", result.error.unwrap_or_default());
                std::process::exit(1);
            }
        }
        Some(Commands::Decrypt { path, output, compress, password }) => {
            let password = get_password(password)?;
            let target_type = if path.to_string_lossy().ends_with(".sf") 
                || path.to_string_lossy().ends_with(".sf.gz") {
                // Assume it was a directory if it has .sf extension
                if path.to_string_lossy().contains("directory") {
                    TargetType::Directory
                } else {
                    TargetType::File
                }
            } else {
                TargetType::File
            };

            let mut params = OperationParams::new(
                OperationType::Decrypt,
                target_type,
                path.clone(),
            ).with_compression(compress);

            if let Some(output) = output {
                params = params.with_destination(output);
            }

            let operator = FileOperator::new();
            let result = operator.process(&params, &password).await;

            if result.success {
                println!("{}", result);
            } else {
                eprintln!("Error: {}", result.error.unwrap_or_default());
                std::process::exit(1);
            }
        }
        Some(Commands::WatchEncrypt { 
            watch_dir, 
            target_dir, 
            password, 
            delete_source, 
            compress, 
            extensions,
            process_existing 
        }) => {
            let password = get_password(password)?;
            
            let mut config = WatchConfig::new(
                watch_dir,
                OperationType::Encrypt,
                password,
            )
            .with_delete_source(delete_source)
            .with_compression(compress)
            .with_process_existing(process_existing);

            if let Some(target_dir) = target_dir {
                config = config.with_target_dir(target_dir);
            }

            if let Some(extensions_str) = extensions {
                let ext_list: Vec<String> = extensions_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                config = config.with_extensions(ext_list);
            }

            let watcher = FileWatcher::new(config);
            if let Err(e) = watcher.start().await {
                eprintln!("Watch error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::WatchDecrypt { 
            watch_dir, 
            target_dir, 
            password, 
            delete_source, 
            compress,
            process_existing 
        }) => {
            let password = get_password(password)?;
            
            let mut config = WatchConfig::new(
                watch_dir,
                OperationType::Decrypt,
                password,
            )
            .with_delete_source(delete_source)
            .with_compression(compress)
            .with_process_existing(process_existing);

            if let Some(target_dir) = target_dir {
                config = config.with_target_dir(target_dir);
            }

            let watcher = FileWatcher::new(config);
            if let Err(e) = watcher.start().await {
                eprintln!("Watch error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::HybridEncrypt { path, output, compress, public_key }) => {
            let target_type = if path.is_dir() {
                TargetType::Directory
            } else {
                TargetType::File
            };

            let mut params = OperationParams::new(
                OperationType::HybridEncrypt,
                target_type,
                path.clone(),
            ).with_compression(compress);

            if let Some(output) = output {
                params = params.with_destination(output);
            }

            if let Some(public_key) = public_key {
                params = params.with_public_key_path(public_key);
            }

            let operator = FileOperator::new();
            let result = operator.process(&params, "").await; // Empty password for hybrid mode

            if result.success {
                println!("{}", result);
            } else {
                eprintln!("Error: {}", result.error.unwrap_or_default());
                std::process::exit(1);
            }
        }
        Some(Commands::HybridDecrypt { path, output, compress, private_key }) => {
            let target_type = if path.to_string_lossy().ends_with(".hsf") {
                // Detect if it was a directory based on filename patterns
                if path.to_string_lossy().contains("directory") {
                    TargetType::Directory
                } else {
                    TargetType::File
                }
            } else {
                TargetType::File
            };

            let mut params = OperationParams::new(
                OperationType::HybridDecrypt,
                target_type,
                path.clone(),
            ).with_compression(compress);

            if let Some(output) = output {
                params = params.with_destination(output);
            }

            if let Some(private_key) = private_key {
                params = params.with_private_key_path(private_key);
            }

            let operator = FileOperator::new();
            let result = operator.process(&params, "").await; // Empty password for hybrid mode

            if result.success {
                println!("{}", result);
            } else {
                eprintln!("Error: {}", result.error.unwrap_or_default());
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// Get password from argument or prompt user
fn get_password(password: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    match password {
        Some(pwd) => Ok(pwd),
        None => {
            use std::io::{self, Write};
            print!("Enter password: ");
            io::stdout().flush()?;
            let mut password = String::new();
            io::stdin().read_line(&mut password)?;
            Ok(password.trim().to_string())
        }
    }
}
