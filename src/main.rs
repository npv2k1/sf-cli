use clap::{Parser, Subcommand};
use sf_cli::{
    file_ops::FileOperator,
    models::{OperationParams, OperationType, TargetType},
    tui::App,
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
