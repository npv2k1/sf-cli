//! File system watching for automatic encryption/decryption

use crate::{
    file_ops::FileOperator,
    models::{OperationParams, OperationType, TargetType},
};
use anyhow::{anyhow, Result};
use notify::{
    event::{CreateKind, EventKind, ModifyKind},
    Event, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};
use thiserror::Error;

/// Watch mode errors
#[derive(Error, Debug)]
pub enum WatchError {
    #[error("Watch error: {0}")]
    NotifyError(#[from] notify::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Channel error: {0}")]
    ChannelError(String),
    #[error("Invalid watch configuration: {0}")]
    InvalidConfig(String),
}

/// Watch mode configuration
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Directory to watch
    pub watch_dir: PathBuf,
    /// Target directory for processed files (None = same as source)
    pub target_dir: Option<PathBuf>,
    /// Operation type (encrypt or decrypt)
    pub operation: OperationType,
    /// Password for operations
    pub password: String,
    /// Whether to delete source files after processing
    pub delete_source: bool,
    /// Whether to enable compression
    pub compress: bool,
    /// File extensions to watch (None = all files)
    pub watch_extensions: Option<Vec<String>>,
    /// Whether to process existing files on startup
    pub process_existing: bool,
    /// Debounce delay in milliseconds
    pub debounce_ms: u64,
}

impl WatchConfig {
    /// Create new watch configuration
    pub fn new(
        watch_dir: PathBuf,
        operation: OperationType,
        password: String,
    ) -> Self {
        Self {
            watch_dir,
            target_dir: None,
            operation,
            password,
            delete_source: false,
            compress: false,
            watch_extensions: None,
            process_existing: false,
            debounce_ms: 1000, // 1 second debounce
        }
    }

    /// Set target directory
    pub fn with_target_dir(mut self, target_dir: PathBuf) -> Self {
        self.target_dir = Some(target_dir);
        self
    }

    /// Enable source file deletion
    pub fn with_delete_source(mut self, delete_source: bool) -> Self {
        self.delete_source = delete_source;
        self
    }

    /// Enable compression
    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Set file extensions to watch
    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.watch_extensions = Some(extensions);
        self
    }

    /// Enable processing existing files
    pub fn with_process_existing(mut self, process_existing: bool) -> Self {
        self.process_existing = process_existing;
        self
    }

    /// Set debounce delay
    pub fn with_debounce_ms(mut self, debounce_ms: u64) -> Self {
        self.debounce_ms = debounce_ms;
        self
    }

    /// Check if file should be processed based on extension filter
    pub fn should_process_file(&self, path: &Path) -> bool {
        match &self.watch_extensions {
            Some(extensions) => {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    extensions.iter().any(|e| e.eq_ignore_ascii_case(ext))
                } else {
                    false
                }
            }
            None => true, // Process all files if no filter specified
        }
    }

    /// Check if file should be processed based on operation type
    pub fn should_process_by_operation(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        match self.operation {
            OperationType::Encrypt => {
                // For encryption, avoid processing already encrypted files
                !path_str.ends_with(".sf") && !path_str.ends_with(".sf.gz")
            }
            OperationType::Decrypt => {
                // For decryption, only process encrypted files
                path_str.ends_with(".sf") || path_str.ends_with(".sf.gz")
            }
        }
    }
}

/// File system watcher
pub struct FileWatcher {
    config: WatchConfig,
    operator: FileOperator,
}

impl FileWatcher {
    /// Create new file watcher
    pub fn new(config: WatchConfig) -> Self {
        Self {
            config,
            operator: FileOperator::new(),
        }
    }

    /// Get reference to the configuration
    pub fn config(&self) -> &WatchConfig {
        &self.config
    }

    /// Start watching for file changes
    pub async fn start(&self) -> Result<()> {
        // Validate watch directory exists
        if !self.config.watch_dir.exists() {
            return Err(anyhow!(
                "Watch directory does not exist: {}",
                self.config.watch_dir.display()
            ));
        }

        // Create target directory if specified
        if let Some(ref target_dir) = self.config.target_dir {
            std::fs::create_dir_all(target_dir)?;
        }

        println!(
            "🔍 Starting {} watcher on directory: {}",
            match self.config.operation {
                OperationType::Encrypt => "encryption",
                OperationType::Decrypt => "decryption",
            },
            self.config.watch_dir.display()
        );

        if let Some(ref target_dir) = self.config.target_dir {
            println!("📁 Target directory: {}", target_dir.display());
        }

        println!("🗑️ Delete source files: {}", self.config.delete_source);
        println!("🗜️ Compression: {}", self.config.compress);

        // Process existing files if requested
        if self.config.process_existing {
            println!("📂 Processing existing files...");
            self.process_existing_files().await?;
        }

        // Set up file system watcher
        let (tx, rx): (Sender<notify::Result<Event>>, Receiver<notify::Result<Event>>) =
            mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                if let Err(e) = tx.send(res) {
                    eprintln!("Failed to send watch event: {}", e);
                }
            },
            notify::Config::default(),
        )?;

        watcher.watch(&self.config.watch_dir, RecursiveMode::Recursive)?;

        println!("👀 Watching for file changes... Press Ctrl+C to stop.");

        // Process events
        self.event_loop(rx).await?;

        Ok(())
    }

    /// Process existing files in the watch directory
    async fn process_existing_files(&self) -> Result<()> {
        fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    collect_files(&path, files)?;
                } else {
                    files.push(path);
                }
            }
            Ok(())
        }

        let mut files = Vec::new();
        collect_files(&self.config.watch_dir, &mut files)?;

        for file in files {
            if self.should_process_file(&file) {
                self.process_file(&file).await?;
            }
        }

        Ok(())
    }

    /// Main event processing loop
    async fn event_loop(&self, rx: Receiver<notify::Result<Event>>) -> Result<()> {
        let mut debounce_map = std::collections::HashMap::new();

        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(event)) => {
                    self.handle_event(event, &mut debounce_map).await?;
                }
                Ok(Err(e)) => {
                    eprintln!("Watch error: {}", e);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Check for debounced files to process
                    self.process_debounced_files(&mut debounce_map).await?;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    println!("Watch channel disconnected, stopping...");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single file system event
    async fn handle_event(
        &self,
        event: Event,
        debounce_map: &mut std::collections::HashMap<PathBuf, std::time::Instant>,
    ) -> Result<()> {
        match event.kind {
            EventKind::Create(CreateKind::File) | EventKind::Modify(ModifyKind::Data(_)) => {
                for path in event.paths {
                    if path.is_file() && self.should_process_file(&path) {
                        // Add to debounce map
                        debounce_map.insert(path, std::time::Instant::now());
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Process files that have been debounced
    async fn process_debounced_files(
        &self,
        debounce_map: &mut std::collections::HashMap<PathBuf, std::time::Instant>,
    ) -> Result<()> {
        let now = std::time::Instant::now();
        let debounce_duration = Duration::from_millis(self.config.debounce_ms);

        let mut files_to_process = Vec::new();
        let mut files_to_remove = Vec::new();

        for (path, timestamp) in debounce_map.iter() {
            if now.duration_since(*timestamp) >= debounce_duration {
                if path.exists() {
                    files_to_process.push(path.clone());
                }
                files_to_remove.push(path.clone());
            }
        }

        // Remove processed files from debounce map
        for path in files_to_remove {
            debounce_map.remove(&path);
        }

        // Process files
        for path in files_to_process {
            if let Err(e) = self.process_file(&path).await {
                eprintln!("Failed to process file {}: {}", path.display(), e);
            }
        }

        Ok(())
    }

    /// Check if file should be processed
    fn should_process_file(&self, path: &Path) -> bool {
        // Skip if not a regular file
        if !path.is_file() {
            return false;
        }

        // Skip hidden files
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with('.'))
            .unwrap_or(false)
        {
            return false;
        }

        // Check extension filter
        if !self.config.should_process_file(path) {
            return false;
        }

        // Check operation-specific filter
        if !self.config.should_process_by_operation(path) {
            return false;
        }

        true
    }

    /// Process a single file
    async fn process_file(&self, source_path: &Path) -> Result<()> {
        // Determine target path
        let target_path = if let Some(ref target_dir) = self.config.target_dir {
            let relative_path = source_path
                .strip_prefix(&self.config.watch_dir)
                .unwrap_or(source_path.file_name().unwrap().as_ref());
            target_dir.join(relative_path)
        } else {
            source_path.to_path_buf()
        };

        // Create operation parameters
        let mut params = OperationParams::new(
            self.config.operation.clone(),
            TargetType::File,
            source_path.to_path_buf(),
        )
        .with_compression(self.config.compress)
        .with_delete_source(self.config.delete_source)
        .with_progress(false); // Disable progress for watch mode

        // Set destination if needed
        if self.config.target_dir.is_some() {
            let destination = match self.config.operation {
                OperationType::Encrypt => {
                    if self.config.compress {
                        target_path.with_extension("sf.gz")
                    } else {
                        target_path.with_extension("sf")
                    }
                }
                OperationType::Decrypt => {
                    let path_str = target_path.to_string_lossy();
                    if path_str.ends_with(".sf.gz") {
                        PathBuf::from(path_str.trim_end_matches(".sf.gz"))
                    } else if path_str.ends_with(".sf") {
                        PathBuf::from(path_str.trim_end_matches(".sf"))
                    } else {
                        target_path.with_extension("decrypted")
                    }
                }
            };
            params = params.with_destination(destination);
        }

        // Ensure target directory exists
        if let Some(destination) = &params.destination {
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }

        println!(
            "🔄 Processing file: {} -> {}",
            source_path.display(),
            params.get_destination().display()
        );

        // Process the file
        let result = self.operator.process(&params, &self.config.password).await;

        if result.success {
            println!("✅ {}", result);
        } else {
            eprintln!("❌ {}", result);
            return Err(anyhow!(
                "Failed to process file: {}",
                result.error.unwrap_or_default()
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_watch_config_creation() {
        let config = WatchConfig::new(
            PathBuf::from("/tmp/watch"),
            OperationType::Encrypt,
            "password123".to_string(),
        );

        assert_eq!(config.operation, OperationType::Encrypt);
        assert_eq!(config.password, "password123");
        assert!(!config.delete_source);
        assert!(!config.compress);
    }

    #[tokio::test]
    async fn test_should_process_file() {
        let config = WatchConfig::new(
            PathBuf::from("/tmp"),
            OperationType::Encrypt,
            "password".to_string(),
        );

        // Should process regular files
        assert!(config.should_process_by_operation(Path::new("test.txt")));
        
        // Should not process already encrypted files for encryption
        assert!(!config.should_process_by_operation(Path::new("test.sf")));
        assert!(!config.should_process_by_operation(Path::new("test.sf.gz")));

        // For decrypt mode
        let decrypt_config = WatchConfig::new(
            PathBuf::from("/tmp"),
            OperationType::Decrypt,
            "password".to_string(),
        );

        // Should process encrypted files
        assert!(decrypt_config.should_process_by_operation(Path::new("test.sf")));
        assert!(decrypt_config.should_process_by_operation(Path::new("test.sf.gz")));
        
        // Should not process regular files for decryption
        assert!(!decrypt_config.should_process_by_operation(Path::new("test.txt")));
    }

    #[tokio::test]
    async fn test_extension_filtering() {
        let config = WatchConfig::new(
            PathBuf::from("/tmp"),
            OperationType::Encrypt,
            "password".to_string(),
        ).with_extensions(vec!["txt".to_string(), "doc".to_string()]);

        // Should process specified extensions
        assert!(config.should_process_file(Path::new("test.txt")));
        assert!(config.should_process_file(Path::new("document.doc")));
        
        // Should not process other extensions
        assert!(!config.should_process_file(Path::new("image.jpg")));
        assert!(!config.should_process_file(Path::new("video.mp4")));
    }
}