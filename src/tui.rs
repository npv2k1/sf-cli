//! Terminal User Interface for file encryption operations

use crate::{
    file_ops::FileOperator,
    models::{OperationParams, OperationType, TargetType},
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::{
    fs, io,
    path::PathBuf,
    collections::HashMap,
};

/// File entry for display
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_directory: bool,
    pub is_encrypted: bool,
    pub size: u64,
}

impl FileEntry {
    pub fn new(path: PathBuf) -> io::Result<Self> {
        let metadata = fs::metadata(&path)?;
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        
        let is_directory = metadata.is_dir();
        let is_encrypted = if !is_directory {
            name.ends_with(".sf") || name.ends_with(".sf.gz")
        } else {
            false
        };

        Ok(Self {
            name,
            path,
            is_directory,
            is_encrypted,
            size: metadata.len(),
        })
    }
}

/// Application settings
#[derive(Debug, Clone)]
pub struct AppSettings {
    pub global_password: Option<String>,
    pub use_global_password: bool,
    pub default_compression: bool,
    pub delete_after_operation: bool,
    pub verify_checksums: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            global_password: None,
            use_global_password: false,
            default_compression: false,
            delete_after_operation: false,
            verify_checksums: true,
        }
    }
}

/// TUI Application state
pub struct App {
    /// File operator
    file_operator: FileOperator,
    /// Current input text
    input: String,
    /// Current screen mode
    mode: AppMode,
    /// Status message
    status: String,
    /// Whether to quit the application
    should_quit: bool,
    /// Current directory
    current_dir: PathBuf,
    /// Files in current directory
    files: Vec<FileEntry>,
    /// File list state for navigation
    file_list_state: ListState,
    /// Search query
    search_query: String,
    /// Application settings
    settings: AppSettings,
    /// Selected file indices (for multi-select)
    selected_files: HashMap<usize, bool>,
    /// Current operation progress
    operation_progress: Option<f64>,
}

/// Confirmation action type
#[derive(Debug, Clone, PartialEq)]
enum ConfirmAction {
    DeleteFiles,
    OverwriteFile,
    ClearSettings,
}

/// Application modes
#[derive(Debug, Clone, PartialEq)]
enum AppMode {
    /// File browser view
    Browser,
    /// Settings screen
    Settings,
    /// Search mode
    Search,
    /// Input password
    InputPassword { 
        operation: OperationType, 
        files: Vec<PathBuf>, 
        compress: bool 
    },
    /// Processing files
    Processing {
        operation: OperationType,
        current_file: String,
        progress: f64,
    },
    /// Help screen
    Help,
    /// Confirmation dialog
    Confirm {
        message: String,
        action: ConfirmAction,
    },
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Create a new TUI application
    pub fn new() -> Self {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut app = Self {
            file_operator: FileOperator::new(),
            input: String::new(),
            mode: AppMode::Browser,
            status: "Ready - Navigate with ↑/↓, Enter to select, ? for help".to_string(),
            should_quit: false,
            current_dir: current_dir.clone(),
            files: Vec::new(),
            file_list_state: ListState::default(),
            search_query: String::new(),
            settings: AppSettings::default(),
            selected_files: HashMap::new(),
            operation_progress: None,
        };
        
        app.refresh_file_list();
        app
    }

    /// Refresh the file list for current directory
    fn refresh_file_list(&mut self) {
        self.files.clear();
        self.selected_files.clear();
        
        // Add parent directory entry if not at root
        if let Some(parent) = self.current_dir.parent() {
            self.files.push(FileEntry {
                name: "..".to_string(),
                path: parent.to_path_buf(),
                is_directory: true,
                is_encrypted: false,
                size: 0,
            });
        }

        // Read directory contents
        if let Ok(entries) = fs::read_dir(&self.current_dir) {
            let mut file_entries: Vec<FileEntry> = entries
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    FileEntry::new(entry.path()).ok()
                })
                .collect();

            // Sort: directories first, then by name
            file_entries.sort_by(|a, b| {
                match (a.is_directory, b.is_directory) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a.name.cmp(&b.name),
                }
            });

            self.files.extend(file_entries);
        }

        // Reset selection to first item
        if !self.files.is_empty() {
            self.file_list_state.select(Some(0));
        }
    }

    /// Get selected file entries
    fn get_selected_files(&self) -> Vec<&FileEntry> {
        if self.selected_files.is_empty() {
            // If no files are explicitly selected, use the currently highlighted file
            if let Some(selected) = self.file_list_state.selected() {
                if let Some(file) = self.files.get(selected) {
                    return vec![file];
                }
            }
            return vec![];
        }

        self.selected_files
            .keys()
            .filter_map(|&index| self.files.get(index))
            .collect()
    }

    /// Toggle selection of current file
    fn toggle_selection(&mut self) {
        if let Some(selected) = self.file_list_state.selected() {
            if let Some(file) = self.files.get(selected) {
                if !file.is_directory || file.name != ".." {
                    let is_selected = self.selected_files.get(&selected).unwrap_or(&false);
                    if *is_selected {
                        self.selected_files.remove(&selected);
                    } else {
                        self.selected_files.insert(selected, true);
                    }
                }
            }
        }
    }

    /// Navigate to directory
    fn navigate_to(&mut self, path: PathBuf) {
        if path.is_dir() {
            self.current_dir = path;
            self.refresh_file_list();
        }
    }

    /// Apply search filter
    fn filter_files(&self) -> Vec<(usize, &FileEntry)> {
        if self.search_query.is_empty() {
            return self.files.iter().enumerate().collect();
        }

        self.files
            .iter()
            .enumerate()
            .filter(|(_, file)| {
                file.name.to_lowercase().contains(&self.search_query.to_lowercase())
            })
            .collect()
    }

    /// Run the TUI application
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = self.run_app(&mut terminal).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    /// Main application loop
    async fn run_app<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            terminal.draw(|f| self.ui(f))?;

            if self.should_quit {
                break;
            }

            if let Event::Key(key) = event::read()? {
                self.handle_key_event(key.code).await;
            }
        }
        Ok(())
    }

    /// Handle key events based on current mode
    async fn handle_key_event(&mut self, key: KeyCode) {
        match &self.mode.clone() {
            AppMode::Browser => self.handle_browser_keys(key).await,
            AppMode::Search => self.handle_search_keys(key),
            AppMode::Settings => self.handle_settings_keys(key),
            AppMode::InputPassword { .. } => self.handle_password_input_keys(key).await,
            AppMode::Processing { .. } => {
                // Processing mode - only allow quit
                if let KeyCode::Esc = key {
                    self.mode = AppMode::Browser;
                }
            }
            AppMode::Help => self.handle_help_keys(key),
            AppMode::Confirm { .. } => self.handle_confirm_keys(key),
        }
    }

    /// Handle keys in browser mode
    async fn handle_browser_keys(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Char('?') => {
                self.mode = AppMode::Help;
            }
            KeyCode::Char('/') => {
                self.mode = AppMode::Search;
                self.search_query.clear();
                self.input.clear();
                self.status = "Search: Type to filter files, Esc to cancel".to_string();
            }
            KeyCode::Char('s') => {
                self.mode = AppMode::Settings;
                self.status = "Settings - Use ↑/↓ to navigate, Enter to toggle".to_string();
            }
            KeyCode::Up => {
                let selected = self.file_list_state.selected().unwrap_or(0);
                if selected > 0 {
                    self.file_list_state.select(Some(selected - 1));
                }
            }
            KeyCode::Down => {
                let selected = self.file_list_state.selected().unwrap_or(0);
                if selected < self.files.len().saturating_sub(1) {
                    self.file_list_state.select(Some(selected + 1));
                }
            }
            KeyCode::Enter => {
                if let Some(selected) = self.file_list_state.selected() {
                    if let Some(file) = self.files.get(selected) {
                        if file.is_directory {
                            self.navigate_to(file.path.clone());
                        } else {
                            // File selected - determine operation
                            self.handle_file_selection().await;
                        }
                    }
                }
            }
            KeyCode::Char(' ') => {
                self.toggle_selection();
            }
            KeyCode::Char('a') => {
                // Select all files (not directories)
                self.selected_files.clear();
                for (i, file) in self.files.iter().enumerate() {
                    if !file.is_directory || file.name != ".." {
                        self.selected_files.insert(i, true);
                    }
                }
            }
            KeyCode::Char('c') => {
                // Clear selection
                self.selected_files.clear();
            }
            _ => {}
        }
    }

    /// Handle file selection
    async fn handle_file_selection(&mut self) {
        let selected_files = self.get_selected_files();
        if selected_files.is_empty() {
            return;
        }

        // Check if files are encrypted or not
        let has_encrypted = selected_files.iter().any(|f| f.is_encrypted);
        let has_unencrypted = selected_files.iter().any(|f| !f.is_encrypted);

        if has_encrypted && has_unencrypted {
            self.status = "Cannot mix encrypted and unencrypted files in one operation".to_string();
            return;
        }

        let operation = if has_encrypted {
            OperationType::Decrypt
        } else {
            OperationType::Encrypt
        };

        let file_paths: Vec<PathBuf> = selected_files.iter().map(|f| f.path.clone()).collect();
        let compress = self.settings.default_compression && operation == OperationType::Encrypt;

        if self.settings.use_global_password && self.settings.global_password.is_some() {
            // Use global password
            self.process_files(operation, file_paths, compress, 
                              self.settings.global_password.as_ref().unwrap().clone()).await;
        } else {
            // Ask for password
            self.mode = AppMode::InputPassword {
                operation: operation.clone(),
                files: file_paths,
                compress,
            };
            self.input.clear();
            self.status = format!("Enter password for {} operation:", 
                                if operation == OperationType::Encrypt { "encryption" } else { "decryption" });
        }
    }

    /// Handle keys in search mode
    fn handle_search_keys(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char(c) => {
                self.input.push(c);
                self.search_query = self.input.clone();
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.search_query = self.input.clone();
            }
            KeyCode::Enter => {
                self.mode = AppMode::Browser;
                self.status = "Search applied".to_string();
            }
            KeyCode::Esc => {
                self.mode = AppMode::Browser;
                self.search_query.clear();
                self.input.clear();
                self.status = "Search cancelled".to_string();
            }
            _ => {}
        }
    }

    /// Handle keys in settings mode
    fn handle_settings_keys(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.mode = AppMode::Browser;
                self.status = "Settings saved".to_string();
            }
            KeyCode::Char('1') => {
                self.settings.use_global_password = !self.settings.use_global_password;
            }
            KeyCode::Char('2') => {
                self.settings.default_compression = !self.settings.default_compression;
            }
            KeyCode::Char('3') => {
                self.settings.delete_after_operation = !self.settings.delete_after_operation;
            }
            KeyCode::Char('4') => {
                self.settings.verify_checksums = !self.settings.verify_checksums;
            }
            _ => {}
        }
    }

    /// Handle keys in password input mode
    async fn handle_password_input_keys(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char(c) => {
                self.input.push(c);
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                if !self.input.is_empty() {
                    if let AppMode::InputPassword { operation, files, compress } = self.mode.clone() {
                        let password = self.input.clone();
                        self.process_files(operation, files, compress, password).await;
                    }
                }
            }
            KeyCode::Esc => {
                self.mode = AppMode::Browser;
                self.input.clear();
                self.status = "Operation cancelled".to_string();
            }
            _ => {}
        }
    }

    /// Handle keys in help mode
    fn handle_help_keys(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = AppMode::Browser;
                self.status = "Ready - Navigate with ↑/↓, Enter to select, ? for help".to_string();
            }
            _ => {}
        }
    }

    /// Handle keys in confirm mode
    fn handle_confirm_keys(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('y') | KeyCode::Enter => {
                // Handle confirmation action
                if let AppMode::Confirm { action, .. } = &self.mode {
                    match action {
                        ConfirmAction::DeleteFiles => {
                            // TODO: Implement file deletion
                        }
                        ConfirmAction::OverwriteFile => {
                            // TODO: Implement overwrite
                        }
                        ConfirmAction::ClearSettings => {
                            self.settings = AppSettings::default();
                        }
                    }
                }
                self.mode = AppMode::Browser;
                self.status = "Action completed".to_string();
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.mode = AppMode::Browser;
                self.status = "Action cancelled".to_string();
            }
            _ => {}
        }
    }

    /// Process selected files
    async fn process_files(&mut self, operation: OperationType, files: Vec<PathBuf>, compress: bool, password: String) {
        self.mode = AppMode::Processing {
            operation: operation.clone(),
            current_file: "Starting...".to_string(),
            progress: 0.0,
        };

        for (i, file_path) in files.iter().enumerate() {
            let progress = (i as f64) / (files.len() as f64) * 100.0;
            let filename = file_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            self.mode = AppMode::Processing {
                operation: operation.clone(),
                current_file: filename,
                progress,
            };

            let target_type = if file_path.is_dir() {
                TargetType::Directory
            } else {
                TargetType::File
            };

            let params = OperationParams::new(
                operation.clone(),
                target_type,
                file_path.clone(),
            ).with_compression(compress)
             .with_delete_source(self.settings.delete_after_operation)
             .with_verify_checksum(self.settings.verify_checksums);

            let result = self.file_operator.process(&params, &password).await;
            
            if !result.success {
                self.status = format!("Error: {}", result.error.unwrap_or_default());
                self.mode = AppMode::Browser;
                return;
            }
        }

        self.status = format!("Successfully processed {} files", files.len());
        self.mode = AppMode::Browser;
        self.refresh_file_list();
        self.selected_files.clear();
    }

    /// Draw the UI
    fn ui(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(1), // Title
                Constraint::Min(1),    // Main content
                Constraint::Length(3), // Status
            ].as_ref())
            .split(f.size());

        // Title
        let title = Paragraph::new("SF-CLI - Secure File Encryption")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
        f.render_widget(title, chunks[0]);

        // Main content based on mode
        match &self.mode {
            AppMode::Browser => self.draw_browser(f, chunks[1]),
            AppMode::Search => self.draw_search(f, chunks[1]),
            AppMode::Settings => self.draw_settings(f, chunks[1]),
            AppMode::InputPassword { operation, files, .. } => {
                self.draw_password_input(f, chunks[1], operation, files.len())
            }
            AppMode::Processing { operation, current_file, progress } => {
                self.draw_processing(f, chunks[1], operation, current_file, *progress)
            }
            AppMode::Help => self.draw_help(f, chunks[1]),
            AppMode::Confirm { message, .. } => self.draw_confirm(f, chunks[1], message),
        }

        // Status bar
        let status_text = if matches!(self.mode, AppMode::InputPassword { .. }) {
            // Hide password input
            format!("{} {}", self.status, "*".repeat(self.input.len()))
        } else if matches!(self.mode, AppMode::Search) {
            format!("{} {}", self.status, self.input)
        } else {
            self.status.clone()
        };

        let status_line = Line::from(vec![Span::styled(
            &status_text,
            Style::default().fg(Color::Green),
        )]);
        let status = Paragraph::new(status_line)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(status, chunks[2]);
    }

    /// Draw browser interface
    fn draw_browser(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
            .split(area);

        // File list
        let filtered_files = self.filter_files();
        let items: Vec<ListItem> = filtered_files
            .iter()
            .enumerate()
            .map(|(_display_idx, (original_idx, file))| {
                let prefix = if file.is_directory {
                    if file.name == ".." {
                        "📁 "
                    } else {
                        "📂 "
                    }
                } else if file.is_encrypted {
                    "🔒 "
                } else {
                    "📄 "
                };

                let style = if self.selected_files.contains_key(original_idx) {
                    Style::default().bg(Color::Blue).fg(Color::White)
                } else if file.is_encrypted {
                    Style::default().fg(Color::Yellow)
                } else if file.is_directory {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                };

                let size_str = if file.is_directory && file.name != ".." {
                    "<DIR>".to_string()
                } else if file.size < 1024 {
                    format!("{} B", file.size)
                } else if file.size < 1024 * 1024 {
                    format!("{:.1} KB", file.size as f64 / 1024.0)
                } else {
                    format!("{:.1} MB", file.size as f64 / (1024.0 * 1024.0))
                };

                ListItem::new(format!("{}{:<30} {:>10}", prefix, file.name, size_str))
                    .style(style)
            })
            .collect();

        let current_dir_display = self.current_dir.to_string_lossy();
        let file_list = List::new(items)
            .block(Block::default()
                .title(format!("Files: {} ({})", current_dir_display, filtered_files.len()))
                .borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");

        f.render_stateful_widget(file_list, chunks[0], &mut self.file_list_state.clone());

        // Info panel
        let info_text = vec![
            Line::from("Controls:"),
            Line::from(""),
            Line::from("↑/↓     - Navigate"),
            Line::from("Enter   - Select/Open"),
            Line::from("Space   - Toggle selection"),
            Line::from("a       - Select all"),
            Line::from("c       - Clear selection"),
            Line::from("/       - Search"),
            Line::from("s       - Settings"),
            Line::from("?       - Help"),
            Line::from("q       - Quit"),
            Line::from(""),
            Line::from(Span::styled("Legend:", Style::default().add_modifier(Modifier::BOLD))),
            Line::from("📂 Directory"),
            Line::from("📄 File"),
            Line::from(Span::styled("🔒 Encrypted", Style::default().fg(Color::Yellow))),
        ];

        let info_panel = Paragraph::new(info_text)
            .block(Block::default().title("Info").borders(Borders::ALL))
            .wrap(ratatui::widgets::Wrap { trim: true });
        f.render_widget(info_panel, chunks[1]);
    }

    /// Draw search interface
    fn draw_search(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let search_text = format!("Search: {}", self.input);
        let search_input = Paragraph::new(search_text)
            .block(Block::default().title("Search Files").borders(Borders::ALL));
        f.render_widget(search_input, area);
    }

    /// Draw settings interface
    fn draw_settings(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let settings_text = vec![
            Line::from("Settings:"),
            Line::from(""),
            Line::from(format!("1. Global Password: {}", 
                if self.settings.use_global_password { "Enabled" } else { "Disabled" })),
            Line::from(format!("2. Default Compression: {}", 
                if self.settings.default_compression { "Enabled" } else { "Disabled" })),
            Line::from(format!("3. Delete After Operation: {}", 
                if self.settings.delete_after_operation { "Enabled" } else { "Disabled" })),
            Line::from(format!("4. Verify Checksums: {}", 
                if self.settings.verify_checksums { "Enabled" } else { "Disabled" })),
            Line::from(""),
            Line::from("Press number to toggle, Esc to return"),
        ];

        let settings_panel = Paragraph::new(settings_text)
            .block(Block::default().title("Settings").borders(Borders::ALL));
        f.render_widget(settings_panel, area);
    }

    /// Draw password input interface
    fn draw_password_input(&self, f: &mut Frame, area: ratatui::layout::Rect, operation: &OperationType, file_count: usize) {
        let password_text = format!("Enter password for {} {} file(s):", 
                                   operation, file_count);
        let password_input = Paragraph::new(password_text)
            .block(Block::default().title("Password Input").borders(Borders::ALL));
        f.render_widget(password_input, area);
    }

    /// Draw processing interface
    fn draw_processing(&self, f: &mut Frame, area: ratatui::layout::Rect, operation: &OperationType, current_file: &str, progress: f64) {
        let processing_text = vec![
            Line::from(format!("Operation: {}", operation)),
            Line::from(format!("Current File: {}", current_file)),
            Line::from(format!("Progress: {:.1}%", progress)),
        ];

        let processing_panel = Paragraph::new(processing_text)
            .block(Block::default().title("Processing").borders(Borders::ALL));
        f.render_widget(processing_panel, area);
    }

    /// Draw help interface
    fn draw_help(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let help_text = vec![
            Line::from("SF-CLI Help"),
            Line::from(""),
            Line::from("File Operations:"),
            Line::from("- Select files with Enter or Space"),
            Line::from("- Encrypted files (🔒) can be decrypted"),
            Line::from("- Regular files (📄) can be encrypted"),
            Line::from("- Use 'a' to select all, 'c' to clear selection"),
            Line::from(""),
            Line::from("Navigation:"),
            Line::from("- Use ↑/↓ to move between files"),
            Line::from("- Enter on directory to navigate"),
            Line::from("- .. goes to parent directory"),
            Line::from(""),
            Line::from("Features:"),
            Line::from("- File extension preservation"),
            Line::from("- SHA-256 checksum verification"),
            Line::from("- Multi-file selection"),
            Line::from("- Search with '/'"),
            Line::from("- Settings with 's'"),
            Line::from(""),
            Line::from("Press Esc or q to return"),
        ];

        let help_panel = Paragraph::new(help_text)
            .block(Block::default().title("Help").borders(Borders::ALL));
        f.render_widget(help_panel, area);
    }

    /// Draw confirmation dialog
    fn draw_confirm(&self, f: &mut Frame, area: ratatui::layout::Rect, message: &str) {
        let confirm_text = vec![
            Line::from(message),
            Line::from(""),
            Line::from("Press 'y' to confirm, 'n' or Esc to cancel"),
        ];

        let confirm_panel = Paragraph::new(confirm_text)
            .block(Block::default().title("Confirm").borders(Borders::ALL));
        f.render_widget(confirm_panel, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let app = App::new();
        assert_eq!(app.mode, AppMode::Browser);
        assert!(app.input.is_empty());
        assert!(!app.should_quit);
        assert!(!app.files.is_empty()); // Should have at least current directory files
    }
}