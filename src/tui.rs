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
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::{
    io,
    path::PathBuf,
};

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
}

/// Application modes
#[derive(Debug, Clone, PartialEq)]
enum AppMode {
    /// Main menu
    MainMenu,
    /// Input file path
    InputPath,
    /// Input password
    InputPassword { operation: OperationType, path: PathBuf, target_type: TargetType, compress: bool },
    /// Processing file
    Processing,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Create a new TUI application
    pub fn new() -> Self {
        Self {
            file_operator: FileOperator::new(),
            input: String::new(),
            mode: AppMode::MainMenu,
            status: "Ready".to_string(),
            should_quit: false,
        }
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
                match key.code {
                    KeyCode::Char('q') if self.mode == AppMode::MainMenu => {
                        self.should_quit = true;
                    }
                    KeyCode::Char('1') if self.mode == AppMode::MainMenu => {
                        self.mode = AppMode::InputPath;
                        self.input.clear();
                        self.status = "Enter file/folder path to encrypt:".to_string();
                    }
                    KeyCode::Char('2') if self.mode == AppMode::MainMenu => {
                        self.mode = AppMode::InputPath;
                        self.input.clear();
                        self.status = "Enter file/folder path to decrypt:".to_string();
                    }
                    KeyCode::Char(c) => {
                        self.input.push(c);
                    }
                    KeyCode::Backspace => {
                        self.input.pop();
                    }
                    KeyCode::Enter => {
                        self.handle_enter().await;
                    }
                    KeyCode::Esc => {
                        self.mode = AppMode::MainMenu;
                        self.input.clear();
                        self.status = "Ready".to_string();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Handle Enter key press
    async fn handle_enter(&mut self) {
        match self.mode.clone() {
            AppMode::MainMenu => {
                // No action on main menu
            }
            AppMode::InputPath => {
                if !self.input.is_empty() {
                    let path = PathBuf::from(&self.input);
                    if !path.exists() {
                        self.status = "Path does not exist!".to_string();
                        return;
                    }

                    let target_type = if path.is_dir() {
                        TargetType::Directory
                    } else {
                        TargetType::File
                    };

                    let operation = if self.status.contains("encrypt") {
                        OperationType::Encrypt
                    } else {
                        OperationType::Decrypt
                    };

                    // Ask for compression preference for encryption
                    let compress = operation == OperationType::Encrypt && target_type == TargetType::File;

                    self.mode = AppMode::InputPassword {
                        operation,
                        path,
                        target_type,
                        compress,
                    };
                    self.input.clear();
                    self.status = "Enter password:".to_string();
                }
            }
            AppMode::InputPassword { operation, path, target_type, compress } => {
                if !self.input.is_empty() {
                    let password = self.input.clone();
                    let params = OperationParams::new(
                        operation.clone(),
                        target_type.clone(),
                        path.clone(),
                    ).with_compression(compress);

                    self.mode = AppMode::Processing;
                    self.input.clear();
                    self.status = format!("Processing {}...", operation);

                    // Process the file
                    let result = self.file_operator.process(&params, &password).await;
                    
                    if result.success {
                        self.status = format!("✓ Success: {}", result);
                    } else {
                        self.status = format!("✗ Failed: {}", result.error.unwrap_or_default());
                    }

                    self.mode = AppMode::MainMenu;
                }
            }
            AppMode::Processing => {
                // No action during processing
            }
        }
    }

    /// Draw the UI
    fn ui(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([Constraint::Min(1), Constraint::Length(3)].as_ref())
            .split(f.size());

        // Main content area
        match &self.mode {
            AppMode::MainMenu => {
                let items = vec![
                    ListItem::new("1. Encrypt file/folder"),
                    ListItem::new("2. Decrypt file/folder"),
                    ListItem::new("q. Quit"),
                ];
                let list = List::new(items)
                    .block(Block::default().title("SF-CLI - Secure File Encryption").borders(Borders::ALL))
                    .style(Style::default().fg(Color::White))
                    .highlight_style(Style::default().add_modifier(Modifier::ITALIC))
                    .highlight_symbol(">> ");
                f.render_widget(list, chunks[0]);
            }
            AppMode::InputPath | AppMode::InputPassword { .. } => {
                let input_text = if matches!(self.mode, AppMode::InputPassword { .. }) {
                    // Hide password with asterisks
                    "*".repeat(self.input.len())
                } else {
                    self.input.clone()
                };

                let input = Paragraph::new(input_text)
                    .block(Block::default().title("Input").borders(Borders::ALL));
                f.render_widget(input, chunks[0]);
            }
            AppMode::Processing => {
                let processing = Paragraph::new("Processing... Please wait.")
                    .block(Block::default().title("Processing").borders(Borders::ALL))
                    .style(Style::default().fg(Color::Yellow));
                f.render_widget(processing, chunks[0]);
            }
        }

        // Status bar
        let status_line = Line::from(vec![Span::styled(
            &self.status,
            Style::default().fg(Color::Green),
        )]);
        let status = Paragraph::new(status_line)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(status, chunks[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let app = App::new();
        assert_eq!(app.mode, AppMode::MainMenu);
        assert!(app.input.is_empty());
        assert!(!app.should_quit);
    }
}