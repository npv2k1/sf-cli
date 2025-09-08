//! Progress tracking for file operations

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Progress tracker for file operations
pub struct ProgressTracker {
    bar: ProgressBar,
}

impl ProgressTracker {
    /// Create a new progress tracker with total size
    pub fn new(total_size: u64, operation: &str) -> Self {
        let bar = ProgressBar::new(total_size);
        bar.set_style(
            ProgressStyle::default_bar()
                .template(&format!(
                    "{} [{{elapsed_precise}}] [{{bar:40.cyan/blue}}] {{bytes}}/{{total_bytes}} ({{eta}})",
                    operation
                ))
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );
        bar.enable_steady_tick(Duration::from_millis(100));

        Self { bar }
    }

    /// Create a spinner for operations without known size
    pub fn new_spinner(operation: &str) -> Self {
        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::default_spinner()
                .template(&format!("{} [{{elapsed_precise}}] {{spinner}} {{msg}}", operation))
                .unwrap(),
        );
        bar.enable_steady_tick(Duration::from_millis(100));

        Self { bar }
    }

    /// Update progress by adding bytes processed
    pub fn inc(&self, bytes: u64) {
        self.bar.inc(bytes);
    }

    /// Set current position
    pub fn set_position(&self, pos: u64) {
        self.bar.set_position(pos);
    }

    /// Set message for spinner
    pub fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }

    /// Mark operation as finished
    pub fn finish(&self, message: &str) {
        self.bar.finish_with_message(message.to_string());
    }

    /// Mark operation as finished and clear
    pub fn finish_and_clear(&self) {
        self.bar.finish_and_clear();
    }
}

impl Drop for ProgressTracker {
    fn drop(&mut self) {
        self.bar.finish_and_clear();
    }
}

/// Progress callback function type
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

/// Create a progress callback that updates a progress tracker
pub fn create_progress_callback(tracker: &ProgressTracker) -> impl Fn(u64) + '_ {
    move |bytes_processed| {
        tracker.inc(bytes_processed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_progress_tracker() {
        let tracker = ProgressTracker::new(1000, "Testing");
        
        // Simulate progress
        for _i in 0..10 {
            tracker.inc(100);
            thread::sleep(Duration::from_millis(10));
        }
        
        tracker.finish("Complete");
    }

    #[test]
    fn test_spinner() {
        let tracker = ProgressTracker::new_spinner("Processing");
        
        tracker.set_message("Working...");
        thread::sleep(Duration::from_millis(50));
        
        tracker.set_message("Almost done...");
        thread::sleep(Duration::from_millis(50));
        
        tracker.finish("Done");
    }
}