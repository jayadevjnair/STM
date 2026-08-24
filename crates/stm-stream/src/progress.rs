pub trait ProgressReporter: Send + Sync {
    fn on_progress(&self, processed_bytes: u64, total_bytes: u64);
}

#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub percentage: f64,
    pub operation: String,
}

pub struct NoopProgressReporter;
impl ProgressReporter for NoopProgressReporter {
    fn on_progress(&self, _processed_bytes: u64, _total_bytes: u64) {}
}

pub struct CallbackProgressReporter<F: Fn(u64, u64) + Send + Sync>(pub F);
impl<F: Fn(u64, u64) + Send + Sync> ProgressReporter for CallbackProgressReporter<F> {
    fn on_progress(&self, processed_bytes: u64, total_bytes: u64) {
        (self.0)(processed_bytes, total_bytes);
    }
}

pub struct CliProgressBar {
    operation: String,
}

impl CliProgressBar {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
        }
    }
}

impl ProgressReporter for CliProgressBar {
    fn on_progress(&self, processed: u64, total: u64) {
        if total == 0 {
            return;
        }
        let percent = ((processed as f64 / total as f64) * 100.0).min(100.0);
        let bar_width: usize = 20;
        let filled = ((percent / 100.0) * bar_width as f64) as usize;
        let empty = bar_width.saturating_sub(filled);
        let bar: String = "█".repeat(filled) + &"░".repeat(empty);

        let processed_mb = processed as f64 / (1024.0 * 1024.0);
        let total_mb = total as f64 / (1024.0 * 1024.0);

        eprint!(
            "\r{}: [{}] {:.0}% ({:.2} MB / {:.2} MB)",
            self.operation, bar, percent, processed_mb, total_mb
        );
        if processed >= total {
            eprintln!();
        }
    }
}
