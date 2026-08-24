use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use stm_stream::progress::CallbackProgressReporter;
use stm_stream::writer::copy_with_progress;

#[test]
fn test_progress_reporter_invocations() {
    let total_size = 1000u64;
    let data = vec![99u8; total_size as usize];
    let cursor = Cursor::new(data);
    let mut sink = Vec::new();

    let last_reported = Arc::new(AtomicU64::new(0));
    let last_reported_clone = last_reported.clone();

    let reporter = CallbackProgressReporter(move |processed, total| {
        assert_eq!(total, total_size);
        assert!(processed >= last_reported_clone.load(Ordering::SeqCst));
        last_reported_clone.store(processed, Ordering::SeqCst);
    });

    let copied = copy_with_progress(cursor, &mut sink, 100, total_size, Some(&reporter)).unwrap();
    assert_eq!(copied, total_size);
    assert_eq!(last_reported.load(Ordering::SeqCst), total_size);
}
