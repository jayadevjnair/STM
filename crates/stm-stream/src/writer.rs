use crate::progress::ProgressReporter;
use std::io::{Read, Write};
use stm_core::StmError;

pub fn copy_with_progress<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    buffer_size: usize,
    total_bytes: u64,
    progress: Option<&dyn ProgressReporter>,
) -> Result<u64, StmError> {
    let mut buffer = vec![0u8; buffer_size.max(1)];
    let mut total_copied = 0u64;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buffer[..n])?;
        total_copied += n as u64;
        if let Some(reporter) = progress {
            reporter.on_progress(total_copied, total_bytes);
        }
    }

    writer.flush()?;
    Ok(total_copied)
}
