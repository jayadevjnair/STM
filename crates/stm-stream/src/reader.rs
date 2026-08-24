use crate::chunk::DEFAULT_CHUNK_SIZE;
use std::io::Read;
use stm_core::StmError;

pub struct StreamReader<R: Read> {
    reader: R,
    chunk_size: usize,
    buffer: Vec<u8>,
}

impl<R: Read> StreamReader<R> {
    pub fn new(reader: R) -> Self {
        Self::with_chunk_size(reader, DEFAULT_CHUNK_SIZE)
    }

    pub fn with_chunk_size(reader: R, chunk_size: usize) -> Self {
        let size = chunk_size.max(1);
        Self {
            reader,
            chunk_size: size,
            buffer: vec![0u8; size],
        }
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn read_next_chunk(&mut self) -> Result<Option<Vec<u8>>, StmError> {
        let mut total_read = 0;
        while total_read < self.chunk_size {
            let n = self
                .reader
                .read(&mut self.buffer[total_read..self.chunk_size])?;
            if n == 0 {
                break;
            }
            total_read += n;
        }

        if total_read == 0 {
            Ok(None)
        } else {
            Ok(Some(self.buffer[..total_read].to_vec()))
        }
    }
}
