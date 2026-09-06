use std::collections::VecDeque;

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub(super) struct ByteBuffer {
    bytes: VecDeque<u8>,
    capacity: usize,
    end: u64,
    pub eof: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SavedBuffer {
    pub capacity: usize,
    pub end: u64,
    pub bytes_base64: String,
    pub eof: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputChunk {
    pub requested_cursor: u64,
    pub start_cursor: u64,
    pub next_cursor: u64,
    pub end_cursor: u64,
    pub retained_from_cursor: u64,
    pub dropped_bytes: u64,
    pub gap_bytes: u64,
    pub bytes_base64: String,
    pub text_utf8_lossy: String,
    pub valid_utf8: bool,
    pub eof: bool,
    pub read_error: Option<String>,
}

impl ByteBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            capacity,
            end: 0,
            eof: false,
            error: None,
        }
    }

    pub fn append(&mut self, data: &[u8]) {
        self.end = self
            .end
            .checked_add(data.len() as u64)
            .expect("output cursor overflow");
        let data = &data[data.len().saturating_sub(self.capacity)..];
        let remove = self
            .bytes
            .len()
            .saturating_add(data.len())
            .saturating_sub(self.capacity);
        self.bytes.drain(..remove);
        self.bytes.extend(data);
    }

    pub fn read(&self, cursor: Option<u64>, max_bytes: usize) -> anyhow::Result<OutputChunk> {
        let start = self.end - self.bytes.len() as u64;
        let requested = cursor.unwrap_or(start);
        anyhow::ensure!(
            requested <= self.end,
            "cursor {requested} is beyond stream end {}",
            self.end
        );
        let cursor = requested.max(start);
        let bytes: Vec<_> = self
            .bytes
            .iter()
            .skip((cursor - start) as usize)
            .take(max_bytes)
            .copied()
            .collect();
        Ok(OutputChunk {
            requested_cursor: requested,
            start_cursor: cursor,
            next_cursor: cursor + bytes.len() as u64,
            end_cursor: self.end,
            retained_from_cursor: start,
            dropped_bytes: start,
            gap_bytes: start.saturating_sub(requested),
            bytes_base64: STANDARD.encode(&bytes),
            text_utf8_lossy: String::from_utf8_lossy(&bytes).into_owned(),
            valid_utf8: std::str::from_utf8(&bytes).is_ok(),
            eof: self.eof,
            read_error: self.error.clone(),
        })
    }

    pub fn save(&self) -> SavedBuffer {
        SavedBuffer {
            capacity: self.capacity,
            end: self.end,
            bytes_base64: STANDARD.encode(self.bytes.iter().copied().collect::<Vec<_>>()),
            eof: self.eof,
            error: self.error.clone(),
        }
    }

    pub fn restore(saved: SavedBuffer, maximum: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(
            saved.capacity > 0 && saved.capacity <= maximum,
            "invalid saved buffer capacity"
        );
        anyhow::ensure!(
            saved.bytes_base64.len() <= saved.capacity.div_ceil(3) * 4,
            "saved output exceeds capacity"
        );
        let bytes = STANDARD
            .decode(saved.bytes_base64)
            .context("invalid saved output base64")?;
        anyhow::ensure!(
            bytes.len() <= saved.capacity && saved.end >= bytes.len() as u64,
            "invalid saved output cursor"
        );
        Ok(Self {
            bytes: bytes.into(),
            capacity: saved.capacity,
            end: saved.end,
            eof: saved.eof,
            error: saved.error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_bytes_cursors_and_partial_utf8_are_exact() -> anyhow::Result<()> {
        let mut buffer = ByteBuffer::new(5);
        buffer.append(b"0123456789");
        let output = buffer.read(Some(0), 3)?;
        assert_eq!(
            (output.start_cursor, output.next_cursor, output.end_cursor),
            (5, 8, 10)
        );
        assert_eq!((output.dropped_bytes, output.gap_bytes), (5, 5));
        assert_eq!(STANDARD.decode(output.bytes_base64)?, b"567");
        assert!(buffer.read(Some(11), 100).is_err());
        buffer.append(&[0xe2, 0x82, 0xac]);
        let partial = buffer.read(Some(11), 1)?;
        assert!(!partial.valid_utf8);
        assert_eq!(STANDARD.decode(partial.bytes_base64)?, [0x82]);
        let restored = ByteBuffer::restore(buffer.save(), 10)?;
        assert_eq!(restored.read(Some(10), 3)?.text_utf8_lossy, "\u{20ac}");
        Ok(())
    }
}
