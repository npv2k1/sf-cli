//! Compression and decompression utilities

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};
use thiserror::Error;

/// Compression errors
#[derive(Error, Debug)]
pub enum CompressionError {
    #[error("Compression failed: {0}")]
    CompressionFailed(String),
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Compression engine for data compression/decompression
pub struct CompressionEngine {
    level: Compression,
}

impl Default for CompressionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CompressionEngine {
    /// Create a new compression engine with default compression level
    pub fn new() -> Self {
        Self {
            level: Compression::default(),
        }
    }

    /// Create a new compression engine with specified compression level (0-9)
    pub fn with_level(level: u32) -> Self {
        Self {
            level: Compression::new(level),
        }
    }

    /// Compress data using gzip
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut encoder = GzEncoder::new(Vec::new(), self.level);
        encoder
            .write_all(data)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;

        encoder
            .finish()
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))
    }

    /// Decompress gzip data
    pub fn decompress(&self, compressed_data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = GzDecoder::new(compressed_data);
        let mut decompressed = Vec::new();

        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        Ok(decompressed)
    }

    /// Estimate compression ratio for given data
    pub fn estimate_ratio(&self, data: &[u8]) -> Result<f64, CompressionError> {
        let compressed = self.compress(data)?;
        Ok(compressed.len() as f64 / data.len() as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_decompression() {
        let engine = CompressionEngine::new();
        let data = b"Hello, World! This is a test message that should compress well because it has repeating patterns. Hello, World! This is a test message that should compress well because it has repeating patterns.";

        let compressed = engine.compress(data).unwrap();
        assert!(compressed.len() < data.len()); // Should be smaller for this repetitive data

        let decompressed = engine.decompress(&compressed).unwrap();
        assert_eq!(decompressed.as_slice(), data);
    }

    #[test]
    fn test_compression_levels() {
        let data = b"Test data for compression level testing. ".repeat(100);

        let engine_fast = CompressionEngine::with_level(1);
        let engine_best = CompressionEngine::with_level(9);

        let compressed_fast = engine_fast.compress(&data).unwrap();
        let compressed_best = engine_best.compress(&data).unwrap();

        // Best compression should produce smaller output
        assert!(compressed_best.len() <= compressed_fast.len());

        // Both should decompress to original data
        let decompressed_fast = engine_fast.decompress(&compressed_fast).unwrap();
        let decompressed_best = engine_best.decompress(&compressed_best).unwrap();

        assert_eq!(decompressed_fast, data);
        assert_eq!(decompressed_best, data);
    }

    #[test]
    fn test_empty_data() {
        let engine = CompressionEngine::new();
        let empty_data = b"";

        let compressed = engine.compress(empty_data).unwrap();
        let decompressed = engine.decompress(&compressed).unwrap();

        assert_eq!(decompressed.as_slice(), empty_data);
    }

    #[test]
    fn test_invalid_compressed_data() {
        let engine = CompressionEngine::new();
        let invalid_data = b"This is not compressed data";

        let result = engine.decompress(invalid_data);
        assert!(matches!(
            result,
            Err(CompressionError::DecompressionFailed(_))
        ));
    }

    #[test]
    fn test_compression_ratio() {
        let engine = CompressionEngine::new();

        // Highly compressible data
        let repetitive_data = b"A".repeat(1000);
        let ratio1 = engine.estimate_ratio(&repetitive_data).unwrap();

        // Less compressible data (random-like)
        let varied_data = (0..1000).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let ratio2 = engine.estimate_ratio(&varied_data).unwrap();

        // Repetitive data should compress better (lower ratio)
        assert!(ratio1 < ratio2);
        assert!(ratio1 < 1.0);
        assert!(ratio2 < 1.0);
    }
}
