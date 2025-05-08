use alloc::{boxed::Box, vec::Vec};
use alloy_primitives::Bytes;
use hana_blobstream::blobstream::BlobstreamProof;
use serde::{Deserialize, Serialize};

/// A structure containing a Celestia Blob and its corresponding proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePayload {
    /// The Celestia blob data
    pub blob: Bytes,
    /// Blobstream proof data
    pub blobstream_proof: BlobstreamProof,
}

impl OraclePayload {
    /// Create a new OraclePayload instance
    pub fn new(blob: Bytes, blobstream_proof: BlobstreamProof) -> Self {
        Self {
            blob,
            blobstream_proof,
        }
    }

    /// Serialize the struct to bytes using serde with a binary format
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        let bytes = bincode::serialize(self)?;
        Ok(bytes)
    }

    /// Deserialize from bytes back into the struct
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn core::error::Error>> {
        let deserialized = bincode::deserialize(bytes)?;
        Ok(deserialized)
    }
}
