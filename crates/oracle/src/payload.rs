use alloc::{boxed::Box, vec::Vec};
use alloy_primitives::{Bytes, FixedBytes, B256, U256};
use alloy_rpc_types_eth::Header;
use celestia_types::{hash::Hash, MerkleProof, ShareProof};
use serde::{Deserialize, Serialize};

/// A structure containing a Celestia Blob and its corresponding proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePayload {
    /// The Celestia blob data
    pub blob: Bytes,
    /// The data root to verify the proof against
    pub data_root: Hash,
    /// The data commitment from Blobstream to verify against
    pub data_commitment: FixedBytes<32>,
    /// The Data Root Tuple Inclusion proof
    pub data_root_tuple_proof: MerkleProof,
    /// The proof for the blob's inclusion
    pub share_proof: ShareProof,
    /// The proof_nonce in blobstream
    pub proof_nonce: U256,
    /// The storage root to verify against
    pub storage_root: B256,
    /// The storage proof for the state_dataCommitments mapping slot in Blobstream
    pub storage_proof: Vec<Bytes>,
    /// The account proof for the blobstream address
    pub account_proof: Vec<Bytes>,
    /// The balance to verify against the blobstream address
    pub blobstream_balance: U256,
    /// The nonce to verify against the blobstream address
    pub blobstream_nonce: u64,
    /// The code hash to verify against the blobstream address
    pub blobstream_code_hash: B256,
    /// The block header corresponding to L1 head. This header must be hashed and verified against the l1Head to be securely used.
    pub block_header: Header,
}

impl OraclePayload {
    /// Create a new OraclePayload instance
    pub fn new(
        blob: Bytes,
        data_root: Hash,
        data_commitment: FixedBytes<32>,
        data_root_tuple_proof: MerkleProof,
        share_proof: ShareProof,
        proof_nonce: U256,
        storage_root: B256,
        storage_proof: Vec<Bytes>,
        account_proof: Vec<Bytes>,
        blobstream_balance: U256,
        blobstream_nonce: u64,
        blobstream_code_hash: B256,
        block_header: Header,
    ) -> Self {
        Self {
            blob,
            data_root,
            data_commitment,
            data_root_tuple_proof,
            share_proof,
            proof_nonce,
            storage_root,
            storage_proof,
            account_proof,
            blobstream_balance,
            blobstream_nonce,
            blobstream_code_hash,
            block_header,
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
