use alloc::{boxed::Box, vec::Vec};
use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
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
    /// The L1 state root hash to verify the account proof against
    pub state_root: FixedBytes<32>,
    /// The blobstream address to verify
    pub blobstream_address: Address,
    /// The balance to verify against the blobstream address
    pub blobstream_balance: U256,
    /// The nonce to verify against the blobstream address
    pub blobstream_nonce: u64,
    /// The code hash to verify against the blobstream address
    pub blobstream_code_hash: B256,
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
        state_root: FixedBytes<32>,
        blobstream_address: Address,
        blobstream_balance: U256,
        blobstream_nonce: u64,
        blobstream_code_hash: B256,
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
            state_root,
            blobstream_address,
            blobstream_balance,
            blobstream_nonce,
            blobstream_code_hash,
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
