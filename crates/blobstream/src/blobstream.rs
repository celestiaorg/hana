use std::boxed::Box;

use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::sol;
use alloy_trie::{
    proof::{verify_proof, ProofVerificationError},
    Nibbles,
};
use celestia_types::{hash::Hash, MerkleProof, ShareProof};
use serde::{Deserialize, Serialize};

/////// Contract ///////

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1Blobstream {
        bool public frozen;
        uint64 public latestBlock;
        uint256 public state_proofNonce;
        mapping(uint64 => bytes32) public blockHeightToHeaderHash;
        mapping(uint256 => bytes32) public state_dataCommitments;
        uint64 public constant DATA_COMMITMENT_MAX = 10000;
        bytes32 public blobstreamProgramVkey;
        address public verifier;

        event DataCommitmentStored(
            uint256 proofNonce,
            uint64 indexed startBlock,
            uint64 indexed endBlock,
            bytes32 indexed dataCommitment
        );

        function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external;
    }
}

/// Represents the stored data commitment event from Blobstream
#[derive(Debug, Clone)]
pub struct SP1BlobstreamDataCommitmentStored {
    pub proof_nonce: U256,
    pub start_block: u64,
    pub end_block: u64,
    pub data_commitment: B256,
}

impl std::fmt::Display for SP1BlobstreamDataCommitmentStored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SP1BlobstreamDataCommitmentStored {{ proof_nonce: {}, start_block: {}, end_block: {}, data_commitment: {} }}",
            self.proof_nonce, self.start_block, self.end_block, self.data_commitment)
    }
}

pub const DATA_COMMITMENTS_SLOT: u32 = 254;

/// A structure containing a Celestia Blob and its corresponding proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobstreamProof {
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

impl BlobstreamProof {
    /// Create a new OraclePayload instance
    pub fn new(
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
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes = bincode::serialize(self)?;
        Ok(bytes)
    }

    /// Deserialize from bytes back into the struct
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let deserialized = bincode::deserialize(bytes)?;
        Ok(deserialized)
    }
}

pub fn encode_data_root_tuple(height: u64, data_root: &Hash) -> Vec<u8> {
    // Create the result vector with 64 bytes capacity
    let mut result = Vec::with_capacity(64);

    // Pad the height to 32 bytes (convert to big-endian and pad with zeros)
    let height_bytes = height.to_be_bytes();

    // Add leading zeros (24 bytes of padding)
    result.extend_from_slice(&[0u8; 24]);

    // Add the 8-byte height
    result.extend_from_slice(&height_bytes);

    // Add the 32-byte data root
    result.extend_from_slice(data_root.as_bytes());

    result
}

/// Verify a storage proof for the state_dataCommitments mapping
pub fn verify_data_commitment_storage(
    storage_root: B256,
    state_root: B256,
    storage_proof: Vec<Bytes>,
    account_proof: Vec<Bytes>,
    commitment_nonce: U256,
    expected_commitment: B256,
    expected_blobstream_address: Address,
    blobstream_balance: U256,
    blobstream_nonce: u64,
    blobstream_code_hash: B256,
) -> Result<(), ProofVerificationError> {
    // Currently verifies the value of the slot
    // need to verify the storage root agains the state root of the block
    // Calculate the storage slot for state_dataCommitments[nonce]
    let slot = calculate_mapping_slot(DATA_COMMITMENTS_SLOT, commitment_nonce);

    let nibbles = Nibbles::unpack(keccak256(slot));

    // Handle the RLP encoding by modifying the expected result
    // Add the 0xa0 prefix to match how it's stored on-chain
    let mut expected_with_prefix = Vec::with_capacity(33);
    expected_with_prefix.push(0xa0); // Add the RLP prefix
    expected_with_prefix.extend_from_slice(expected_commitment.as_slice());

    // verify the value of the storage slot, then of the storage proof against the state root
    match verify_proof(
        storage_root,
        nibbles,
        Some(expected_with_prefix),
        &storage_proof,
    ) {
        Ok(_) => {
            let nibbles = Nibbles::unpack(keccak256(expected_blobstream_address));
            let mut expected = Vec::new();

            let nonce_encoded = alloy_rlp::encode(&blobstream_nonce);
            let balance_encoded = alloy_rlp::encode(&blobstream_balance);
            let code_hash_encoded = alloy_rlp::encode(&blobstream_code_hash);
            let storage_root_encoded = alloy_rlp::encode(&storage_root);

            alloy_rlp::encode_list::<_, Vec<u8>>(
                &[
                    &nonce_encoded,
                    &balance_encoded,
                    &code_hash_encoded,
                    &storage_root_encoded,
                ],
                &mut expected,
            );

            match verify_proof(state_root, nibbles, Some(expected), &account_proof) {
                Ok(_) => return Ok(()),
                Err(err) => return Err(err),
            }
        }
        Err(err) => return Err(err),
    }
}

/// Calculate the storage slot for a mapping with a uint256 key
pub fn calculate_mapping_slot(mapping_slot: u32, key: U256) -> B256 {
    let key_bytes = key.to_be_bytes::<32>();

    let slot_bytes = U256::from(mapping_slot).to_be_bytes::<32>();

    let mut concatenated = [0u8; 64];
    concatenated[0..32].copy_from_slice(&key_bytes);
    concatenated[32..64].copy_from_slice(&slot_bytes);

    alloy_primitives::keccak256(concatenated)
}
