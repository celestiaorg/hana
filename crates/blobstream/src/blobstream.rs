use std::boxed::Box;

use alloc::vec::Vec;
use alloy_chains::NamedChain;
use alloy_consensus::Header;
use alloy_primitives::{address, keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::sol;
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use anyhow::{anyhow, Result};
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
    /// The balance to verify against the blobstream address
    pub blobstream_balance: U256,
    /// The nonce to verify against the blobstream address
    pub blobstream_nonce: u64,
    /// The code hash to verify against the blobstream address
    pub blobstream_code_hash: B256,
    /// The block header to verify against the l1 head
    pub block_header: Header,
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
        blobstream_balance: U256,
        blobstream_nonce: u64,
        blobstream_code_hash: B256,
        block_header: Header,
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
            blobstream_balance,
            blobstream_nonce,
            blobstream_code_hash,
            block_header,
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

/// Verifies that a data commitment exists in the Ethereum state at the specified L1 block.
///
/// This function performs a multi-step verification process:
///
/// 1. Validates that the provided block header hash matches the expected L1 block hash,
///    ensuring we're working with the correct block state.
///
/// 2. Verifies the Blobstream contract account exists at the expected address by checking
///    its account proof against the block's state root. This confirms the contract's
///    balance, nonce, code hash, and storage root are as expected.
///
/// 3. Verifies the data commitment exists at the specific storage slot determined by the
///    commitment nonce, by validating the storage proof against the contract's storage root.
///    This confirms the data commitment was properly recorded in the Blobstream contract.
///
/// Security Note: This function assumes the l1_block_hash and expected_blobsstream_address come from a secure source.
pub fn verify_data_commitment(
    storage_root: B256,
    storage_proof: Vec<Bytes>,
    account_proof: Vec<Bytes>,
    commitment_nonce: U256,
    expected_commitment: B256,
    expected_blobstream_address: Address,
    blobstream_balance: U256,
    blobstream_nonce: u64,
    blobstream_code_hash: B256,
    block_header: Header,
    l1_block_hash: B256,
) -> Result<()> {
    // Verify the block header hash matches the l1 head.
    let block_hash = block_header.hash_slow();
    assert!(
        block_hash == l1_block_hash,
        "computed block hash must match host l1 head"
    );

    let account = TrieAccount {
        nonce: blobstream_nonce,
        balance: blobstream_balance,
        code_hash: blobstream_code_hash,
        storage_root,
    };

    let blobstream_address_nibbles = Nibbles::unpack(keccak256(expected_blobstream_address));

    verify_proof(
        block_header.state_root,
        blobstream_address_nibbles,
        Some(alloy_rlp::encode(&account)),
        &account_proof,
    )
    .map_err(|e| anyhow!("Account proof verification failed: {}", e))?;

    // Get the nibbles for the storage slot for state_dataCommitments[nonce]
    let data_commitment_slot_nibbles = Nibbles::unpack(keccak256(calculate_mapping_slot(
        DATA_COMMITMENTS_SLOT,
        commitment_nonce,
    )));

    // Drop leading zeros before encoding
    let commitment_bytes = expected_commitment.as_slice();
    let canonical_commitment = match commitment_bytes.iter().position(|byte| *byte != 0) {
        Some(idx) => &commitment_bytes[idx..],
        None => &[],
    };
    let expected_with_prefix = alloy_rlp::encode(canonical_commitment);

    // Use canonical RLP encoding
    let expected_rlp = alloy_rlp::encode(canonical_commitment);

    // Verify storage proof
    verify_proof(
        storage_root,
        data_commitment_slot_nibbles,
        Some(expected_with_prefix),
        &storage_proof,
    )
    .map_err(|e| anyhow!("Storage proof verification failed: {}", e))?;

    Ok(())
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

/// The canonical Blobstream address for the given chain id.
///
/// Source: https://docs.celestia.org/how-to-guides/blobstream#deployed-contracts
pub fn blobstream_address(chain_id: u64) -> Option<Address> {
    if let Ok(chain) = NamedChain::try_from(chain_id) {
        match chain {
            NamedChain::Mainnet => Some(address!("0x7Cf3876F681Dbb6EdA8f6FfC45D66B996Df08fAe")),
            NamedChain::Arbitrum => Some(address!("0xA83ca7775Bc2889825BcDeDfFa5b758cf69e8794")),
            NamedChain::Base => Some(address!("0xA83ca7775Bc2889825BcDeDfFa5b758cf69e8794")),
            NamedChain::Scroll => Some(address!("0x5008fa5CC3397faEa90fcde71C35945db6822218")),
            NamedChain::Sepolia => Some(address!("0xF0c6429ebAB2e7DC6e05DaFB61128bE21f13cb1e")),
            NamedChain::ArbitrumSepolia => {
                Some(address!("0xc3e209eb245Fd59c8586777b499d6A665DF3ABD2"))
            }
            NamedChain::BaseSepolia => Some(address!("0xc3e209eb245Fd59c8586777b499d6A665DF3ABD2")),
            NamedChain::Holesky => Some(address!("0x315A044cb95e4d44bBf6253585FbEbcdB6fb41ef")),
            _ => None,
        }
    } else {
        None
    }
}
