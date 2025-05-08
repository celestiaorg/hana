use std::boxed::Box;

use alloc::vec::Vec;
use alloy_primitives::{address, keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy_rpc_types_eth::Header;
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
        state_root: FixedBytes<32>,
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
            state_root,
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
pub fn verify_data_commitment_storage(
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
) -> Result<(), ProofVerificationError> {
    let block_hash = block_header.hash_slow();

    assert!(
        block_hash == l1_block_hash,
        "computed block hash must match host l1 head"
    );

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

    let nibbles = Nibbles::unpack(keccak256(expected_blobstream_address));

    verify_proof(
        block_header.state_root,
        nibbles,
        Some(expected),
        &account_proof,
    )?;

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

    verify_proof(
        storage_root,
        nibbles,
        Some(expected_with_prefix),
        &storage_proof,
    )?;

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

pub enum BlobstreamChainIds {
    // Mainnets
    EthereumMainnet = 1,
    ArbitrumOne = 42161,
    Base = 8453,

    // Testnets
    Sepolia = 11155111,
    ArbitrumSepolia = 421614,
    BaseSepolia = 84532,
}

impl BlobstreamChainIds {
    pub fn from_u64(id: u64) -> Option<Self> {
        match id {
            1 => Some(Self::EthereumMainnet),
            42161 => Some(Self::ArbitrumOne),
            8453 => Some(Self::Base),
            11155111 => Some(Self::Sepolia),
            421614 => Some(Self::ArbitrumSepolia),
            84532 => Some(Self::BaseSepolia),
            _ => None,
        }
    }

    pub fn blostream_address(&self) -> Address {
        match self {
            Self::EthereumMainnet => address!("0x7Cf3876F681Dbb6EdA8f6FfC45D66B996Df08fAe"),
            Self::ArbitrumOne => address!("0xA83ca7775Bc2889825BcDeDfFa5b758cf69e8794"),
            Self::Base => address!("0xA83ca7775Bc2889825BcDeDfFa5b758cf69e8794"),
            Self::Sepolia => address!("0xF0c6429ebAB2e7DC6e05DaFB61128bE21f13cb1e"),
            Self::ArbitrumSepolia => address!("0xc3e209eb245Fd59c8586777b499d6A665DF3ABD2"),
            Self::BaseSepolia => address!("0xc3e209eb245Fd59c8586777b499d6A665DF3ABD2"),
        }
    }
}
