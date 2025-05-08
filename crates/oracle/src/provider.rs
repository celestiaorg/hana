use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes};
use async_trait::async_trait;
use celestia_types::Commitment;
use hana_blobstream::blobstream::{
    encode_data_root_tuple, verify_data_commitment_storage, BlobstreamChainIds,
};
use hana_celestia::CelestiaProvider;
use kona_preimage::errors::PreimageOracleError;
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use kona_proof::errors::OracleProviderError;
use kona_proof::{BootInfo, Hint};
use tracing::info;

use crate::hint::HintWrapper;
use crate::payload::OraclePayload;

/// An oracle-backed da storage.
#[derive(Debug, Clone)]
pub struct OracleCelestiaProvider<T: CommsClient> {
    oracle: Arc<T>,
}

impl<T: CommsClient + Clone> OracleCelestiaProvider<T> {
    /// Constructs a new `OracleBlobProvider`.
    pub fn new(oracle: Arc<T>) -> Self {
        Self { oracle }
    }
}

#[async_trait]
impl<T: CommsClient + Sync + Send> CelestiaProvider for OracleCelestiaProvider<T> {
    type Error = OracleProviderError;

    async fn blob_get(&self, height: u64, commitment: Commitment) -> Result<Bytes, Self::Error> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&height.to_le_bytes());
        encoded.extend_from_slice(commitment.hash());

        // Perform Inclusion checks against the data root
        let hint = Hint::new(HintWrapper::CelestiaDA, encoded.clone());

        hint.send(&*self.oracle).await?;

        let oracle_result = self
            .oracle
            .get(PreimageKey::new(
                *keccak256(encoded),
                PreimageKeyType::GlobalGeneric,
            ))
            .await?;

        let payload = OraclePayload::from_bytes(&oracle_result)
            .expect("Failed to deserialize Celestia Oracle Payload");

        // Load the boot info from the oracle.
        // *Security Note*: This BootInfo must be committed to in the program that is verified on-chain. The l1Head
        // must be verified to match a blockhash on the blockchain where this program is being verified.
        let boot = BootInfo::load(self.oracle.as_ref()).await?;

        // Get the expected blobstream address for the chain id.
        let expected_blobstream_address =
            BlobstreamChainIds::from_u64(boot.rollup_config.l1_chain_id)
                .expect("Invalid chain id")
                .blostream_address();

        // Verify the data commitment exists in storage on the supplied L1 block hash.
        verify_data_commitment_storage(
            payload.storage_root,
            payload.storage_proof,
            payload.account_proof,
            payload.proof_nonce,
            payload.data_commitment,
            expected_blobstream_address,
            payload.blobstream_balance,
            payload.blobstream_nonce,
            payload.blobstream_code_hash,
            payload.block_header,
            boot.l1_head,
        )
        .expect("Failed to verify data commitment against Blobstream storage slot");

        match payload.share_proof.verify(payload.data_root) {
            Ok(_) => info!("Celestia blobs ShareProof succesfully verified"),
            Err(err) => {
                return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                    err.to_string(),
                )))
            }
        }

        // Verify that the encoded data root tuple is valid against the data commitment in the contract.
        let encoded_data_root_tuple = encode_data_root_tuple(height, &payload.data_root);
        payload
            .data_root_tuple_proof
            .verify(encoded_data_root_tuple, *payload.data_commitment)
            .expect("Failed to verify data root tuple proof");

        Ok(payload.blob)
    }
}
