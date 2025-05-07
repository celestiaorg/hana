use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes};
use async_trait::async_trait;
use celestia_types::Commitment;
use hana_blobstream::blobstream::{encode_data_root_tuple, verify_data_commitment_storage};
use hana_celestia::CelestiaProvider;
use kona_preimage::errors::PreimageOracleError;
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use kona_proof::errors::OracleProviderError;
use kona_proof::Hint;
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

        match payload.share_proof.verify(payload.data_root) {
            Ok(_) => info!("Celestia blobs ShareProof succesfully verified"),
            Err(err) => {
                return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                    err.to_string(),
                )))
            }
        }

        let encoded_data_root_tuple = encode_data_root_tuple(height, &payload.data_root);

        payload
            .data_root_tuple_proof
            .verify(encoded_data_root_tuple, *payload.data_commitment)
            .expect("Failed to verify data root tuple proof");

        verify_data_commitment_storage(
            payload.storage_root,
            payload.state_root,
            payload.storage_proof,
            payload.account_proof,
            payload.proof_nonce,
            payload.data_commitment,
            payload.blobstream_address,
            payload.blobstream_balance,
            payload.blobstream_nonce,
            payload.blobstream_code_hash,
            payload.block_header,
            payload.l1_block_hash,
        )
        .expect("Failed to verify data commitment against Blobstream storage slot");

        Ok(payload.blob)
    }
}
