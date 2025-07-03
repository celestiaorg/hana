use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes};
use async_trait::async_trait;
use celestia_types::Commitment;
use hana_blobstream::blobstream::{
    blobstream_address, encode_data_root_tuple, verify_data_commitment,
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
        let expected_blobstream_address = blobstream_address(boot.rollup_config.l1_chain_id)
            .expect("No canonical Blobstream address found for chain id");

        // Verify the data commitment exists in storage on the supplied L1 block hash.
        match verify_data_commitment(
            payload.blobstream_proof.storage_root,
            payload.blobstream_proof.storage_proof,
            payload.blobstream_proof.account_proof,
            payload.blobstream_proof.proof_nonce,
            payload.blobstream_proof.data_commitment,
            expected_blobstream_address,
            payload.blobstream_proof.blobstream_balance,
            payload.blobstream_proof.blobstream_nonce,
            payload.blobstream_proof.blobstream_code_hash,
            payload.blobstream_proof.block_header,
            boot.l1_head,
        ) {
            Ok(_) => info!("Celestia data commitment succesfully verified!"),
            Err(err) => {
                return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                    err.to_string(),
                )))
            }
        }

        match payload
            .blobstream_proof
            .share_proof
            .verify(payload.blobstream_proof.data_root)
        {
            Ok(_) => info!("Celestia blobs ShareProof succesfully verified!"),
            Err(err) => {
                return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                    err.to_string(),
                )))
            }
        }

        // Verify that the encoded data root tuple is valid against the data commitment in the contract.
        let encoded_data_root_tuple =
            encode_data_root_tuple(height, &payload.blobstream_proof.data_root);
        match payload.blobstream_proof.data_root_tuple_proof.verify(
            encoded_data_root_tuple,
            payload.blobstream_proof.data_commitment.0,
        ) {
            Ok(_) => {
                info!("Celestia data root tuple succesfully verified!")
            }
            Err(err) => {
                return Err(OracleProviderError::Preimage(PreimageOracleError::Other(
                    err.to_string(),
                )))
            }
        }

        Ok(payload.blob)
    }
}
