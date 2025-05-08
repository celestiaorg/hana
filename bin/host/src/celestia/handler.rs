//! [HintHandler] for the [CelestiaaChainHost].

use alloy_primitives::{keccak256, Bytes};
use anyhow::{ensure, Result};
use async_trait::async_trait;
use celestia_rpc::BlobClient;
use celestia_types::Commitment;
use hana_oracle::{hint::HintWrapper, payload::OraclePayload};
use hana_proofs::blobstream_inclusion::get_blobstream_proof;
use kona_host::{
    single::SingleChainHintHandler, HintHandler, OnlineHostBackendCfg, SharedKeyValueStore,
};
use kona_preimage::{PreimageKey, PreimageKeyType};
use kona_proof::Hint;

use crate::celestia::cfg::CelestiaChainHost;

/// The [HintHandler] for the [CelestiaChainHost].
#[derive(Debug, Clone, Copy)]
pub struct CelestiaChainHintHandler;

#[async_trait]
impl HintHandler for CelestiaChainHintHandler {
    type Cfg = CelestiaChainHost;

    async fn fetch_hint(
        hint: Hint<<Self::Cfg as OnlineHostBackendCfg>::HintType>,
        cfg: &Self::Cfg,
        providers: &<Self::Cfg as OnlineHostBackendCfg>::Providers,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        match hint.ty {
            HintWrapper::Standard(standard_hint) => {
                let inner_hint = Hint {
                    ty: standard_hint,
                    data: hint.data,
                };

                match SingleChainHintHandler::fetch_hint(
                    inner_hint,
                    &cfg.single_host.clone(),
                    &providers.inner_providers,
                    kv,
                )
                .await
                {
                    Ok(_) => (),
                    Err(err) => anyhow::bail!("Standard Hint processing error {}", err),
                }
            }
            HintWrapper::CelestiaDA => {
                ensure!(hint.data.len() == 40, "Invalid hint data length");

                let height = u64::from_le_bytes(hint.data[0..8].try_into().unwrap());

                let hash_array: [u8; 32] =
                    hint.data[8..40].try_into().expect("Slice must be 32 bytes");
                let commitment = Commitment::new(hash_array);

                let blob = match providers
                    .celestia
                    .client
                    .blob_get(height, providers.celestia.namespace, commitment)
                    .await
                {
                    Ok(blob) => blob,
                    Err(e) => anyhow::bail!("celestia blob not found: {:#}", e),
                };

                let data = blob.data.clone();

                let blobstream_proof = get_blobstream_proof(
                    providers.celestia.client.as_ref(),
                    providers.l1(),
                    cfg.single_host.l1_head,
                    height,
                    blob,
                )
                .await?;

                let payload = OraclePayload::new(
                    Bytes::from(data),
                    blobstream_proof.data_root,
                    blobstream_proof.data_commitment,
                    blobstream_proof.data_root_tuple_proof,
                    blobstream_proof.share_proof,
                    blobstream_proof.proof_nonce,
                    blobstream_proof.storage_root,
                    blobstream_proof.storage_proof,
                    blobstream_proof.account_proof,
                    blobstream_proof.state_root,
                    blobstream_proof.blobstream_address,
                    blobstream_proof.blobstream_balance,
                    blobstream_proof.blobstream_nonce,
                    blobstream_proof.blobstream_code_hash,
                    blobstream_proof.block_header,
                    cfg.single_host.l1_head,
                )
                .to_bytes()
                .expect("failed to serialize celestia oracle payload");

                let mut kv_lock = kv.write().await;

                let celestia_commitment_hash = keccak256(&hint.data);

                // store the blob data as a the preimage behind the hash of the height + blob commitment
                kv_lock.set(
                    PreimageKey::new(*celestia_commitment_hash, PreimageKeyType::GlobalGeneric)
                        .into(),
                    payload.into(),
                )?;
            }
        }
        Ok(())
    }
}
