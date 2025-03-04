//! [HintHandler] for the [CelestiaaChainHost].
use alloy_primitives::{keccak256, Bytes};
use anyhow::{ensure, Result};
use async_trait::async_trait;
use celestia_rpc::BlobClient;
use celestia_types::Commitment;
use hana_oracle::hint::HintWrapper;
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

                let data = match providers
                    .celestia
                    .client
                    .blob_get(height, providers.celestia.namespace, commitment)
                    .await
                {
                    Ok(blob) => Bytes::from(blob.data),
                    Err(e) => anyhow::bail!("celestia blob not found: {:#}", e),
                };

                let mut kv_lock = kv.write().await;

                let celestia_commitment_hash = keccak256(&hint.data);

                // store the preimage to the celestia commitment using the GlobalGeneric key
                kv_lock.set(
                    PreimageKey::new(*celestia_commitment_hash, PreimageKeyType::GlobalGeneric)
                        .into(),
                    data.into(),
                )?;
            }
        }
        Ok(())
    }
}
