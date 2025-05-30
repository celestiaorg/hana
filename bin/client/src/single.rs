use alloc::sync::Arc;
use alloy_consensus::Sealed;
use alloy_evm::{EvmFactory, FromRecoveredTx, FromTxWithEncoded};
use alloy_primitives::B256;
use core::fmt::Debug;
use hana_celestia::{CelestiaDADataSource, CelestiaDASource};
use hana_oracle::provider::OracleCelestiaProvider;
use kona_client::single::FaultProofProgramError;
use kona_derive::sources::EthereumDataSource;
use kona_driver::Driver;
use kona_executor::TrieDBProvider;
use kona_preimage::{CommsClient, HintWriterClient, PreimageKey, PreimageOracleClient};
use kona_proof::{
    errors::OracleProviderError,
    executor::KonaExecutor,
    l1::{OracleBlobProvider, OracleL1ChainProvider, OraclePipeline},
    l2::OracleL2ChainProvider,
    sync::new_oracle_pipeline_cursor,
    BootInfo, CachingOracle, HintType,
};
use op_alloy_consensus::OpTxEnvelope;
use op_revm::OpSpecId;
use tracing::{error, info};

/// Executes the fault proof program with the given [PreimageOracleClient] and [HintWriterClient].
#[inline]
pub async fn run<P, H, Evm>(
    oracle_client: P,
    hint_client: H,
    evm_factory: Evm,
) -> Result<(), FaultProofProgramError>
where
    P: PreimageOracleClient + Send + Sync + Debug + Clone,
    H: HintWriterClient + Send + Sync + Debug + Clone,
    Evm: EvmFactory<Spec = OpSpecId> + Send + Sync + Debug + Clone + 'static,
    <Evm as EvmFactory>::Tx: FromTxWithEncoded<OpTxEnvelope> + FromRecoveredTx<OpTxEnvelope>,
{
    const ORACLE_LRU_SIZE: usize = 1024;

    ////////////////////////////////////////////////////////////////
    //                          PROLOGUE                          //
    ////////////////////////////////////////////////////////////////

    let oracle = Arc::new(CachingOracle::new(
        ORACLE_LRU_SIZE,
        oracle_client,
        hint_client,
    ));
    let boot = match BootInfo::load(oracle.as_ref()).await {
        Ok(boot) => boot,
        Err(e) => {
            return Err(FaultProofProgramError::OracleProviderError(e));
        }
    };
    let rollup_config = Arc::new(boot.rollup_config);
    let safe_head_hash = fetch_safe_head_hash(oracle.as_ref(), boot.agreed_l2_output_root).await?;

    let mut l1_provider = OracleL1ChainProvider::new(boot.l1_head, oracle.clone());
    let mut l2_provider =
        OracleL2ChainProvider::new(safe_head_hash, rollup_config.clone(), oracle.clone());
    let beacon = OracleBlobProvider::new(oracle.clone());

    // Fetch the safe head's block header.
    let safe_head = l2_provider
        .header_by_hash(safe_head_hash)
        .map(|header| Sealed::new_unchecked(header, safe_head_hash))?;

    // If the claimed L2 block number is less than the safe head of the L2 chain, the claim is
    // invalid.
    if boot.claimed_l2_block_number < safe_head.number {
        error!(
            target: "client",
            "Claimed L2 block number {claimed} is less than the safe head {safe}",
            claimed = boot.claimed_l2_block_number,
            safe = safe_head.number
        );
        return Err(FaultProofProgramError::InvalidClaim(
            boot.agreed_l2_output_root,
            boot.claimed_l2_output_root,
        ));
    }

    // In the case where the agreed upon L2 output root is the same as the claimed L2 output root,
    // trace extension is detected and we can skip the derivation and execution steps.
    if boot.agreed_l2_output_root == boot.claimed_l2_output_root {
        info!(
            target: "client",
            "Trace extension detected. State transition is already agreed upon.",
        );
        return Ok(());
    }

    ////////////////////////////////////////////////////////////////
    //                   DERIVATION & EXECUTION                   //
    ////////////////////////////////////////////////////////////////

    // Create a new derivation driver with the given boot information and oracle.
    let cursor = new_oracle_pipeline_cursor(
        rollup_config.as_ref(),
        safe_head,
        &mut l1_provider,
        &mut l2_provider,
    )
    .await?;
    l2_provider.set_cursor(cursor.clone());

    let ethereum_data_source =
        EthereumDataSource::new_from_parts(l1_provider.clone(), beacon, &rollup_config);
    let celestia_data_source = CelestiaDASource::new(OracleCelestiaProvider::new(oracle.clone()));
    let da_provider = CelestiaDADataSource::new(ethereum_data_source, celestia_data_source);

    let pipeline = OraclePipeline::new(
        rollup_config.clone(),
        cursor.clone(),
        oracle.clone(),
        da_provider,
        l1_provider.clone(),
        l2_provider.clone(),
    )
    .await?;
    let executor = KonaExecutor::new(
        rollup_config.as_ref(),
        l2_provider.clone(),
        l2_provider,
        evm_factory,
        None,
    );
    let mut driver = Driver::new(cursor, executor, pipeline);

    // Run the derivation pipeline until we are able to produce the output root of the claimed
    // L2 block.
    let (safe_head, output_root) = driver
        .advance_to_target(rollup_config.as_ref(), Some(boot.claimed_l2_block_number))
        .await?;

    ////////////////////////////////////////////////////////////////
    //                          EPILOGUE                          //
    ////////////////////////////////////////////////////////////////

    if output_root != boot.claimed_l2_output_root {
        error!(
            target: "client",
            "Failed to validate L2 block #{number} with output root {output_root}",
            number = safe_head.block_info.number,
            output_root = output_root
        );
        return Err(FaultProofProgramError::InvalidClaim(
            output_root,
            boot.claimed_l2_output_root,
        ));
    }

    info!(
        target: "client",
        "Successfully validated L2 block #{number} with output root {output_root}",
        number = safe_head.block_info.number,
        output_root = output_root
    );

    Ok(())
}

/// Fetches the safe head hash of the L2 chain based on the agreed upon L2 output root in the
/// [BootInfo].
pub async fn fetch_safe_head_hash<O>(
    caching_oracle: &O,
    agreed_l2_output_root: B256,
) -> Result<B256, OracleProviderError>
where
    O: CommsClient,
{
    let mut output_preimage = [0u8; 128];
    HintType::StartingL2Output
        .with_data(&[agreed_l2_output_root.as_ref()])
        .send(caching_oracle)
        .await?;
    caching_oracle
        .get_exact(
            PreimageKey::new_keccak256(*agreed_l2_output_root),
            output_preimage.as_mut(),
        )
        .await?;

    output_preimage[96..128]
        .try_into()
        .map_err(OracleProviderError::SliceConversion)
}
