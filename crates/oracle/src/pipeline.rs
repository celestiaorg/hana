use alloc::{boxed::Box, sync::Arc};
use async_trait::async_trait;
use core::fmt::Debug;
use hana_celestia::{CelestiaDADataSource, CelestiaDASource, CelestiaProvider};
use kona_derive::{
    attributes::StatefulAttributesBuilder,
    errors::PipelineErrorKind,
    pipeline::{DerivationPipeline, PipelineBuilder},
    sources::EthereumDataSource,
    stages::{
        AttributesQueue, BatchProvider, BatchStream, ChannelProvider, ChannelReader, FrameQueue,
        L1Retrieval, L1Traversal,
    },
    traits::{BlobProvider, L2ChainProvider, OriginProvider, Pipeline, SignalReceiver},
    types::{PipelineResult, ResetSignal, Signal, StepResult},
};
use kona_driver::{DriverPipeline, PipelineCursor};
use kona_genesis::{RollupConfig, SystemConfig};
use kona_preimage::CommsClient;
use kona_proof::{l1::OracleL1ChainProvider, l2::OracleL2ChainProvider, FlushableCache};
use kona_protocol::{BlockInfo, L2BlockInfo};
use kona_rpc::OpAttributesWithParent;
use spin::RwLock;

/// An oracle-backed derivation pipeline
pub type OracleDerivationPipeline<O, B, C> = DerivationPipeline<
    OracleAttributesQueue<OracleDataProvider<O, B, C>, O>,
    OracleL2ChainProvider<O>,
>;

/// An oracle-backed Celestia data source.
pub type OracleDataProvider<O, B, C> = CelestiaDADataSource<OracleL1ChainProvider<O>, B, C>;

/// An oracle-backed payload attributes builder for the `AttributesQueue` stage of the derivation
/// pipeline.
pub type OracleAttributesBuilder<O> =
    StatefulAttributesBuilder<OracleL1ChainProvider<O>, OracleL2ChainProvider<O>>;

/// An oracle-backed attributes queue for the derivation pipeline.
pub type OracleAttributesQueue<DAP, O> = AttributesQueue<
    BatchProvider<
        BatchStream<
            ChannelReader<
                ChannelProvider<
                    FrameQueue<L1Retrieval<DAP, L1Traversal<OracleL1ChainProvider<O>>>>,
                >,
            >,
            OracleL2ChainProvider<O>,
        >,
        OracleL2ChainProvider<O>,
    >,
    OracleAttributesBuilder<O>,
>;

/// An oracle-backed derivation pipeline.
#[derive(Debug)]
pub struct OraclePipeline<O, B, C>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    C: CelestiaProvider + Send + Sync + Debug + Clone,
{
    /// The internal derivation pipeline.
    pub pipeline: OracleDerivationPipeline<O, B, C>,
    /// The caching oracle.
    pub caching_oracle: Arc<O>,
}

impl<O, B, C> OraclePipeline<O, B, C>
where
    O: CommsClient + FlushableCache + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    C: CelestiaProvider + Send + Sync + Debug + Clone,
{
    /// Constructs a new oracle-backed derivation pipeline.
    pub async fn new(
        cfg: Arc<RollupConfig>,
        sync_start: Arc<RwLock<PipelineCursor>>,
        caching_oracle: Arc<O>,
        blob_provider: B,
        chain_provider: OracleL1ChainProvider<O>,
        mut l2_chain_provider: OracleL2ChainProvider<O>,
        celestia_provider: C,
    ) -> PipelineResult<Self> {
        let attributes = StatefulAttributesBuilder::new(
            cfg.clone(),
            l2_chain_provider.clone(),
            chain_provider.clone(),
        );
        let dap = EthereumDataSource::new_from_parts(chain_provider.clone(), blob_provider, &cfg);
        let celestia_data_source = CelestiaDASource::new(celestia_provider);
        let dap = CelestiaDADataSource::new(dap, celestia_data_source);

        let mut pipeline = PipelineBuilder::new()
            .rollup_config(cfg.clone())
            .dap_source(dap)
            .l2_chain_provider(l2_chain_provider.clone())
            .chain_provider(chain_provider)
            .builder(attributes)
            .origin(sync_start.read().origin())
            .build();

        // Reset the pipeline to populate the initial system configuration in L1 Traversal.
        let l2_safe_head = *sync_start.read().l2_safe_head();
        pipeline
            .signal(
                ResetSignal {
                    l2_safe_head,
                    l1_origin: sync_start.read().origin(),
                    system_config: l2_chain_provider
                        .system_config_by_number(l2_safe_head.block_info.number, cfg.clone())
                        .await
                        .ok(),
                }
                .signal(),
            )
            .await?;

        Ok(Self {
            pipeline,
            caching_oracle,
        })
    }
}

impl<O, B, C> DriverPipeline<OracleDerivationPipeline<O, B, C>> for OraclePipeline<O, B, C>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    C: CelestiaProvider + Send + Sync + Debug + Clone,
{
    /// Flushes the cache on re-org.
    fn flush(&mut self) {
        self.caching_oracle.flush();
    }
}

#[async_trait]
impl<O, B, C> SignalReceiver for OraclePipeline<O, B, C>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    C: CelestiaProvider + Send + Sync + Debug + Clone,
{
    /// Receives a signal from the driver.
    async fn signal(&mut self, signal: Signal) -> PipelineResult<()> {
        self.pipeline.signal(signal).await
    }
}

impl<O, B, C> OriginProvider for OraclePipeline<O, B, C>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    C: CelestiaProvider + Send + Sync + Debug + Clone,
{
    /// Returns the optional L1 [BlockInfo] origin.
    fn origin(&self) -> Option<BlockInfo> {
        self.pipeline.origin()
    }
}

impl<O, B, C> Iterator for OraclePipeline<O, B, C>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    C: CelestiaProvider + Send + Sync + Debug + Clone,
{
    type Item = OpAttributesWithParent;

    fn next(&mut self) -> Option<Self::Item> {
        self.pipeline.next()
    }
}

#[async_trait]
impl<O, B, C> Pipeline for OraclePipeline<O, B, C>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    C: CelestiaProvider + Send + Sync + Debug + Clone,
{
    /// Peeks at the next [OpAttributesWithParent] from the pipeline.
    fn peek(&self) -> Option<&OpAttributesWithParent> {
        self.pipeline.peek()
    }

    /// Attempts to progress the pipeline.
    async fn step(&mut self, cursor: L2BlockInfo) -> StepResult {
        self.pipeline.step(cursor).await
    }

    /// Returns the rollup config.
    fn rollup_config(&self) -> &RollupConfig {
        self.pipeline.rollup_config()
    }

    /// Returns the [SystemConfig] by L2 number.
    async fn system_config_by_number(
        &mut self,
        number: u64,
    ) -> Result<SystemConfig, PipelineErrorKind> {
        self.pipeline.system_config_by_number(number).await
    }
}
