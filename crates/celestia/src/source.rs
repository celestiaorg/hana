//! Celestia Data source

use crate::traits::CelestiaProvider;

use alloc::vec::Vec;
use alloy_primitives::Bytes;
use celestia_types::Commitment;
use kona_derive::{PipelineError, PipelineErrorKind, PipelineResult};

/// Data source for Celestia DA
#[derive(Debug, Clone)]
pub struct CelestiaDASource<C>
where
    C: CelestiaProvider + Send,
{
    /// Celestia connection
    pub celestia_fetcher: C,
    /// Celestia Blobs
    pub data: Vec<Bytes>,
}

impl<C> CelestiaDASource<C>
where
    C: CelestiaProvider + Send,
{
    /// Creates a new celestia source.
    pub const fn new(celestia_fetcher: C) -> Self {
        Self {
            celestia_fetcher,
            data: Vec::new(),
        }
    }

    /// Fetches the next blob from the source.
    pub async fn next(&mut self, height: u64, commitment: Commitment) -> PipelineResult<Bytes> {
        self.load_blobs(height, commitment).await?;
        let next_data = match self.next_data() {
            Ok(d) => d,
            Err(e) => return e,
        };

        // check decoding / encoding from lumina crates
        Ok(Bytes::from(next_data))
    }

    /// Clears the source's data
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Loads blob data into the source if it is not open.
    async fn load_blobs(
        &mut self,
        height: u64,
        commitment: Commitment,
    ) -> Result<(), PipelineErrorKind> {
        info!(target: "celestia-source", "fetching blobs from celestia fetcher");
        let blob = self.celestia_fetcher.blob_get(height, commitment).await;
        match blob {
            Ok(blob) => {
                self.data.push(blob.clone());

                info!(target: "celestia-source", "load_blobs {:?}", self.data);

                Ok(())
            }
            Err(e) => {
                let pipeline_err: PipelineErrorKind = e.into();

                match pipeline_err {
                    PipelineErrorKind::Critical(pipeline_err) => {
                        return Err(PipelineErrorKind::Critical(pipeline_err))
                    }
                    PipelineErrorKind::Temporary(pipeline_err) => {
                        return Err(PipelineErrorKind::Temporary(pipeline_err))
                    }
                    PipelineErrorKind::Reset(pipeline_err) => {
                        return Err(PipelineErrorKind::Reset(pipeline_err))
                    }
                }
            }
        }
    }

    fn next_data(&mut self) -> Result<Bytes, PipelineResult<Bytes>> {
        info!(target: "celestia-source", "celestia source data empty: {:?}", self.data.is_empty());

        if self.data.is_empty() {
            return Err(Err(PipelineError::Eof.temp()));
        }
        Ok(self.data.remove(0))
    }
}
