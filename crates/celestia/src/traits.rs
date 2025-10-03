use alloc::{boxed::Box, string::ToString};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use celestia_types::Commitment;
use core::fmt::Display;
use kona_derive::PipelineErrorKind;

/// Describes the functionality of the Celestia DA client needed to fetch a blob from calldata
#[async_trait]
pub trait CelestiaProvider {
    type Error: Display + ToString + Into<PipelineErrorKind>;

    async fn blob_get(&self, height: u64, commitment: Commitment) -> Result<Bytes, Self::Error>;
}
