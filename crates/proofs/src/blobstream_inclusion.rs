use alloc::{boxed::Box, vec::Vec};
use alloy_primitives::{hex, keccak256, Address, Bytes as AlloyBytes, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::{BlockNumberOrTag, Filter, FilterBlockOption, FilterSet};
use alloy_sol_types::SolEvent;
use celestia_rpc::{blobstream::BlobstreamClient, Client, HeaderClient, ShareClient};
use celestia_types::{nmt::Namespace, Blob};
use hana_blobstream::blobstream::{
    calculate_mapping_slot, encode_data_root_tuple, find_pfb_with_commitment,
    verify_data_commitment_storage, BlobstreamProof,
    SP1Blobstream::{self},
    SP1BlobstreamDataCommitmentStored, DATA_COMMITMENTS_SLOT,
};

use tracing::info;

// Geth has a default of 5000 block limit for filters
const FILTER_BLOCK_RANGE: u64 = 5000;

/// Find the data commitment  that contains the given Celestia height by parsing event logs
pub async fn find_data_commitment(
    celestia_height: u64,
    blobstream_address: Address,
    eth_provider: &RootProvider,
) -> Result<SP1BlobstreamDataCommitmentStored, Box<dyn core::error::Error>> {
    let eth_block_height = eth_provider.get_block_number().await?;
    // Calculate event signature manually for reliability
    let event_signature = "DataCommitmentStored(uint256,uint64,uint64,bytes32)";
    let event_selector = keccak256(event_signature.as_bytes());
    let topic0: FilterSet<B256> = vec![event_selector.into()].into();

    // Start from the given Ethereum block height and scan backwards
    let mut end = eth_block_height;
    let mut start = if end > FILTER_BLOCK_RANGE {
        end - FILTER_BLOCK_RANGE
    } else {
        0
    };

    loop {
        // Create filter for DataCommitmentStored events
        let filter = Filter {
            block_option: FilterBlockOption::Range {
                from_block: Some(BlockNumberOrTag::Number(start.into())),
                to_block: Some(BlockNumberOrTag::Number(end.into())),
            },
            address: vec![blobstream_address].into(),
            topics: [
                topic0.clone(),
                Default::default(),
                Default::default(),
                Default::default(),
            ],
        };

        // Get logs using the client reference
        let logs = eth_provider.get_logs(&filter).await?;

        // Parse logs using the generated event type
        for log in logs {
            // Try to decode the log using SP1Blobstream's generated event decoder
            if let Ok(event) =
                SP1Blobstream::DataCommitmentStored::decode_log(&log.clone().into(), true)
            {
                // Check if this event contains the celestia_height
                if event.startBlock <= celestia_height && celestia_height < event.endBlock {
                    let stored_event = SP1BlobstreamDataCommitmentStored {
                        proof_nonce: event.proofNonce,
                        start_block: event.startBlock,
                        end_block: event.endBlock,
                        data_commitment: event.dataCommitment,
                    };

                    info!(
                        "Found Data Root submission event block_number={} proof_nonce={} start={} end={}",
                        log.clone().block_number.unwrap(),
                        stored_event.proof_nonce,
                        stored_event.start_block,
                        stored_event.end_block
                    );

                    return Ok(stored_event);
                }
            }
        }

        // If we've reached the beginning of the chain, stop
        if start == 0 {
            return Err("No matching event found for the given Celestia height".into());
        }

        // Move to the previous batch
        end = start;
        start = if end > FILTER_BLOCK_RANGE {
            end - FILTER_BLOCK_RANGE
        } else {
            0
        };
    }
}

/// Fetches a `BlobstreamProof` for the given blob, height, and blobstream contract address
pub async fn get_blobstream_proof(
    celestia_node: &Client,
    l1_provider: &RootProvider,
    height: u64,
    blob: Blob,
    blobstream_address: Address,
) -> Result<BlobstreamProof, anyhow::Error> {
    // Fetch the block's data root
    let header = celestia_node.header_get_by_height(height).await?;
    let data_root = header.dah.hash();

    let namespace_data = celestia_node
        .share_get_namespace_data(&header, Namespace::PAY_FOR_BLOB)
        .await?;

    let pfb = find_pfb_with_commitment(&namespace_data, &blob.commitment)?;

    for msg in pfb {
        info!("Matched PFB: {:?}", msg);
        info!(
            "Commitment: {:?}, expected: {:?}",
            hex::encode(msg.0.share_commitments[0].clone()),
            hex::encode(blob.commitment.hash())
        );

        info!("Start {:?} and End {:?}", msg.1 .0, msg.1 .1);
        info!(
            "Start u64 {:?} and End u64{:?}",
            msg.1 .0 as u64, msg.1 .1 as u64
        );
        let shares_proof = celestia_node
            .share_get_range(&header, msg.1 .0 as u64, msg.1 .1 as u64)
            .await
            .expect("Failed getting share proof");

        let share_proof = shares_proof.proof;

        share_proof
            .verify(data_root)
            .expect("failed to verify share proof against data root");

        let event = find_data_commitment(height, blobstream_address, l1_provider)
            .await
            .unwrap();

        let data_root_proof = celestia_node
            .get_data_root_tuple_inclusion_proof(height, event.start_block, event.end_block)
            .await?;

        let encoded_data_root_tuple = encode_data_root_tuple(height, &data_root);

        data_root_proof
            .verify(encoded_data_root_tuple, *event.data_commitment.clone())
            .expect("failed to verify data root tuple inclusion proof");

        let slot = calculate_mapping_slot(DATA_COMMITMENTS_SLOT, event.proof_nonce);

        let slot_b256 = B256::from_slice(slot.as_slice());

        let proof_response = l1_provider
            .get_proof(blobstream_address, vec![slot_b256])
            .await?;

        let proof_bytes: Vec<AlloyBytes> = proof_response
            .storage_proof
            .into_iter()
            .flat_map(|proof| {
                // Extract the proof field and apply any needed transformations
                proof.proof.into_iter().map(|bytes| {
                    // You can apply transformations here if needed
                    // For example: Bytes::from(some_transformation(bytes))
                    // But in this case, we can just return the bytes directly
                    bytes
                })
            })
            .collect();

        match verify_data_commitment_storage(
            proof_response.storage_hash,
            proof_bytes.clone(),
            event.proof_nonce,
            event.data_commitment,
        ) {
            Ok(_) => {
                println!("Succesfully verified storage proof for Blobstream data commitment");

                return Ok(BlobstreamProof::new(
                    data_root,
                    event.data_commitment,
                    data_root_proof,
                    share_proof,
                    namespace_data,
                    event.proof_nonce,
                    proof_response.storage_hash.clone(),
                    proof_bytes,
                ));
            }
            Err(err) => anyhow::bail!("Error verifying storage proof {}", err),
        }
    }

    anyhow::bail!("could not find shares with pfb commitment")
}
