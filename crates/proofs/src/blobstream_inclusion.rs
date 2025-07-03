use alloc::{boxed::Box, vec::Vec};
use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::{
    BlockId, BlockNumberOrTag, Filter, FilterBlockOption, FilterSet, RpcBlockHash,
};
use alloy_sol_types::SolEvent;
use anyhow::ensure;
use celestia_rpc::{blobstream::BlobstreamClient, Client, HeaderClient, ShareClient};
use celestia_types::{Blob, DataAvailabilityHeader};
use hana_blobstream::blobstream::{
    blobstream_address, calculate_mapping_slot, encode_data_root_tuple, verify_data_commitment,
    BlobstreamProof, SP1Blobstream, SP1BlobstreamDataCommitmentStored, DATA_COMMITMENTS_SLOT,
};
use tracing::info;

// Geth has a default of 5000 block limit for filters
const FILTER_BLOCK_RANGE: u64 = 5000;

/// Find the data commitment  that contains the given Celestia height by parsing event logs
/// This function assumes that the l1_head_block_number is one such that the event for relaying
/// the celestia_height in question has already passed, its up to implementation on how to do this,
/// Example: https://github.com/succinctlabs/op-succinct/blob/46482d3f21eb435b4cffae6c80d14bf3cc1c6e19/utils/celestia/host/src/host.rs#L40C17-L40C98
pub async fn find_data_commitment(
    celestia_height: u64,
    blobstream_address: Address,
    eth_provider: &RootProvider,
    l1_head_block_number: u64,
) -> Result<SP1BlobstreamDataCommitmentStored, Box<dyn core::error::Error>> {
    // Calculate event signature manually for reliability
    let event_signature = "DataCommitmentStored(uint256,uint64,uint64,bytes32)";
    let event_selector = keccak256(event_signature.as_bytes());
    let topic0: FilterSet<B256> = vec![event_selector.into()].into();

    // Start from the given Ethereum block height and scan backwards
    let mut end = l1_head_block_number;
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
            if let Ok(event) = SP1Blobstream::DataCommitmentStored::decode_log(&log.clone().into())
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
    l1_head: FixedBytes<32>,
    height: u64,
    blob: Blob,
) -> Result<BlobstreamProof, anyhow::Error> {
    let l1_block = l1_provider.get_block_by_hash(l1_head).await?.unwrap();

    let block_id = BlockId::Hash(RpcBlockHash::from(B256::from(l1_head)));

    let block_header = l1_block.header;
    let chain_id = l1_provider.get_chain_id().await?;

    let blobstream_address =
        blobstream_address(chain_id).expect("No canonical Blobstream address found for chain id");

    // Fetch the block's data root
    let header = celestia_node.header_get_by_height(height).await?;

    // values needed to verify account proof
    let blobstream_balance = l1_provider
        .get_balance(blobstream_address)
        .block_id(block_id)
        .await?;

    let code = l1_provider
        .get_code_at(blobstream_address)
        .block_id(block_id)
        .await?;

    let blobstream_code_hash: B256;
    if code.is_empty() {
        anyhow::bail!("Error getting blobstream code hash (address has no code)")
    } else {
        blobstream_code_hash = B256::from(alloy_primitives::keccak256(&code));
    }

    let blobstream_nonce = l1_provider
        .get_transaction_count(blobstream_address)
        .block_id(block_id)
        .await?;

    // celestia data root
    let blob_index = match blob.index {
        Some(index) => index,
        None => anyhow::bail!("Could not get blob index for blobstream proof"),
    };
    let data_root = header.dah.hash();
    let (start_index, end_index) =
        calculate_indices(header.dah.clone(), blob_index, blob.shares_len() as u64);

    let share_proof = celestia_node
        .share_get_range(&header, start_index, end_index)
        .await
        .expect("Failed getting share proof")
        .proof;

    // validate the proof before placing it on the KV store
    match share_proof.verify(data_root) {
        Ok(_) => info!("Celestia share proof succesfully verified!"),
        Err(err) => return Err(err.into()),
    }

    let event = find_data_commitment(height, blobstream_address, l1_provider, block_header.number)
        .await
        .unwrap();

    let data_root_proof = celestia_node
        .blobstream_get_data_root_tuple_inclusion_proof(height, event.start_block, event.end_block)
        .await?;

    let encoded_data_root_tuple = encode_data_root_tuple(height, &data_root);

    data_root_proof
        .verify(encoded_data_root_tuple, *event.data_commitment.clone())
        .expect("failed to verify data root tuple inclusion proof");

    let slot = calculate_mapping_slot(DATA_COMMITMENTS_SLOT, event.proof_nonce);

    let slot_b256 = B256::from_slice(slot.as_slice());

    let proof_response = l1_provider
        .get_proof(blobstream_address, vec![slot_b256])
        .block_id(block_id)
        .await?;

    ensure!(
        proof_response.address == blobstream_address,
        "storage proof address does not match blobstream address"
    );

    // get blobstream address from L1 Provider, check against the proof and also verify in program

    let proof_bytes: Vec<Bytes> = proof_response
        .storage_proof
        .into_iter()
        .flat_map(|proof| proof.proof.into_iter().map(|bytes| bytes))
        .collect();

    match verify_data_commitment(
        proof_response.storage_hash,
        proof_bytes.clone(),
        proof_response.account_proof.clone(),
        event.proof_nonce,
        event.data_commitment,
        blobstream_address,
        blobstream_balance,
        blobstream_nonce,
        blobstream_code_hash,
        block_header.inner.clone(),
        l1_head,
    ) {
        Ok(_) => {
            println!("Succesfully verified Blobstream data commitment");

            return Ok(BlobstreamProof::new(
                data_root,
                event.data_commitment,
                data_root_proof,
                share_proof,
                event.proof_nonce,
                proof_response.storage_hash.clone(),
                proof_bytes,
                proof_response.account_proof,
                blobstream_balance,
                blobstream_nonce,
                blobstream_code_hash,
                block_header.inner.clone(),
            ));
        }
        Err(err) => return Err(err.into()),
    }
}

fn calculate_indices(
    data_availability_header: DataAvailabilityHeader,
    blob_index: u64,
    shares_length: u64,
) -> (u64, u64) {
    let eds_row_roots = data_availability_header.row_roots();
    let eds_size: u64 = eds_row_roots.len().try_into().unwrap();
    let ods_size: u64 = eds_size / 2;

    let first_row_index: u64 = blob_index / eds_size;
    let start_index = blob_index - (first_row_index * ods_size);
    let end_index = start_index + shares_length;

    (start_index, end_index)
}
