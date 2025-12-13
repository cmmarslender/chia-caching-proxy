use crate::proxy_client::ProxyRpcClient;
use crate::wallet_sdk_extensions::cat1::Cat1;
use crate::wallet_sdk_extensions::cat1_info::Cat1Info;
use crate::wallet_sdk_extensions::nft_metadata::NftMetadata;
use anyhow::Context;
use chia_caching_proxy::coin_info::{
    CatInfoResponse, CoinType, GetCoinInfoRequest, GetCoinInfoResponse, NftInfoResponse,
};
use chia_wallet_sdk::clvmr::Allocator;
use chia_wallet_sdk::driver::{Cat, CatInfo, NftInfo, Puzzle};
use chia_wallet_sdk::prelude::{Address, ChiaRpcClient, FromClvm, ToClvm};
use hyper::body::Bytes;
use std::sync::Arc;

pub async fn handle_get_coin_info(
    body_bytes: Bytes,
    proxy_rpc_client: Arc<ProxyRpcClient>,
) -> anyhow::Result<Bytes> {
    // Parse the request body
    let request_data: GetCoinInfoRequest = serde_json::from_slice(&body_bytes)?;

    let Some(coin_record) = proxy_rpc_client
        .get_coin_record_by_name(request_data.name)
        .await?
        .coin_record
    else {
        anyhow::bail!("Can't find requested coin");
    };

    let mut response = GetCoinInfoResponse {
        coin_id: request_data.name,
        ..Default::default()
    };

    // Check for coinbase/farming reward
    if !coin_record.coinbase {
        let mut allocator = Allocator::default();

        let parent_puz_solution = proxy_rpc_client
            .get_puzzle_and_solution(
                coin_record.coin.parent_coin_info,
                Some(coin_record.confirmed_block_index),
            )
            .await?;
        let parent_coin_spend = parent_puz_solution.coin_solution.context("No coin")?;

        let parent_puzzle_program = &parent_coin_spend.puzzle_reveal;
        let outer_puz_ptr = parent_puzzle_program
            .to_clvm(&mut allocator)
            .context("Failed to convert to CLVM")?;
        let parent_puzzle = Puzzle::parse(&allocator, outer_puz_ptr);

        let parent_solution_program = parent_coin_spend.solution;
        let parent_solution_ptr = parent_solution_program
            .to_clvm(&mut allocator)
            .context("Failed to convert to CLVM")?;

        // Compute address using CatInfo::parse (only works for CAT2)
        if let Some((parent_cat_info, _puzzle)) = CatInfo::parse(&allocator, parent_puzzle)? {
            let cat_children = Cat::parse_children(
                &mut allocator,
                parent_coin_spend.coin,
                parent_puzzle,
                parent_solution_ptr,
            )?
            .context("Parent CAT has no children")?;
            let child_cat = cat_children
                .iter()
                .find(|cat| cat.coin.coin_id() == request_data.name)
                .context("Could not find CAT from its parent")?;

            response.coin_type = if parent_cat_info.hidden_puzzle_hash.is_some() {
                CoinType::RevocableCat2
            } else {
                CoinType::Cat2
            };
            response.cat_info = Some(CatInfoResponse {
                asset_id: parent_cat_info.asset_id,
                from_puzzle_hash: parent_cat_info.p2_puzzle_hash,
                from_address: Address::new(parent_cat_info.p2_puzzle_hash, "xch".to_string())
                    .encode()?,
                to_puzzle_hash: child_cat.info.p2_puzzle_hash,
                to_address: Address::new(child_cat.info.p2_puzzle_hash, "xch".to_string())
                    .encode()?,
            });
        }

        if let Some((nft_info, _puzzle)) = NftInfo::parse(&allocator, parent_puzzle)? {
            let nft_meta_ptr = nft_info.metadata.ptr();
            let metadata = NftMetadata::from_clvm(&allocator, nft_meta_ptr)?;
            response.coin_type = CoinType::Nft;
            response.nft_info = Some(NftInfoResponse {
                launcher_id: nft_info.launcher_id,
                data_uris: metadata.data_uris,
                meta_uris: metadata.metadata_uris,
                edition_number: metadata.edition_number,
                edition_total: metadata.edition_total,
                license_uris: metadata.license_uris,
                owner_did: nft_info.current_owner,
            });
        }

        if let Some((parent_cat_info, _puzzle)) = Cat1Info::parse(&allocator, parent_puzzle)? {
            let cat_children = Cat1::parse_children(
                &mut allocator,
                parent_coin_spend.coin,
                parent_puzzle,
                parent_solution_ptr,
            )?
            .context("Parent CAT has no children")?;
            let child_cat = cat_children
                .iter()
                .find(|cat| cat.coin.coin_id() == request_data.name)
                .context("Could not find CAT from its parent")?;

            response.coin_type = CoinType::Cat1;
            response.cat_info = Some(CatInfoResponse {
                asset_id: parent_cat_info.asset_id,
                from_puzzle_hash: parent_cat_info.p2_puzzle_hash,
                from_address: Address::new(parent_cat_info.p2_puzzle_hash, "xch".to_string())
                    .encode()?,
                to_puzzle_hash: child_cat.info.p2_puzzle_hash,
                to_address: Address::new(child_cat.info.p2_puzzle_hash, "xch".to_string())
                    .encode()?,
            });
        }
    }

    response.success = true;
    let json_body = serde_json::json!(response).to_string();
    Ok(Bytes::from(json_body))
}
