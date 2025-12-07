use chia_wallet_sdk::prelude::Bytes32;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CoinType {
    #[serde(rename = "xch")]
    #[default]
    Xch,

    #[serde(rename = "cat1")]
    Cat1,

    #[serde(rename = "cat2")]
    Cat2,

    #[serde(rename = "revocable-cat2")]
    RevocableCat2,

    #[serde(rename = "nft")]
    Nft,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct GetCoinInfoRequest {
    pub name: Bytes32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CatInfoResponse {
    pub asset_id: Bytes32,
    pub from_puzzle_hash: Bytes32,
    pub from_address: String,
    pub to_puzzle_hash: Bytes32,
    pub to_address: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NftInfoResponse {
    pub launcher_id: Bytes32,
    pub data_uris: Vec<String>,
    pub meta_uris: Vec<String>,
    pub edition_number: u64,
    pub edition_total: u64,
    pub license_uris: Vec<String>,
    pub owner_did: Option<Bytes32>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct GetCoinInfoResponse {
    pub success: bool,
    pub coin_id: Bytes32,
    pub coin_type: CoinType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cat_info: Option<CatInfoResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nft_info: Option<NftInfoResponse>,
}
