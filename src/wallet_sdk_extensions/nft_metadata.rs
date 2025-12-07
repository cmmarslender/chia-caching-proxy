use chia_wallet_sdk::prelude::clvm_traits::{
    ClvmDecoder, ClvmEncoder, FromClvmError, Raw, ToClvmError,
};
use chia_wallet_sdk::prelude::{Bytes32, FromClvm, ToClvm};

// @TODO This whole file is only required until this PR https://github.com/Chia-Network/chia_rs/pull/1310
// is merged, and then wallet SDK is updated to use that version.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftMetadata {
    pub edition_number: u64,
    pub edition_total: u64,
    pub data_uris: Vec<String>,
    pub data_hash: Option<Bytes32>,
    pub metadata_uris: Vec<String>,
    pub metadata_hash: Option<Bytes32>,
    pub license_uris: Vec<String>,
    pub license_hash: Option<Bytes32>,
}

impl Default for NftMetadata {
    fn default() -> Self {
        Self {
            edition_number: 1,
            edition_total: 1,
            data_uris: Vec::new(),
            data_hash: None,
            metadata_uris: Vec::new(),
            metadata_hash: None,
            license_uris: Vec::new(),
            license_hash: None,
        }
    }
}

impl<N, D: ClvmDecoder<Node = N>> FromClvm<D> for NftMetadata {
    fn from_clvm(decoder: &D, node: N) -> Result<Self, FromClvmError> {
        let items: Vec<(String, Raw<N>)> = FromClvm::from_clvm(decoder, node)?;
        let mut metadata = Self::default();

        for (key, value_ptr) in items {
            match key.as_str() {
                "sn" => {
                    metadata.edition_number =
                        FromClvm::from_clvm(decoder, value_ptr.0).unwrap_or(1);
                }
                "st" => {
                    metadata.edition_total = FromClvm::from_clvm(decoder, value_ptr.0).unwrap_or(1);
                }
                "u" => {
                    metadata.data_uris =
                        FromClvm::from_clvm(decoder, value_ptr.0).unwrap_or_default();
                }
                "h" => {
                    metadata.data_hash =
                        FromClvm::from_clvm(decoder, value_ptr.0).unwrap_or_default();
                }
                "mu" => {
                    metadata.metadata_uris =
                        FromClvm::from_clvm(decoder, value_ptr.0).unwrap_or_default();
                }
                "mh" => {
                    metadata.metadata_hash =
                        FromClvm::from_clvm(decoder, value_ptr.0).unwrap_or_default();
                }
                "lu" => {
                    metadata.license_uris =
                        FromClvm::from_clvm(decoder, value_ptr.0).unwrap_or_default();
                }
                "lh" => {
                    metadata.license_hash =
                        FromClvm::from_clvm(decoder, value_ptr.0).unwrap_or_default();
                }
                _ => (),
            }
        }

        Ok(metadata)
    }
}

impl<N, E: ClvmEncoder<Node = N>> ToClvm<E> for NftMetadata {
    fn to_clvm(&self, encoder: &mut E) -> Result<N, ToClvmError> {
        let mut items: Vec<(&str, Raw<N>)> = Vec::new();

        if !self.data_uris.is_empty() {
            items.push(("u", Raw(self.data_uris.to_clvm(encoder)?)));
        }

        if let Some(hash) = self.data_hash {
            items.push(("h", Raw(hash.to_clvm(encoder)?)));
        }

        if !self.metadata_uris.is_empty() {
            items.push(("mu", Raw(self.metadata_uris.to_clvm(encoder)?)));
        }

        if let Some(hash) = self.metadata_hash {
            items.push(("mh", Raw(hash.to_clvm(encoder)?)));
        }

        if !self.license_uris.is_empty() {
            items.push(("lu", Raw(self.license_uris.to_clvm(encoder)?)));
        }

        if let Some(hash) = self.license_hash {
            items.push(("lh", Raw(hash.to_clvm(encoder)?)));
        }

        items.extend(vec![
            ("sn", Raw(self.edition_number.to_clvm(encoder)?)),
            ("st", Raw(self.edition_total.to_clvm(encoder)?)),
        ]);

        items.to_clvm(encoder)
    }
}
