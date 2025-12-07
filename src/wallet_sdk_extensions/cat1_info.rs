use crate::wallet_sdk_extensions::cat1_args::Cat1Args;
use crate::wallet_sdk_extensions::cat1_layer::Cat1Layer;
use chia_wallet_sdk::prelude::{Allocator, Bytes32, DriverError, Layer, Puzzle, TreeHash};

/// Information needed to construct the outer puzzle of a CAT.
/// This includes the [`Cat1Layer`].
/// However, it does not include the inner puzzle, which must be stored separately.
///
/// This type can be used on its own for parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cat1Info {
    /// The hash of the TAIL (Token and Asset Issuance Limitations) program.
    /// This is what controls the supply, and thus the main way to identify a CAT.
    /// You can spend multiple CAT coins at once, as long as they have the same [`asset_id`](Self::asset_id).
    pub asset_id: Bytes32,

    /// The hash of the inner puzzle to this CAT.
    /// If you encode this puzzle hash as bech32m, it's the same as the current owner's address.
    pub p2_puzzle_hash: Bytes32,
}

impl Cat1Info {
    pub fn new(asset_id: Bytes32, p2_puzzle_hash: Bytes32) -> Self {
        Self {
            asset_id,
            p2_puzzle_hash,
        }
    }

    /// Parses a [`Cat1Info`] from a [`Puzzle`] by extracting the [`Cat1Layer`].
    ///
    /// This will return a tuple of the [`Cat1Info`] and its p2 puzzle.
    ///
    /// If the puzzle is not a CAT, this will return [`None`] instead of an error.
    /// However, if the puzzle should have been a CAT but had a parsing error, this will return an error.
    pub fn parse(
        allocator: &Allocator,
        puzzle: Puzzle,
    ) -> Result<Option<(Self, Option<Puzzle>)>, DriverError> {
        let Some(cat_layer) = Cat1Layer::<Puzzle>::parse_puzzle(allocator, puzzle)? else {
            return Ok(None);
        };

        let info = Self::new(
            cat_layer.asset_id,
            cat_layer.inner_puzzle.curried_puzzle_hash().into(),
        );
        Ok(Some((info, Some(cat_layer.inner_puzzle))))
    }

    /// Calculates the inner puzzle hash of the CAT.
    ///
    /// This is only different than the [`p2_puzzle_hash`](Self::p2_puzzle_hash) for revocable CATs.
    pub fn inner_puzzle_hash(&self) -> TreeHash {
        TreeHash::from(self.p2_puzzle_hash)
    }

    /// Calculates the full puzzle hash of the CAT, which is the hash of the outer [`Cat1Layer`].
    pub fn puzzle_hash(&self) -> TreeHash {
        Cat1Args::curry_tree_hash(self.asset_id, self.inner_puzzle_hash())
    }
}
