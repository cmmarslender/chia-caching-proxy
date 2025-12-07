use crate::wallet_sdk_extensions::cat1_layer::{CAT1_PUZZLE, CAT1_PUZZLE_HASH};
use chia_wallet_sdk::chia::puzzles::{CoinProof, LineageProof};
use chia_wallet_sdk::prelude::{Bytes32, Coin, CurriedProgram, Mod, ToTreeHash, TreeHash};
use clvm_traits::{FromClvm, ToClvm};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct Cat1Args<I> {
    pub mod_hash: Bytes32,
    pub asset_id: Bytes32,
    pub inner_puzzle: I,
}

impl<I> Cat1Args<I> {
    pub fn new(asset_id: Bytes32, inner_puzzle: I) -> Self {
        Self {
            mod_hash: CAT1_PUZZLE_HASH.into(),
            asset_id,
            inner_puzzle,
        }
    }
}

impl Cat1Args<TreeHash> {
    pub fn curry_tree_hash(asset_id: Bytes32, inner_puzzle: TreeHash) -> TreeHash {
        CurriedProgram {
            program: TreeHash::new(CAT1_PUZZLE_HASH),
            args: Cat1Args {
                mod_hash: CAT1_PUZZLE_HASH.into(),
                asset_id,
                inner_puzzle,
            },
        }
        .tree_hash()
    }
}

impl<I> Mod for Cat1Args<I> {
    fn mod_reveal() -> Cow<'static, [u8]> {
        Cow::Borrowed(&CAT1_PUZZLE)
    }

    fn mod_hash() -> TreeHash {
        TreeHash::new(CAT1_PUZZLE_HASH)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct Cat1Solution<I> {
    pub inner_puzzle_solution: I,
    pub lineage_proof: Option<LineageProof>,
    pub prev_coin_id: Bytes32,
    pub this_coin_info: Coin,
    pub next_coin_proof: CoinProof,
    pub prev_subtotal: i64,
    pub extra_delta: i64,
}

#[cfg(test)]
mod tests {
    use chia_wallet_sdk::chia::puzzles::cat::{
        EverythingWithSignatureTailArgs, GenesisByCoinIdTailArgs,
    };
    use chia_wallet_sdk::chia::puzzles::standard::StandardArgs;
    use chia_wallet_sdk::clvmr::serde::node_from_bytes;
    use chia_wallet_sdk::prelude::{Allocator, PublicKey, tree_hash};
    use chia_wallet_sdk::puzzles::{
        EVERYTHING_WITH_SIGNATURE, GENESIS_BY_COIN_ID, P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE,
    };

    use super::*;

    use crate::wallet_sdk_extensions::cat1_layer::CAT1_PUZZLE;

    #[test]
    fn curry_cat_tree_hash() {
        let synthetic_key = PublicKey::default();
        let asset_id = Bytes32::new([120; 32]);

        let mut a = Allocator::new();
        let mod_ptr = node_from_bytes(&mut a, &CAT1_PUZZLE).unwrap();
        let inner_mod_ptr = node_from_bytes(&mut a, &P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE).unwrap();

        let curried_ptr = CurriedProgram {
            program: mod_ptr,
            args: Cat1Args::new(
                asset_id,
                CurriedProgram {
                    program: inner_mod_ptr,
                    args: StandardArgs::new(synthetic_key),
                },
            ),
        }
        .to_clvm(&mut a)
        .unwrap();

        let allocated_tree_hash = hex::encode(tree_hash(&a, curried_ptr));

        let inner_puzzle_hash = StandardArgs::curry_tree_hash(synthetic_key);
        let tree_hash = hex::encode(Cat1Args::curry_tree_hash(asset_id, inner_puzzle_hash));

        assert_eq!(allocated_tree_hash, tree_hash);
    }

    #[test]
    fn curry_everything_with_signature() {
        let public_key = PublicKey::default();

        let mut a = Allocator::new();
        let mod_ptr = node_from_bytes(&mut a, &EVERYTHING_WITH_SIGNATURE).unwrap();

        let curried_ptr = CurriedProgram {
            program: mod_ptr,
            args: EverythingWithSignatureTailArgs::new(public_key),
        }
        .to_clvm(&mut a)
        .unwrap();

        let allocated_tree_hash = hex::encode(tree_hash(&a, curried_ptr));

        let tree_hash = hex::encode(EverythingWithSignatureTailArgs::curry_tree_hash(public_key));

        assert_eq!(allocated_tree_hash, tree_hash);
    }

    #[test]
    fn curry_genesis_by_coin_id() {
        let genesis_coin_id = Bytes32::new([120; 32]);

        let mut a = Allocator::new();
        let mod_ptr = node_from_bytes(&mut a, &GENESIS_BY_COIN_ID).unwrap();

        let curried_ptr = CurriedProgram {
            program: mod_ptr,
            args: GenesisByCoinIdTailArgs::new(genesis_coin_id),
        }
        .to_clvm(&mut a)
        .unwrap();

        let allocated_tree_hash = hex::encode(tree_hash(&a, curried_ptr));

        let tree_hash = hex::encode(GenesisByCoinIdTailArgs::curry_tree_hash(genesis_coin_id));

        assert_eq!(allocated_tree_hash, tree_hash);
    }
}
