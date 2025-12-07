use crate::wallet_sdk_extensions::cat1_info::Cat1Info;
use crate::wallet_sdk_extensions::cat1_layer::Cat1Layer;
use chia_wallet_sdk::chia::puzzles::LineageProof;
use chia_wallet_sdk::prelude::{
    Allocator, Bytes32, Coin, Condition, CreateCoin, DriverError, Layer, NodePtr, Puzzle, Spend,
    run_puzzle,
};
use clvm_traits::FromClvm;

/// Contains all information needed to spend the outer puzzles of CAT1 coins.
/// The [`Cat1Info`] is used to construct the puzzle, but the [`LineageProof`] is needed for the solution.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cat1 {
    /// The coin that this [`Cat1`] represents. Its puzzle hash should match the [`Cat1Info::puzzle_hash`].
    pub coin: Coin,

    /// The lineage proof is needed by the CAT puzzle to prove that this coin is a legitimate CAT.
    /// It's typically obtained by looking up and parsing the parent coin.
    ///
    /// This can get a bit tedious, so a helper method [`Cat1::parse_children`] is provided to parse
    /// the child [`Cat1`] objects from the parent (once you have looked up its information on-chain).
    ///
    /// Note that while the lineage proof is needed for most coins, it is optional if you are
    /// issuing more of the CAT by running its TAIL program.
    pub lineage_proof: Option<LineageProof>,

    /// The information needed to construct the outer puzzle of a CAT. See [`Cat1Info`] for more details.
    pub info: Cat1Info,
}

impl Cat1 {
    pub fn new(coin: Coin, lineage_proof: Option<LineageProof>, info: Cat1Info) -> Self {
        Self {
            coin,
            lineage_proof,
            info,
        }
    }

    /// Creates a [`LineageProof`] for which would be valid for any children created by this [`Cat`].
    pub fn child_lineage_proof(&self) -> LineageProof {
        LineageProof {
            parent_parent_coin_info: self.coin.parent_coin_info,
            parent_inner_puzzle_hash: self.info.inner_puzzle_hash().into(),
            parent_amount: self.coin.amount,
        }
    }

    /// Creates a new [`Cat1`] that represents a child of this one.
    pub fn child(&self, p2_puzzle_hash: Bytes32, amount: u64) -> Self {
        self.child_with(
            Cat1Info {
                p2_puzzle_hash,
                ..self.info
            },
            amount,
        )
    }

    /// Creates a new [`Cat1`] that represents a child of this one.
    ///
    /// You can specify the [`Cat1Info`] to use for the child manually.
    /// In most cases, you will want to use [`Cat1::child`] instead.
    pub fn child_with(&self, info: Cat1Info, amount: u64) -> Self {
        Self {
            coin: Coin::new(self.coin.coin_id(), info.puzzle_hash().into(), amount),
            lineage_proof: Some(self.child_lineage_proof()),
            info,
        }
    }

    /// Parses the children of a [`Cat1`] from the parent coin spend.
    pub fn parse_children(
        allocator: &mut Allocator,
        parent_coin: Coin,
        parent_puzzle: Puzzle,
        parent_solution: NodePtr,
    ) -> Result<Option<Vec<Self>>, DriverError> {
        let Some(parent_layer) = Cat1Layer::<Puzzle>::parse_puzzle(allocator, parent_puzzle)?
        else {
            return Ok(None);
        };
        let parent_solution = Cat1Layer::<Puzzle>::parse_solution(allocator, parent_solution)?;

        let p2_puzzle_hash = parent_layer.inner_puzzle.curried_puzzle_hash().into();
        let inner_spend = Spend::new(
            parent_layer.inner_puzzle.ptr(),
            parent_solution.inner_puzzle_solution,
        );

        let cat = Cat1::new(
            parent_coin,
            parent_solution.lineage_proof,
            Cat1Info::new(parent_layer.asset_id, p2_puzzle_hash),
        );

        let output = run_puzzle(allocator, inner_spend.puzzle, inner_spend.solution)?;
        let conditions = Vec::<Condition>::from_clvm(allocator, output)?;

        let outputs = conditions
            .into_iter()
            .filter_map(Condition::into_create_coin)
            .map(|create_coin| cat.child_from_p2_create_coin(create_coin))
            .collect();

        Ok(Some(outputs))
    }

    /// Creates a new [`Cat1`] that reflects the create coin condition in the p2 spend's conditions.
    pub fn child_from_p2_create_coin(&self, create_coin: CreateCoin<NodePtr>) -> Self {
        // Child with the same hidden puzzle hash as the parent
        self.child(create_coin.puzzle_hash, create_coin.amount)
    }
}
