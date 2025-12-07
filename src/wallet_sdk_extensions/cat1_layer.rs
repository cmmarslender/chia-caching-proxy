use crate::wallet_sdk_extensions::cat1_args::{Cat1Args, Cat1Solution};
use chia_wallet_sdk::prelude::{
    Allocator, Bytes32, DriverError, FromClvm, Layer, NodePtr, Puzzle, SpendContext, ToTreeHash,
    TreeHash,
};
use hex_literal::hex;

pub const CAT1_PUZZLE: [u8; 1420] = hex!(
    "ff02ffff01ff02ff5effff04ff02ffff04ffff04ff05ffff04ffff0bff2cff0580ffff04ff0bff80808080ffff04ffff02ff17ff2f80ffff04ff5fffff04ffff02ff2effff04ff02ffff04ff17ff80808080ffff04ffff0bff82027fff82057fff820b7f80ffff04ff81bfffff04ff82017fffff04ff8202ffffff04ff8205ffffff04ff820bffff80808080808080808080808080ffff04ffff01ffffffff81ca3dff46ff0233ffff3c04ff01ff0181cbffffff02ff02ffff03ff05ffff01ff02ff32ffff04ff02ffff04ff0dffff04ffff0bff22ffff0bff2cff3480ffff0bff22ffff0bff22ffff0bff2cff5c80ff0980ffff0bff22ff0bffff0bff2cff8080808080ff8080808080ffff010b80ff0180ffff02ffff03ff0bffff01ff02ffff03ffff09ffff02ff2effff04ff02ffff04ff13ff80808080ff820b9f80ffff01ff02ff26ffff04ff02ffff04ffff02ff13ffff04ff5fffff04ff17ffff04ff2fffff04ff81bfffff04ff82017fffff04ff1bff8080808080808080ffff04ff82017fff8080808080ffff01ff088080ff0180ffff01ff02ffff03ff17ffff01ff02ffff03ffff20ff81bf80ffff0182017fffff01ff088080ff0180ffff01ff088080ff018080ff0180ffff04ffff04ff05ff2780ffff04ffff10ff0bff5780ff778080ff02ffff03ff05ffff01ff02ffff03ffff09ffff02ffff03ffff09ff11ff7880ffff0159ff8080ff0180ffff01818f80ffff01ff02ff7affff04ff02ffff04ff0dffff04ff0bffff04ffff04ff81b9ff82017980ff808080808080ffff01ff02ff5affff04ff02ffff04ffff02ffff03ffff09ff11ff7880ffff01ff04ff78ffff04ffff02ff36ffff04ff02ffff04ff13ffff04ff29ffff04ffff0bff2cff5b80ffff04ff2bff80808080808080ff398080ffff01ff02ffff03ffff09ff11ff2480ffff01ff04ff24ffff04ffff0bff20ff2980ff398080ffff010980ff018080ff0180ffff04ffff02ffff03ffff09ff11ff7880ffff0159ff8080ff0180ffff04ffff02ff7affff04ff02ffff04ff0dffff04ff0bffff04ff17ff808080808080ff80808080808080ff0180ffff01ff04ff80ffff04ff80ff17808080ff0180ffffff02ffff03ff05ffff01ff04ff09ffff02ff26ffff04ff02ffff04ff0dffff04ff0bff808080808080ffff010b80ff0180ff0bff22ffff0bff2cff5880ffff0bff22ffff0bff22ffff0bff2cff5c80ff0580ffff0bff22ffff02ff32ffff04ff02ffff04ff07ffff04ffff0bff2cff2c80ff8080808080ffff0bff2cff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff8080808080ffff01ff0bff2cff058080ff0180ffff04ffff04ff28ffff04ff5fff808080ffff02ff7effff04ff02ffff04ffff04ffff04ff2fff0580ffff04ff5fff82017f8080ffff04ffff02ff7affff04ff02ffff04ff0bffff04ff05ffff01ff808080808080ffff04ff17ffff04ff81bfffff04ff82017fffff04ffff0bff8204ffffff02ff36ffff04ff02ffff04ff09ffff04ff820affffff04ffff0bff2cff2d80ffff04ff15ff80808080808080ff8216ff80ffff04ff8205ffffff04ff820bffff808080808080808080808080ff02ff2affff04ff02ffff04ff5fffff04ff3bffff04ffff02ffff03ff17ffff01ff09ff2dffff0bff27ffff02ff36ffff04ff02ffff04ff29ffff04ff57ffff04ffff0bff2cff81b980ffff04ff59ff80808080808080ff81b78080ff8080ff0180ffff04ff17ffff04ff05ffff04ff8202ffffff04ffff04ffff04ff24ffff04ffff0bff7cff2fff82017f80ff808080ffff04ffff04ff30ffff04ffff0bff81bfffff0bff7cff15ffff10ff82017fffff11ff8202dfff2b80ff8202ff808080ff808080ff138080ff80808080808080808080ff018080"
);
pub const CAT1_PUZZLE_HASH: [u8; 32] =
    hex!("72dec062874cd4d3aab892a0906688a1ae412b0109982e1797a170add88bdcdc");

/// The CAT [`Layer`] enforces restrictions on the supply of a token.
/// Specifically, unless the TAIL program is run, the supply cannot change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cat1Layer<I> {
    /// The asset id of the CAT token. This is the tree hash of the TAIL program.
    pub asset_id: Bytes32,
    /// The inner puzzle layer, commonly used for determining ownership.
    pub inner_puzzle: I,
}

impl<I> Cat1Layer<I> {
    #[cfg(test)]
    pub fn new(asset_id: Bytes32, inner_puzzle: I) -> Self {
        Self {
            asset_id,
            inner_puzzle,
        }
    }
}

impl<I> Layer for Cat1Layer<I>
where
    I: Layer,
{
    type Solution = Cat1Solution<I::Solution>;

    fn parse_puzzle(allocator: &Allocator, puzzle: Puzzle) -> Result<Option<Self>, DriverError> {
        let Some(puzzle) = puzzle.as_curried() else {
            return Ok(None);
        };

        if puzzle.mod_hash != CAT1_PUZZLE_HASH.into() {
            return Ok(None);
        }

        let args = Cat1Args::<NodePtr>::from_clvm(allocator, puzzle.args)?;

        if args.mod_hash != CAT1_PUZZLE_HASH.into() {
            return Err(DriverError::InvalidModHash);
        }

        let Some(inner_puzzle) =
            I::parse_puzzle(allocator, Puzzle::parse(allocator, args.inner_puzzle))?
        else {
            return Ok(None);
        };

        Ok(Some(Self {
            asset_id: args.asset_id,
            inner_puzzle,
        }))
    }

    fn parse_solution(
        allocator: &Allocator,
        solution: NodePtr,
    ) -> Result<Self::Solution, DriverError> {
        let solution = Cat1Solution::<NodePtr>::from_clvm(allocator, solution)?;
        let inner_solution = I::parse_solution(allocator, solution.inner_puzzle_solution)?;
        Ok(Cat1Solution {
            inner_puzzle_solution: inner_solution,
            lineage_proof: solution.lineage_proof,
            prev_coin_id: solution.prev_coin_id,
            this_coin_info: solution.this_coin_info,
            next_coin_proof: solution.next_coin_proof,
            prev_subtotal: solution.prev_subtotal,
            extra_delta: solution.extra_delta,
        })
    }

    fn construct_puzzle(&self, ctx: &mut SpendContext) -> Result<NodePtr, DriverError> {
        let inner_puzzle = self.inner_puzzle.construct_puzzle(ctx)?;
        ctx.curry(Cat1Args::new(self.asset_id, inner_puzzle))
    }

    fn construct_solution(
        &self,
        ctx: &mut SpendContext,
        solution: Self::Solution,
    ) -> Result<NodePtr, DriverError> {
        let inner_solution = self
            .inner_puzzle
            .construct_solution(ctx, solution.inner_puzzle_solution)?;
        ctx.alloc(&Cat1Solution {
            inner_puzzle_solution: inner_solution,
            lineage_proof: solution.lineage_proof,
            prev_coin_id: solution.prev_coin_id,
            this_coin_info: solution.this_coin_info,
            next_coin_proof: solution.next_coin_proof,
            prev_subtotal: solution.prev_subtotal,
            extra_delta: solution.extra_delta,
        })
    }
}

impl<I> ToTreeHash for Cat1Layer<I>
where
    I: ToTreeHash,
{
    fn tree_hash(&self) -> TreeHash {
        let inner_puzzle_hash = self.inner_puzzle.tree_hash();
        Cat1Args::curry_tree_hash(self.asset_id, inner_puzzle_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::chia::puzzles::CoinProof;
    use chia_wallet_sdk::prelude::Coin;

    #[test]
    fn test_cat_layer() -> anyhow::Result<()> {
        let mut ctx = SpendContext::new();
        let asset_id = Bytes32::new([1; 32]);

        let layer = Cat1Layer::new(asset_id, "Hello, world!".to_string());

        let ptr = layer.construct_puzzle(&mut ctx)?;
        let puzzle = Puzzle::parse(&ctx, ptr);
        let roundtrip =
            Cat1Layer::<String>::parse_puzzle(&ctx, puzzle)?.expect("invalid CAT layer");

        assert_eq!(roundtrip.asset_id, layer.asset_id);
        assert_eq!(roundtrip.inner_puzzle, layer.inner_puzzle);

        let expected = Cat1Args::curry_tree_hash(asset_id, layer.inner_puzzle.tree_hash());
        assert_eq!(hex::encode(ctx.tree_hash(ptr)), hex::encode(expected));

        Ok(())
    }

    #[test]
    fn test_cat_solution() -> anyhow::Result<()> {
        let mut ctx = SpendContext::new();

        let layer = Cat1Layer::new(Bytes32::default(), NodePtr::NIL);

        let solution = Cat1Solution {
            inner_puzzle_solution: NodePtr::NIL,
            lineage_proof: None,
            prev_coin_id: Bytes32::default(),
            this_coin_info: Coin::new(Bytes32::default(), Bytes32::default(), 42),
            next_coin_proof: CoinProof {
                parent_coin_info: Bytes32::default(),
                inner_puzzle_hash: Bytes32::default(),
                amount: 34,
            },
            prev_subtotal: 0,
            extra_delta: 0,
        };
        let expected_ptr = ctx.alloc(&solution)?;
        let expected_hash = ctx.tree_hash(expected_ptr);

        let actual_ptr = layer.construct_solution(&mut ctx, solution)?;
        let actual_hash = ctx.tree_hash(actual_ptr);

        assert_eq!(hex::encode(actual_hash), hex::encode(expected_hash));

        let roundtrip = Cat1Layer::<NodePtr>::parse_solution(&ctx, actual_ptr)?;
        assert_eq!(roundtrip, solution);

        Ok(())
    }
}
