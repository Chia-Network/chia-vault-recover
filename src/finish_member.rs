//! Finish member used while a vault is in recovery.
//!
//! Curried arguments are `(PUZZLE_HASH CONDITIONS)`. The puzzle returns `CONDITIONS` when
//! the delegated puzzle hash equals `PUZZLE_HASH`.
//!
//! ```chialisp
//! (mod (PUZZLE_HASH CONDITIONS delegated_puzzle_hash)
//!   (if (= PUZZLE_HASH delegated_puzzle_hash)
//!       CONDITIONS
//!       (x)))
//! ```
//!
//! Against the curried environment `(PUZZLE_HASH CONDITIONS . (delegated_puzzle_hash))`.
//! `if` is strict, so only the chosen branch is applied:
//! `(a (i (= 2 11) (q . 5) (q . (x))) 1)`.

use std::borrow::Cow;
use std::sync::OnceLock;

use chia_protocol::Bytes32;
use chia_sdk_driver::{Spend, SpendContext};
use chia_sdk_types::{Conditions, Mod};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::{TreeHash, tree_hash};
use clvmr::{Allocator, NodePtr, serde::node_from_bytes};

use crate::error::Result;

const FINISH_MEMBER_MOD: [u8; 27] = [
    0xff, 0x02, 0xff, 0xff, 0x03, 0xff, 0xff, 0x09, 0xff, 0x02, 0xff, 0x0b, 0x80, 0xff, 0xff, 0x01,
    0x05, 0xff, 0xff, 0x01, 0xff, 0x08, 0x80, 0x80, 0xff, 0x01, 0x80,
];

fn finish_member_mod_hash() -> TreeHash {
    static HASH: OnceLock<TreeHash> = OnceLock::new();
    *HASH.get_or_init(|| {
        let mut allocator = Allocator::new();
        let ptr = node_from_bytes(&mut allocator, &FINISH_MEMBER_MOD)
            .expect("finish member mod is valid clvm");
        tree_hash(&allocator, ptr)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
struct FinishMemberArgs<C> {
    puzzle_hash: Bytes32,
    conditions: C,
}

impl<C> Mod for FinishMemberArgs<C> {
    fn mod_reveal() -> Cow<'static, [u8]> {
        Cow::Borrowed(&FINISH_MEMBER_MOD)
    }

    fn mod_hash() -> TreeHash {
        finish_member_mod_hash()
    }
}

pub(crate) fn empty_delegated_spend(ctx: &mut SpendContext) -> Result<Spend> {
    Ok(ctx.delegated_spend(Conditions::new())?)
}

pub(crate) fn pinned_member(
    ctx: &mut SpendContext,
    delegated_puzzle_hash: TreeHash,
    conditions: &Conditions,
) -> Result<Spend> {
    let conditions = ctx.alloc(conditions)?;
    let puzzle = ctx.curry(FinishMemberArgs {
        puzzle_hash: delegated_puzzle_hash.into(),
        conditions,
    })?;
    Ok(Spend::new(puzzle, NodePtr::NIL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clvmr::serde::node_to_bytes;

    fn cons(allocator: &mut Allocator, first: NodePtr, rest: NodePtr) -> NodePtr {
        allocator.new_pair(first, rest).unwrap()
    }

    fn atom(allocator: &mut Allocator, byte: u8) -> NodePtr {
        allocator.new_atom(&[byte]).unwrap()
    }

    fn list(allocator: &mut Allocator, items: &[NodePtr]) -> NodePtr {
        let mut out = NodePtr::NIL;
        for item in items.iter().rev() {
            out = cons(allocator, *item, out);
        }
        out
    }

    /// `(a (i (= 2 11) (q . 5) (q . (x))) 1)`
    fn compiled_mod(allocator: &mut Allocator) -> NodePtr {
        let nil = NodePtr::NIL;
        let q = atom(allocator, 1);
        let five = atom(allocator, 5);
        let quoted_five = cons(allocator, q, five);
        let q2 = atom(allocator, 1);
        let op_x = atom(allocator, 8);
        let raise = cons(allocator, op_x, nil);
        let quoted_raise = cons(allocator, q2, raise);
        let op_eq = atom(allocator, 9);
        let two = atom(allocator, 2);
        let eleven = atom(allocator, 11);
        let eq = list(allocator, &[op_eq, two, eleven]);
        let op_if = atom(allocator, 3);
        let if_form = list(allocator, &[op_if, eq, quoted_five, quoted_raise]);
        let op_a = atom(allocator, 2);
        let env = atom(allocator, 1);
        list(allocator, &[op_a, if_form, env])
    }

    #[test]
    fn mod_bytes_match_hash_check() {
        let mut allocator = Allocator::new();
        let program = compiled_mod(&mut allocator);
        let bytes = node_to_bytes(&allocator, program).unwrap();
        assert_eq!(bytes, FINISH_MEMBER_MOD);
    }

    #[test]
    fn returns_conditions_only_for_the_committed_hash() {
        let mut ctx = SpendContext::new();
        let delegated = empty_delegated_spend(&mut ctx).unwrap();
        let delegated_hash = ctx.tree_hash(delegated.puzzle);
        let conditions = Conditions::new().reserve_fee(1);
        let member = pinned_member(&mut ctx, delegated_hash, &conditions).unwrap();
        let conditions_ptr = ctx.alloc(&conditions).unwrap();

        let solution = ctx.alloc(&vec![Bytes32::from(delegated_hash)]).unwrap();
        let output = ctx.run(member.puzzle, solution).unwrap();
        assert_eq!(ctx.tree_hash(output), ctx.tree_hash(conditions_ptr));

        let other = ctx.alloc(&vec![Bytes32::default()]).unwrap();
        assert!(ctx.run(member.puzzle, other).is_err());
    }
}
