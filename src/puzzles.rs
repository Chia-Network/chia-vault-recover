//! Puzzles Cloud Wallet uses that `chia-sdk-types` 0.36 does not ship yet.

use std::borrow::Cow;

use chia_sdk_types::Mod;
use clvm_utils::TreeHash;
use hex_literal::hex;

/// Delegated puzzle wrapper that makes a spend recreate the singleton (odd-amount `CREATE_COIN`).
/// Copied from chia-wallet-sdk `force_singleton_recreation.rs`; drop once the crate release has it.
pub const FORCE_SINGLETON_RECREATION: [u8; 243] = hex!(
    "
    ff02ffff01ff02ff1effff04ff02ffff04ffff02ff16ffff04ff02ffff04ff05
    ff80808080ffff04ff05ff8080808080ffff04ffff01ffff4933ffff02ffff03
    ffff09ff09ff0c80ffff01ff02ffff03ffff18ff2dffff010180ffff01ff04ff
    13ff2d80ffff010b80ff0180ffff01ff02ffff03ffff09ff09ff0880ffff01ff
    04ff15ff1b80ffff010b80ff018080ff0180ffff02ffff03ff05ffff01ff02ff
    0affff04ff02ffff04ff09ffff04ffff02ff16ffff04ff02ffff04ff0dff8080
    8080ff8080808080ffff01ff01ff808080ff0180ff02ffff03ffff09ff09ff0d
    80ffff010bffff01ff088080ff0180ff018080
    "
);
pub const FORCE_SINGLETON_RECREATION_HASH: [u8; 32] =
    hex!("63e04374ced7e7f9ab0f46e9bad1b4e82bf3edf671ea355cd60113c7a947ee1e");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForceSingletonRecreationMod;

impl Mod for ForceSingletonRecreationMod {
    fn mod_reveal() -> Cow<'static, [u8]> {
        Cow::Borrowed(&FORCE_SINGLETON_RECREATION)
    }

    fn mod_hash() -> TreeHash {
        FORCE_SINGLETON_RECREATION_HASH.into()
    }
}

#[cfg(test)]
mod tests {
    use clvm_utils::tree_hash;
    use clvmr::{Allocator, serde::node_from_bytes};

    use super::*;

    #[test]
    fn force_singleton_recreation_hash_matches_reveal() {
        let mut allocator = Allocator::new();
        let ptr = node_from_bytes(&mut allocator, &FORCE_SINGLETON_RECREATION).unwrap();
        assert_eq!(
            tree_hash(&allocator, ptr),
            TreeHash::new(FORCE_SINGLETON_RECREATION_HASH)
        );
    }
}
