//! Reconstruct vault custody when the on-chain CHIP-0043 hint is absent.
//!
//! Cloud Wallet now attaches that hint to the vault singleton. Prefer it (see
//! [`crate::hint`]). A custody spend of the current 1-of-2 inner puzzle still
//! reveals the custody path: the One-of-N member puzzle hashes to `custody_hash`,
//! and a 1-of-1 member also reveals the public key. Combined with the recovery
//! seed and clawback timelock (known or tried from common Cloud Wallet values)
//! we can rebuild a config that matches the singleton.

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzles::{FORCE_1_OF_2_W_RESTRICTED_VARIABLE_HASH, ONE_OF_N_HASH, RESTRICTIONS_HASH};
use chia_sdk_driver::Puzzle;
use chia_sdk_types::{
    Mod,
    puzzles::{
        BlsMember, BlsMemberPuzzleAssert, K1Member, K1MemberPuzzleAssert, OneOfNSolution,
        PasskeyMember, PasskeyMemberPuzzleAssert, R1Member, R1MemberPuzzleAssert, RestrictionsArgs,
        SingletonMember, SingletonMemberWithMode,
    },
};
use clvm_traits::FromClvm;
use clvm_utils::{ToTreeHash, TreeHash};
use clvmr::{Allocator, NodePtr};
use serde::{Deserialize, Serialize};

use crate::config::{
    Curve, KeyType, VaultConfig, VaultConfigMember, VaultConfigRecovery, VaultConfigSide,
};
use crate::error::{Error, Result};
use crate::keys::{key_from_mnemonic, public_key_to_hex};
use crate::mips::{alloc_spend, peel_index_wrapper, peel_vault_mips};
use crate::vault::{CustodyPath, SignerSet, VaultMemberKey, get_vault_internals};

/// Common Cloud Wallet / test timelocks, tried when the user does not pass one.
pub const DEFAULT_TIMELOCK_CANDIDATES: &[u64] = &[
    43_200, 86_400, 3_600, 7_200, 21_600, 604_800, 1, 10, 60, 300,
];

/// How to choose clawback seconds when reconstructing the public layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClawbackGuess {
    #[default]
    Unknown,
    /// User-supplied, not yet matched to the chain.
    Hint(u64),
    /// User typed this value, or it already matched the chain.
    Known(u64),
}

impl ClawbackGuess {
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    pub fn secs(self) -> Option<u64> {
        match self {
            Self::Unknown => None,
            Self::Hint(secs) | Self::Known(secs) => Some(secs),
        }
    }

    /// An explicit value is tried alone; otherwise keep the cached guess.
    pub fn with_typed(self, typed: Option<u64>) -> Self {
        match typed {
            Some(secs) => Self::Known(secs),
            None => self,
        }
    }

    pub fn candidates(self) -> Vec<u64> {
        match self {
            Self::Unknown => DEFAULT_TIMELOCK_CANDIDATES.to_vec(),
            Self::Known(secs) => vec![secs],
            Self::Hint(secs) => {
                let mut out = vec![secs];
                for &candidate in DEFAULT_TIMELOCK_CANDIDATES {
                    if candidate != secs {
                        out.push(candidate);
                    }
                }
                out
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredCustodyPath {
    pub custody_hash: TreeHash,
    pub members: Vec<VaultMemberKey>,
    pub vault_launcher_ids: Vec<Bytes32>,
}

impl DiscoveredCustodyPath {
    pub fn members_complete(&self) -> bool {
        !self.members.is_empty() || !self.vault_launcher_ids.is_empty()
    }
}

/// Chain facts from a custody-spend lookup. No mnemonic and no hinted config.
#[derive(Debug, Clone)]
pub struct FoundVault {
    pub launcher_id: Bytes32,
    pub launcher_source: String,
    pub custody: DiscoveredCustodyPath,
    pub current_coin: Coin,
    pub ancestor_puzzle_hashes: Vec<Bytes32>,
}

#[derive(Debug, Clone)]
pub struct ReconstructedVault {
    pub found: FoundVault,
    pub config: VaultConfig,
    pub matches_current: bool,
}

/// Extract the custody path from a vault singleton spend, if this spend used custody.
pub fn custody_from_vault_spend(spend: &CoinSpend) -> Result<Option<DiscoveredCustodyPath>> {
    let (ctx, puzzle, solution_ptr) = alloc_spend(spend)?;
    custody_from_parsed_spend(&ctx, puzzle, solution_ptr)
}

fn custody_from_parsed_spend(
    alloc: &Allocator,
    puzzle: Puzzle,
    solution: NodePtr,
) -> Result<Option<DiscoveredCustodyPath>> {
    let Some((one_puzzle, one_solution)) = peel_vault_mips(alloc, puzzle, solution)? else {
        return Ok(None);
    };
    let Some(one_of_n) = one_puzzle.as_curried() else {
        return Ok(None);
    };
    if one_of_n.mod_hash != ONE_OF_N_HASH.into() {
        return Ok(None);
    }
    let one_sol = OneOfNSolution::<NodePtr, NodePtr>::from_clvm(alloc, one_solution)
        .map_err(|e| Error::msg(format!("parse one-of-n solution: {e}")))?;

    let member_puzzle = Puzzle::parse(alloc, one_sol.member_puzzle);
    if member_looks_like_recovery(alloc, member_puzzle) {
        return Ok(None);
    }

    let custody_hash = member_puzzle.tree_hash();
    let (mut members, mut vault_launcher_ids) =
        parse_member_keys(alloc, member_puzzle, one_sol.member_solution);

    if !members.is_empty() || !vault_launcher_ids.is_empty() {
        let computed = CustodyPath::Signers(SignerSet {
            keys: members.clone(),
            vault_launcher_ids: vault_launcher_ids.clone(),
            threshold: 1,
        })
        .hash()?;
        if computed != custody_hash {
            members.clear();
            vault_launcher_ids.clear();
        }
    }

    Ok(Some(DiscoveredCustodyPath {
        custody_hash,
        members,
        vault_launcher_ids,
    }))
}

/// Rebuild a vault-config that matches `custody` + recovery seed + timelock.
pub fn reconstruct_config(
    launcher_id: Bytes32,
    custody: &DiscoveredCustodyPath,
    recovery_mnemonic: &str,
    clawback_timelock: u64,
) -> Result<VaultConfig> {
    if custody.members_complete() {
        let computed = CustodyPath::Signers(SignerSet {
            keys: custody.members.clone(),
            vault_launcher_ids: custody.vault_launcher_ids.clone(),
            threshold: 1,
        })
        .hash()?;
        if computed != custody.custody_hash {
            return Err(Error::msg(
                "parsed custody members do not hash to the spent custody path",
            ));
        }
    }

    let recovery = key_from_mnemonic(recovery_mnemonic)?;

    Ok(VaultConfig {
        launcher_id: format!("0x{}", hex::encode(launcher_id)),
        custody: VaultConfigSide {
            threshold: 1,
            members: members_to_config(&custody.members, &custody.vault_launcher_ids),
            hash: Some(format!("0x{}", hex::encode(custody.custody_hash))),
        },
        recovery: VaultConfigRecovery {
            threshold: 1,
            clawback_timelock,
            members: vec![VaultConfigMember::PublicKey {
                public_key: public_key_to_hex(&recovery.public_key),
                curve: Curve::Bls12_381,
                key_type: Some(KeyType::RecoveryPhrase),
            }],
        },
        receive_address: None,
    })
}

pub fn reconstruct(
    found: &FoundVault,
    recovery_mnemonic: &str,
    clawback: ClawbackGuess,
) -> Result<ReconstructedVault> {
    let candidates = clawback.candidates();
    for &timelock in &candidates {
        let config = reconstruct_config(
            found.launcher_id,
            &found.custody,
            recovery_mnemonic,
            timelock,
        )?;
        let ready_match = config_matches_puzzle_hash(&config, found.current_coin.puzzle_hash)?;
        let ancestor_match = found
            .ancestor_puzzle_hashes
            .iter()
            .any(|ph| config_matches_puzzle_hash(&config, *ph).unwrap_or(false));
        if ready_match || ancestor_match {
            return Ok(ReconstructedVault {
                found: found.clone(),
                config,
                matches_current: ready_match,
            });
        }
    }

    Err(Error::msg(format!(
        "found custody hash 0x{} but no candidate timelock produced a matching vault puzzle hash. \
         Enter the clawback window explicitly (Cloud Wallet default is 43200)",
        hex::encode(found.custody.custody_hash)
    )))
}

/// Result of an optional post-lookup clawback check. Phrase is used only in memory.
#[derive(Debug, Clone)]
pub enum ClawbackCheck {
    Hint(u64),
    Verified(Box<ReconstructedVault>),
}

impl ClawbackCheck {
    pub fn guess(&self) -> ClawbackGuess {
        match self {
            Self::Hint(secs) => ClawbackGuess::Hint(*secs),
            Self::Verified(rebuilt) => {
                ClawbackGuess::Known(rebuilt.config.recovery.clawback_timelock)
            }
        }
    }
}

pub fn recovery_phrase_matches(config: &VaultConfig, mnemonic: &str) -> Result<()> {
    let key = key_from_mnemonic(mnemonic)?;
    let expected = public_key_to_hex(&key.public_key);
    let ok = config.recovery.members.iter().any(|member| match member {
        VaultConfigMember::PublicKey {
            public_key, curve, ..
        } => *curve == Curve::Bls12_381 && public_key.eq_ignore_ascii_case(&expected),
        VaultConfigMember::Vault { .. } => false,
    });
    if ok {
        Ok(())
    } else {
        Err(Error::msg(
            "recovery phrase does not match a recovery key in the on-chain hint",
        ))
    }
}

/// Accept a hinted layout. The phrase is checked when present. A typed clawback must match the hint.
pub fn confirm_hinted_config(
    config: &VaultConfig,
    recovery_mnemonic: Option<&str>,
    clawback_secs: Option<u64>,
) -> Result<()> {
    if let Some(phrase) = recovery_mnemonic.map(str::trim).filter(|s| !s.is_empty()) {
        recovery_phrase_matches(config, phrase)?;
    }
    if let Some(secs) = clawback_secs
        && secs != config.recovery.clawback_timelock
    {
        return Err(Error::msg(format!(
            "on-chain hint clawback is {}s, not {secs}s",
            config.recovery.clawback_timelock
        )));
    }
    Ok(())
}

pub fn check_clawback(
    found: &FoundVault,
    recovery_mnemonic: Option<&str>,
    clawback_secs: Option<u64>,
) -> Result<ClawbackCheck> {
    let words = recovery_mnemonic.map(str::trim).filter(|s| !s.is_empty());
    match (words, clawback_secs) {
        (None, None) => Err(Error::msg(
            "enter a clawback window and/or the recovery phrase to check now, or skip and do this later",
        )),
        (None, Some(secs)) => Ok(ClawbackCheck::Hint(secs)),
        (Some(words), secs) => {
            let rebuilt = reconstruct(found, words, ClawbackGuess::Unknown.with_typed(secs))?;
            Ok(ClawbackCheck::Verified(Box::new(rebuilt)))
        }
    }
}

pub fn config_matches_puzzle_hash(config: &VaultConfig, puzzle_hash: Bytes32) -> Result<bool> {
    let internals = get_vault_internals(config.launcher_id_bytes()?, &config.to_vault_keys()?)?;
    Ok(internals.full_puzzle_hash == puzzle_hash)
}

fn members_to_config(
    keys: &[VaultMemberKey],
    vault_launcher_ids: &[Bytes32],
) -> Vec<VaultConfigMember> {
    crate::config::config_members_from_keys(keys, vault_launcher_ids)
}

fn member_looks_like_recovery(alloc: &Allocator, puzzle: Puzzle) -> bool {
    let inner = peel_index_wrapper(alloc, puzzle);
    let Some(curried) = inner.as_curried() else {
        return false;
    };
    if curried.mod_hash != RESTRICTIONS_HASH.into() {
        return false;
    }
    let Ok(args) =
        RestrictionsArgs::<Vec<Puzzle>, Vec<Puzzle>, Puzzle>::from_clvm(alloc, curried.args)
    else {
        return true;
    };
    args.delegated_puzzle_validators.iter().any(|p| {
        p.as_curried()
            .is_some_and(|c| c.mod_hash == FORCE_1_OF_2_W_RESTRICTED_VARIABLE_HASH.into())
    })
}

fn parse_member_keys(
    alloc: &Allocator,
    puzzle: Puzzle,
    solution: NodePtr,
) -> (Vec<VaultMemberKey>, Vec<Bytes32>) {
    let mut keys = Vec::new();
    let mut vaults = Vec::new();
    collect_member_keys(alloc, puzzle, solution, &mut keys, &mut vaults);
    (keys, vaults)
}

fn collect_member_keys(
    alloc: &Allocator,
    puzzle: Puzzle,
    solution: NodePtr,
    keys: &mut Vec<VaultMemberKey>,
    vaults: &mut Vec<Bytes32>,
) {
    let inner = peel_index_wrapper(alloc, puzzle);
    let Some(curried) = inner.as_curried() else {
        return;
    };

    if curried.mod_hash == RESTRICTIONS_HASH.into() {
        if let Ok(args) =
            RestrictionsArgs::<Vec<Puzzle>, Vec<Puzzle>, Puzzle>::from_clvm(alloc, curried.args)
        {
            collect_member_keys(alloc, args.inner_puzzle, solution, keys, vaults);
        }
        return;
    }

    if curried.mod_hash == ONE_OF_N_HASH.into()
        && let Ok(one_sol) = OneOfNSolution::<NodePtr, NodePtr>::from_clvm(alloc, solution)
    {
        collect_member_keys(
            alloc,
            Puzzle::parse(alloc, one_sol.member_puzzle),
            one_sol.member_solution,
            keys,
            vaults,
        );
        return;
    }

    if let Some(key) = parse_leaf_member(alloc, inner) {
        match key {
            Leaf::Key(k) => keys.push(k),
            Leaf::Vault(id) => vaults.push(id),
        }
    }
}

enum Leaf {
    Key(VaultMemberKey),
    Vault(Bytes32),
}

fn parse_leaf_member(alloc: &Allocator, puzzle: Puzzle) -> Option<Leaf> {
    let curried = puzzle.as_curried()?;
    let args = curried.args;

    if curried.mod_hash == BlsMember::mod_hash()
        && let Ok(m) = BlsMember::from_clvm(alloc, args)
    {
        return Some(Leaf::Key(VaultMemberKey::Bls(m.public_key)));
    }
    if curried.mod_hash == BlsMemberPuzzleAssert::mod_hash()
        && let Ok(m) = BlsMemberPuzzleAssert::from_clvm(alloc, args)
    {
        return Some(Leaf::Key(VaultMemberKey::Bls(m.public_key)));
    }
    if curried.mod_hash == K1Member::mod_hash()
        && let Ok(m) = K1Member::from_clvm(alloc, args)
    {
        return Some(Leaf::Key(VaultMemberKey::K1(m.public_key)));
    }
    if curried.mod_hash == K1MemberPuzzleAssert::mod_hash()
        && let Ok(m) = K1MemberPuzzleAssert::from_clvm(alloc, args)
    {
        return Some(Leaf::Key(VaultMemberKey::K1(m.public_key)));
    }
    if curried.mod_hash == R1Member::mod_hash()
        && let Ok(m) = R1Member::from_clvm(alloc, args)
    {
        return Some(Leaf::Key(VaultMemberKey::R1(m.public_key)));
    }
    if curried.mod_hash == R1MemberPuzzleAssert::mod_hash()
        && let Ok(m) = R1MemberPuzzleAssert::from_clvm(alloc, args)
    {
        return Some(Leaf::Key(VaultMemberKey::R1(m.public_key)));
    }
    if curried.mod_hash == PasskeyMember::mod_hash()
        && let Ok(m) = PasskeyMember::from_clvm(alloc, args)
    {
        return Some(Leaf::Key(VaultMemberKey::Passkey(m.public_key)));
    }
    if curried.mod_hash == PasskeyMemberPuzzleAssert::mod_hash()
        && let Ok(m) = PasskeyMemberPuzzleAssert::from_clvm(alloc, args)
    {
        return Some(Leaf::Key(VaultMemberKey::Passkey(m.public_key)));
    }
    if curried.mod_hash == SingletonMember::mod_hash()
        && let Ok(m) = SingletonMember::from_clvm(alloc, args)
    {
        return Some(Leaf::Vault(m.singleton_struct.launcher_id));
    }
    if curried.mod_hash == SingletonMemberWithMode::mod_hash()
        && let Ok(m) = SingletonMemberWithMode::from_clvm(alloc, args)
    {
        return Some(Leaf::Vault(m.singleton_struct.launcher_id));
    }
    None
}

#[cfg(test)]
mod tests {
    use chia_sdk_driver::SpendContext;
    use chia_sdk_types::puzzles::{BlsMember, IndexWrapperArgs};

    use crate::keys::{MnemonicWordCount, generate_mnemonic};

    use super::*;

    #[test]
    fn parse_curried_bls_member() {
        let mut ctx = SpendContext::new();
        let key = generate_mnemonic(MnemonicWordCount::Words12).unwrap();
        let member = BlsMember::new(key.key_pair.public_key);
        let puzzle = ctx.curry(member).unwrap();
        let alloc: &Allocator = &ctx;
        let parsed = Puzzle::parse(alloc, puzzle);
        let leaf = parse_leaf_member(alloc, parsed);
        assert!(
            matches!(leaf, Some(Leaf::Key(VaultMemberKey::Bls(_)))),
            "failed to parse curried BLS member"
        );
    }

    #[test]
    fn parse_index_wrapped_bls_member() {
        let mut ctx = SpendContext::new();
        let key = generate_mnemonic(MnemonicWordCount::Words12).unwrap();
        let inner = ctx.curry(BlsMember::new(key.key_pair.public_key)).unwrap();
        let wrapped = ctx.curry(IndexWrapperArgs::new(0usize, inner)).unwrap();
        let alloc: &Allocator = &ctx;
        let parsed = Puzzle::parse(alloc, wrapped);
        let (mut keys, vaults) = parse_member_keys(alloc, parsed, NodePtr::NIL);
        assert!(vaults.is_empty());
        assert!(
            matches!(keys.first(), Some(VaultMemberKey::Bls(_))),
            "keys={keys:?}"
        );
        keys.clear();
    }

    #[test]
    fn reconstructed_bls_custody_is_not_labeled_recovery_phrase() {
        let custody = generate_mnemonic(MnemonicWordCount::Words12).unwrap();
        let labeled = members_to_config(&[VaultMemberKey::Bls(custody.key_pair.public_key)], &[]);
        assert!(matches!(
            labeled.first(),
            Some(VaultConfigMember::PublicKey {
                key_type: None,
                curve: Curve::Bls12_381,
                ..
            })
        ));
    }

    #[test]
    fn hash_only_config_uses_custody_path_hash() {
        let recovery = generate_mnemonic(MnemonicWordCount::Words12).unwrap();
        let hash_only = DiscoveredCustodyPath {
            custody_hash: TreeHash::from(Bytes32::new([0x11; 32])),
            members: vec![],
            vault_launcher_ids: vec![],
        };
        let config = reconstruct_config(
            Bytes32::new([0x22; 32]),
            &hash_only,
            &recovery.words,
            43_200,
        )
        .unwrap();
        assert!(config.custody.members.is_empty());
        assert!(config.custody.hash.is_some());
        assert!(matches!(
            config.to_vault_keys().unwrap().custody,
            CustodyPath::Hash(_)
        ));
    }

    #[test]
    fn clawback_guess_candidates() {
        assert_eq!(
            ClawbackGuess::Unknown.candidates(),
            DEFAULT_TIMELOCK_CANDIDATES
        );
        assert_eq!(ClawbackGuess::Known(5).candidates(), vec![5]);
        assert_eq!(
            ClawbackGuess::Unknown.with_typed(Some(5)),
            ClawbackGuess::Known(5)
        );
        let hinted = ClawbackGuess::Hint(7).candidates();
        assert_eq!(hinted[0], 7);
        assert!(hinted.contains(&43_200));
    }

    fn dummy_found() -> FoundVault {
        FoundVault {
            launcher_id: Bytes32::new([0xaa; 32]),
            launcher_source: "test".into(),
            custody: DiscoveredCustodyPath {
                custody_hash: TreeHash::from(Bytes32::new([0x11; 32])),
                members: vec![],
                vault_launcher_ids: vec![],
            },
            current_coin: Coin::new(Bytes32::new([0x22; 32]), Bytes32::new([0x33; 32]), 1),
            ancestor_puzzle_hashes: vec![],
        }
    }

    #[test]
    fn check_clawback_hint_without_phrase() {
        let check = check_clawback(&dummy_found(), None, Some(43_200)).unwrap();
        assert!(matches!(check, ClawbackCheck::Hint(43_200)));
        assert_eq!(check.guess(), ClawbackGuess::Hint(43_200));
    }

    #[test]
    fn check_clawback_requires_something() {
        let err = check_clawback(&dummy_found(), Some("   "), None).unwrap_err();
        assert!(err.to_string().contains("later"));
    }
}
