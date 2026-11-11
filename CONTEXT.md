# Vault Recovery

Recover a Chia Cloud Wallet vault from its Receive address using the recovery phrase, then rekey custody.

## Language

**Vault**:
A Cloud Wallet MIPS 1-of-2 singleton (custody | recovery) identified by a launcher id.
_Avoid_: wallet, account

**Receive address**:
The bech32m `xch1…` / `txch1…` address shown in Cloud Wallet. It does not contain the launcher id, but it can be rebuilt from one (its p2 puzzle curries the launcher id), which is how the launcher scan recognizes the vault. A vault has one at nonce 0; the address walk also checks derived nonces up to 100, a chosen search bound. A spend that reveals a higher-nonce puzzle is still found. It does not depend on the vault singleton's puzzle, which Cloud Wallet has changed over time.
_Avoid_: wallet address (ambiguous)

**Recovery phrase**:
The 12- or 24-word BIP39 phrase Cloud Wallet issued for delayed recovery. Never written to the lookup cache.
_Avoid_: passphrase, mnemonic, seed (overloaded)

**Custody phrase**:
A 12- or 24-word BIP39 phrase that becomes the post-recovery spend key.
_Avoid_: mnemonic, passphrase

**New recovery phrase**:
A 12- or 24-word BIP39 phrase for the recovery branch after rekey. Generated (24 words by default) when the user does not supply one.
_Avoid_: mnemonic, passphrase

**Clawback timelock**:
The delay, in seconds, during which old custody can still cancel a started recovery.
_Avoid_: timeout, wait period

**Lookup**:
Resolving a Receive address to the launcher and the on-chain recovery hint, or to a prior custody spend when that hint is absent. Does not need the recovery phrase. The whole lookup has a 30-minute deadline; in the GUI, Cancel stops it, including the launcher match.
_Avoid_: discover, resolve (CLI aliases only)

**Launcher scan**:
Opt-in lookup step for a never-spent vault: check every singleton launcher in a block range (`--created-on` or `--scan-from-height`/`--scan-to-height`) against the Receive address. Runs last, only when nothing at the address reveals the launcher. Matching stops at the first match, page by page, and yields to the runtime so the lookup deadline or GUI Cancel can stop it. Height ranges are limited to 5 days unless `--force-scan`; a created-on resolved range has a sanity cap of twice that. The address lookup stops at 8 pages or the record cap and returns a partial list; the scan must be complete and reports an error otherwise.
_Avoid_: deep search, brute force

**Found vault**:
The public chain facts from a successful lookup: launcher, custody path, current coin, ancestor puzzle hashes. No recovery phrase and no clawback timelock.
_Avoid_: vault-config (that file also has clawback and recovery pubkey)

**Lookup cache**:
The last successful lookup on disk (hinted layout or found vault), shared by GUI and CLI, so a later run can skip lookup. It carries a format version; an older or unversioned file is ignored. A lookup that needs a fallback removes the entry for that address.
_Avoid_: vault-config, session, save file

**On-chain recovery hint**:
The CHIP-0043 memo Cloud Wallet writes on the vault singleton. It reveals the public custody and recovery layout, including the clawback timelock. Primary source for recovery.
_Avoid_: download, vault-config export

**Clawback hint**:
A user-supplied clawback timelock that has not been checked against the chain (no recovery phrase yet).
_Avoid_: clawback (unqualified), on-chain recovery hint

**Verified clawback**:
A clawback timelock that matched the chain when reconstructed with the recovery phrase.
_Avoid_: confirmed timeout

**Custody path**:
The One-of-N member of the vault inner puzzle used for everyday spends (passkey or Chia Signer App).
_Avoid_: custody key (may be hash-only)

**Start recovery**:
Broadcast the delayed-recovery spend that moves the vault into RECOVERY.
_Avoid_: recover (the whole process)

**Finish recovery**:
The permissionless rekey after the clawback timelock, to new BLS custody. Finish and inspect follow the vault from its launcher; a settled vault is reported, not spent.
_Avoid_: complete, claim

**Finished**:
The vault under the recovered custody configuration after finish recovery.
_Avoid_: complete

**Clawed back**:
The vault back under the original custody configuration, created by the recovery coin after old custody cancelled recovery.
_Avoid_: cancelled, reverted

**Inspect**:
Report the vault's phase from its launcher, with a note when a finish or clawback spend is pending or cannot be checked.
_Avoid_: check, status
