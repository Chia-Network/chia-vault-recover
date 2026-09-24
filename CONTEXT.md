# Vault Recovery

Recover a Chia Cloud Wallet vault from its Receive address using the recovery phrase, then rekey custody.

## Language

**Vault**:
A Cloud Wallet MIPS 1-of-2 singleton (custody | recovery) identified by a launcher id.
_Avoid_: wallet, account

**Receive address**:
The bech32m `xch1…` / `txch1…` address shown in Cloud Wallet. It does not contain the launcher id.
_Avoid_: wallet address (ambiguous)

**Recovery phrase**:
The BIP39 words Cloud Wallet issued for delayed recovery. Never written to the lookup cache.
_Avoid_: 24 words (length varies), seed (overloaded)

**Clawback timelock**:
The delay, in seconds, during which old custody can still cancel a started recovery.
_Avoid_: timeout, wait period

**Lookup**:
Resolving a Receive address to the launcher and a prior custody spend. Does not need the recovery phrase.
_Avoid_: discover, scan (CLI aliases only)

**Found vault**:
The public chain facts from a successful lookup: launcher, custody path, current coin, ancestor puzzle hashes. No recovery phrase and no clawback timelock.
_Avoid_: vault-config (that file also has clawback and recovery pubkey)

**Lookup cache**:
The last found vault on disk, shared by GUI and CLI, so a later run can skip lookup.
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
The permissionless rekey after the clawback timelock, to new BLS custody.
_Avoid_: complete, claim
