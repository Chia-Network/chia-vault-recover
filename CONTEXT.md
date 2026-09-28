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
Resolving a Receive address to the launcher and the on-chain recovery hint, or to a prior custody spend when that hint is absent. Does not need the recovery phrase.
_Avoid_: discover, resolve (CLI aliases only)

**Found vault**:
The public chain facts from a successful lookup: launcher, custody path, current coin, ancestor puzzle hashes. No recovery phrase and no clawback timelock.
_Avoid_: vault-config (that file also has clawback and recovery pubkey)

**Lookup cache**:
The last successful lookup on disk (hinted layout or found vault), shared by GUI and CLI, so a later run can skip lookup.
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
