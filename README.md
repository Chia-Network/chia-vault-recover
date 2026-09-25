# Chia Vault Recover

Recover a [Chia Cloud Wallet](https://www.chia.net/) vault using the BIP39 recovery passphrase, then rekey custody to a new BLS mnemonic.

Licensed under the [Apache License 2.0](LICENSE).

## What you need

1. **The vault Receive address** — the bech32m `xch1…` or `txch1…` address shown in Cloud Wallet. Start here. The first run looks up the launcher and reads the on-chain recovery hint. You do **not** enter the recovery phrase for this check.
2. **Recovery passphrase** — the 24-word phrase Cloud Wallet gave you for vault recovery. Needed to **Start recovery** (to sign). You may also enter it after lookup to confirm it matches the hint. It is never written to the lookup cache.
3. **A new custody mnemonic** — 24 words by default (12 optional); this becomes the post-recovery spend key. The tool can auto-generate a second mnemonic for the new recovery branch. Also only needed when you start.

You also need network access (coinset by default, or a full node) to find the vault singleton and broadcast transactions.

Cloud Wallet publishes the public vault layout in a CHIP-0043 memo on the vault singleton (the recovery hint). This tool reads that memo. It includes custody and recovery public keys and the clawback timelock. It does not include the recovery phrase.

## Recover a vault

### GUI

```bash
chia-vault-recover-gui
```

The GUI is a short wizard: **Look up → Start → Finish**. Only one step is on screen at a time.

1. **Look up** — Paste the vault Receive address and click **Look up vault**. This does not ask for the recovery phrase. A successful lookup is saved on disk (see [Lookup cache](#lookup-cache)). The full node URL is under Advanced.
2. If lookup asks for a self-send, follow the on-screen steps (same as the CLI notes below). That spend publishes the recovery hint.
3. **Start** — When the hint is present, the clawback window is already filled in. Paste the recovery phrase and a new custody mnemonic, then **Start recovery**. Public configs are written under `~/.chia-vault-recover/` by default (override with Browse).
4. You can **close the app** after lookup or after Start. The next launch skips any home screen and opens **Start** (saved lookup) or **Finish** (recovery already started).
5. **Finish** — After the clawback window, click **Finish recovery**. Remaining time is shown when Start was recorded in this app.

`xch1…` / `txch1…` selects mainnet or testnet11 automatically.

### CLI

#### 1. Look up the address

```bash
chia-vault-recover lookup --vault xch1...
```

`txch1…` selects testnet11; `xch1…` selects mainnet. A hex launcher id still works if you have one.

The tool:

1. Decodes the Receive address
2. Finds the vault launcher id from spent coins at that address (or their parents)
3. Walks the vault singleton and reads the Cloud Wallet recovery hint from the CHIP-0043 memo
4. If that hint is missing, falls back to a previous **custody** spend

You should see: *This vault can be recovered from the on-chain hint.* The lookup is written to the [lookup cache](#lookup-cache). The recovery phrase is not needed until `start`.

To store a clawback hint, or to verify one if you also pass the phrase:

```bash
chia-vault-recover lookup --vault xch1... --clawback-secs 43200
chia-vault-recover lookup --vault xch1... --clawback-secs 43200 \
  --recovery-mnemonic-file recovery.txt
```

The recovery phrase is used only in memory. It is never written to the cache.

#### 2. If lookup cannot find a custody spend

The Receive address does **not** contain the launcher id. An unused vault, or a vault that has only ever received funds, has nothing on chain for this tool to parse. A vault that has not yet been spent with the recovery hint also cannot be rebuilt from the address alone.

**If you can still open the vault at [vault.chia.net](https://vault.chia.net):**

Send any amount from the vault back to the same Receive address (or any address you control). A self-send is enough. Cloud Wallet spends the vault singleton with your passkey or the Chia Signer App, which publishes the launcher id and the recovery hint. Wait for that transaction to confirm, then run `lookup` on the same address again.

If you cannot access Cloud Wallet and the hint is not already on chain, this tool cannot recover the vault from the address alone.

#### 3. Start delayed recovery

```bash
chia-vault-recover start \
  --vault xch1... \
  --recovery-mnemonic-file recovery.txt \
  --new-custody-mnemonic-file new-custody.txt \
  --out-config post-recovery-vault-config.json
```

`start --vault` reuses the lookup cache when present (no chain walk). Otherwise it looks up the vault and writes the cache. When the on-chain hint is present, that layout and clawback are used and the recovery phrase only signs. Without the hint, the public layout is rebuilt from the recovery phrase. If you know the current clawback window, pass `--clawback-secs` (for example `43200`). If you omit it, a verified cache value is used; then a user-supplied hint (tried first, then defaults); then common Cloud Wallet values until the reconstructed spend matches the chain. The vault enters RECOVERY (the old passkey or Chia Signer App can still claw back during the window). Run `lookup` again to refresh a stale cache.

`start` writes the public layout to `vault-config.json` (override with `--lookup-config`). `finish` reads that file. Pass `--config` only when you already have the public layout this tool wrote.

#### 4. Wait, then finish

Wait `clawbackTimelock` seconds (often 43200 / 12h):

```bash
chia-vault-recover finish \
  --config vault-config.json \
  --post-recovery-config post-recovery-vault-config.json
```

Default destination: new **24-word** BLS custody + an **auto-generated** second BLS recovery mnemonic (12-word option available). The generated recovery mnemonic is shown once (CLI print / GUI clipboard) and is **not** written into the public post-recovery config file.

## Install / build

```bash
cargo build --release
# binaries: target/release/chia-vault-recover
#           target/release/chia-vault-recover-gui
```

## CLI reference

```bash
# First run: address only (reads the on-chain recovery hint)
chia-vault-recover lookup --vault xch1...

# Optional: save a clawback hint, or verify it with the recovery phrase
chia-vault-recover lookup --vault xch1... --clawback-secs 43200
chia-vault-recover lookup --vault xch1... --clawback-secs 43200 \
  --recovery-mnemonic-file recovery.txt

# Later: start delayed recovery (phrase required here)
chia-vault-recover start \
  --vault xch1... \
  --recovery-mnemonic-file recovery.txt \
  --new-custody-mnemonic-file new-custody.txt

# Optional: pass the current clawback window if you know it
chia-vault-recover start \
  --vault xch1... \
  --clawback-secs 43200 \
  --recovery-mnemonic-file recovery.txt \
  --new-custody-mnemonic-file new-custody.txt

# After the clawback window
chia-vault-recover finish \
  --config vault-config.json \
  --post-recovery-config post-recovery-vault-config.json

# Confirm the public layout this tool wrote
chia-vault-recover inspect --config vault-config.json
```

`lookup` aliases: `discover`, `resolve`.

Useful flags:

| Flag | Meaning |
|------|---------|
| `--vault` | Receive address (`xch1…` / `txch1…`) or launcher id. Aliases: `--address`, `--launcher-id` |
| `--network mainnet\|testnet11` | Used when the input is a hex launcher id. Addresses pick the network from `xch` / `txch` |
| `--backend coinset\|rpc` | Default **coinset**; with `rpc` set `--full-node-url` |
| `--word-count 12\|24` | Length for auto-generated recovery mnemonic (default 24) |
| `--clawback-secs` | On `lookup`, saved as a user hint unless a recovery phrase is also given (then verified). Ignored when the on-chain hint already has the timelock, unless the value disagrees with that hint. On `start --vault` without an on-chain hint, an explicit value is tried alone; if omitted, a verified cache value, then a user hint, then common Cloud Wallet values (including 43200 / 12h) |

Fees are not supported yet (zero-fee spends only).

Mnemonics may also be passed via env: `CHIA_VAULT_RECOVERY_MNEMONIC`, `CHIA_VAULT_NEW_CUSTODY_MNEMONIC`.

## What it does on chain

Cloud Wallet vaults are MIPS 1-of-2 singletons (custody | recovery). This tool runs **delayed (timelocked) recovery**:

1. **lookup** — address → launcher → on-chain recovery hint (or a prior custody spend if the hint is absent); writes the lookup cache. No recovery phrase
2. **start** — reuse cache when present; recovery phrase signs. The hint supplies the public layout and clawback. Without a hint, `--clawback-secs` or the cache / common values rebuild the layout. Vault enters RECOVERY
3. wait for `clawbackTimelock` seconds
4. **finish** — permissionless rekey to the new custody configuration

## Key derivation (Cloud Wallet compatible)

```
BIP39 mnemonic → seed("") → AugSchemeMPL.keyGen / SecretKey::from_seed
```

No `m/12381/8444/...` path. Matches Cloud Wallet `bls.ts`.

## Lookup cache

A successful lookup writes the public chain facts (launcher, custody path, current coin, ancestor puzzle hashes) to a JSON file shared by the GUI and CLI. The recovery phrase is never stored.

Default path (macOS, Windows, and Linux): `~/.chia-vault-recover/lookup-cache.json`.

- `CHIA_VAULT_RECOVER_DIR` — app data directory (cache, GUI session, default vault-config paths). Default: `~/.chia-vault-recover`.
- `CHIA_VAULT_RECOVER_CACHE` — lookup-cache file path only. Default: `$CHIA_VAULT_RECOVER_DIR/lookup-cache.json` (or `~/.chia-vault-recover/lookup-cache.json`).

The GUI stores public vault-config / post-recovery-config files in that same directory by default, plus a small `gui-session.json` (paths and Start time only — never mnemonics) so Finish works after relaunch.

On GUI launch, the last saved vault opens on **Start** (or **Finish** if recovery was already started). Run **Look up vault** again to refresh from the chain, or use **Look up a different vault** to clear the GUI session.

When lookup reads the on-chain hint, the clawback from that memo is saved as **verified**.

A user-supplied clawback is stored only when you pass one and the hint did not:

- Without the recovery phrase: saved as a **hint** (tried first at Start, then the usual defaults)
- With the recovery phrase: checked against the chain and saved as **verified** when it matches

## Testing

CI runs **Simulator end-to-end** recovery tests (real puzzles and signatures via `chia-sdk-test`). No live-network CI.

```bash
cargo test --all
```

### Manual testnet11 recipe

1. Look up a testnet vault address (`txch1…`).
2. If lookup asks for a self-send, send a dust amount back to the same address from Cloud Wallet and wait for confirmation. That publishes the recovery hint.
3. Ensure the vault singleton is unspent (zero-fee spends only).
4. Run:

```bash
chia-vault-recover lookup --vault txch1...
chia-vault-recover start --vault txch1... --network testnet11 \
  --recovery-mnemonic-file recovery.txt \
  --new-custody-mnemonic-file new-custody.txt
# wait clawbackTimelock
chia-vault-recover finish --config vault-config.json --network testnet11 \
  --post-recovery-config post-recovery-vault-config.json
```

Or point `--backend rpc --full-node-url https://localhost:8555` at a synced full node.

## Caveats

- Instant recovery (spend/passkey or Chia Signer App key) is out of scope — use delayed recovery with the passphrase.
- A never-spent Receive address cannot yield a launcher id. One Cloud Wallet send (including a self-send) is enough.
- `lookup` reads the Cloud Wallet CHIP-0043 recovery hint from the spend that created the current singleton (including the launcher mint). An unspent eve singleton or a vault spent before that hint existed has no memo to read. One custody send publishes it. A previous custody spend is the fallback when the hint is absent.
- Clawback during the window still requires the old custody passkey or Chia Signer App (not implemented here).
- After finish, custody is on-chain BLS; Cloud Wallet’s product UI may not re-import that vault as a normal passkey or Chia Signer App vault.
- p2-singleton XCH/CATs are unchanged; only the vault singleton’s custody hash changes.

## CI artifacts

Every green CI uploads release binaries for:

- macOS universal (`aarch64` + `x86_64`)
- Windows `x86_64`
- Linux `x86_64` and `aarch64`

GitHub Releases published from `Chia-Network/chia-vault-recover` attach signed builds. Asset names include the version, such as `chia-vault-recover-1.0.0-rc4-macos-universal.dmg`. macOS is a Developer ID signed and notarized disk image. Open the image and double-click **Chia Vault Recover**. The CLI beside it is a command-line tool; run that from Terminal. A raw Mach-O downloaded from a browser is saved without the executable bit, so Finder opens it in TextEdit. Windows is Azure Artifact Signed. Linux release binaries are not code-signed. Pull request builds are unsigned and keep the unversioned artifact names.

### Forks and local builds

Forks do not receive the Chia signing secrets. Their CI still passes. A fork's GitHub Release uploads an unsigned macOS disk image, `chia-vault-recover-<version>-macos-universal.dmg`, plus the Windows and Linux binaries. Those names include the release version too. A local `cargo build --release` is also unsigned. macOS only quarantines files downloaded from the internet, so a binary you built on the same Mac is not blocked.

A pull request's CI artifact zip is the raw Mach-O files, not a disk image. After unzipping that zip, `chmod +x` the binary before running it. A browser download of those loose files opens them in TextEdit.

Gatekeeper on macOS Sequoia and later will not launch a bare executable, including one that is Developer ID signed and sitting on a notarized disk image. Finder reports *Apple could not verify … is free of malware* with **Move to Trash** / **Done**, and `spctl` reports `the code is valid but does not seem to be an app`. Release disk images ship the GUI as `Chia Vault Recover.app`. Control-click → Open does not clear that dialog for a loose binary. 1.0.0-rc4 and earlier macOS assets are loose binaries; run the GUI from Terminal, as below. Windows SmartScreen can show a similar warning for an unsigned `.exe`.

**macOS Settings** for an unsigned app (a fork disk image, or a local build): click **Done**, then System Settings → Privacy & Security → **Open Anyway**.

**macOS Terminal** for a CI artifact or an older release binary (use the path where the file actually is):

```bash
xattr -d com.apple.quarantine chia-vault-recover-gui-macos-universal
chmod +x chia-vault-recover-gui-macos-universal
./chia-vault-recover-gui-macos-universal
```

Same `xattr` / `chmod` for `chia-vault-recover-macos-universal`. For a current release disk image, open the `.dmg` and double-click `Chia Vault Recover`. Do not `chmod` the image itself.
