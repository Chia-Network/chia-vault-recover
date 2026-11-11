# Changelog

## Unreleased

The package version is bumped at release time; it is not changed by this entry.

### Added

- Opt-in launcher scan for a never-spent vault: `--created-on`, or
  `--scan-from-height` / `--scan-to-height` (with `--force-scan` to go past the
  5-day limit), and the GUI **Search launchers** option.
- Per-request RPC timeouts, and a hint on `push_tx` timeouts that the
  transaction may still have been submitted.
- Cache format versioning. A lookup cache from an older format is ignored.
- The lookup has an overall 30-minute deadline covering the address walk,
  launcher scan, and hint read.
- Bounds on lookup work: a launcher-scan page cap, a cap on buffered coin
  records, a timestamp-window cap, and a sanity cap on a created-on resolved
  range.
- Finish and inspect follow the vault from its launcher.
- Settled vault phases `Finished` and `ClawedBack`: finish reports them and
  does not push a spend, and the GUI closes its session.
- Inspect notes a pending finish or clawback, or says it could not check;
  an unsuccessful mempool response is reported as unchecked.
- Inspect and finish run under an overall deadline (`INSPECT_DEADLINE`).
- Child-coin listing reports an incomplete listing instead of returning a
  partial result.

### Changed

- Lookup only accepts a launcher that matches the Receive address; the previous
  launcher-from-spend path no longer returns an unrelated singleton launcher.
- A lookup that needs a fallback clears the saved lookup for that address, so
  Start is no longer offered for a stale entry.
- GUI lookup runs in the background with a **Looking up…** state and a
  **Cancel** button.
- The address lookup follows at most 8 pages and stops at the record cap,
  returning the records it read; a launcher scan reports an error when its
  listing is incomplete.
- `workflow::lookup` and `resolve_found` take `LookupOptions`, and the launcher
  scan API `find_launcher_matching` takes a `HeightRange` (library API changes).
- Hint lookups that time out are reported as errors; any other hint-request
  failure reads as no hints.
- Library API: `workflow::inspect`, `workflow::finish`, and `resolve_ready`
  take a generic `ChainClient<C>`. Finish returns `FinishOutcome` /
  `FinishAction`, `VaultPhase` adds `Finished` and `ClawedBack`, and
  `INSPECT_DEADLINE` is public.
- `resolve_vault` is replaced by `resolve_ready(client, config)`;
  `ChainClient::find_unspent_by_puzzle_hash` is removed (library API changes).
