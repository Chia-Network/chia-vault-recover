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
- Bounds on lookup work: an overall lookup deadline, a launcher-scan page cap, a
  cap on buffered coin records, a timestamp-window cap, and a sanity cap on a
  created-on resolved range.

### Changed

- Lookup only accepts a launcher that matches the Receive address; the previous
  launcher-from-spend path no longer returns an unrelated singleton launcher.
- A lookup that needs a fallback clears the saved lookup for that address, so
  Start is no longer offered for a stale entry.
- GUI lookup runs off the UI thread with a **Looking up…** state and a
  **Cancel** button.
- Hint lookups that time out are reported as errors; any other hint-request
  failure reads as no hints.
