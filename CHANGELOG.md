# Changelog

## [0.1.0] - unreleased
First version. Parts were cross-checked on real data (see `docs/VALIDATION.md`
for what is and is not verified).

### Fixed after real-data validation
- Extension records are merged into their base record. Before, 8 records of the
  NIST Hacking Case image showed their 8.3 name instead of the long name and one
  fragmented file reported size 0 (size now comes from the VCN-0 extent).
- TS-001 and TS-002 downgraded from medium to low: on two real unmanipulated
  `$MFT` files they flagged 2.0 % and 39.5 % of ordinary files.
- `malfind` runs as `windows.malware.malfind.Malfind` (the old
  `windows.malfind.Malfind` is a deprecated alias that Volatility announced for
  removal on 2026-06-07); the old name is kept as a fallback.

### Added
- `fet image`: raw acquisition with streaming hashes, bad-sector zero-fill and
  recording, post-copy verification, JSON chain-of-custody record; `fet verify`.
- `fet mft`: `$MFT` parser (fixups, `$STANDARD_INFORMATION`, `$FILE_NAME`,
  `$DATA`/ADS, path reconstruction), reads an extracted `$MFT` or locates it
  inside an NTFS image; CSV / JSON / Sleuth Kit bodyfile output; timestomp
  indicators TS-001..TS-003.
- `fet mem-triage`: Volatility 3 orchestration (pslist, psscan, cmdline,
  malfind, netscan), raw output preserved, rule engine MEM-001..MEM-030,
  Markdown + JSON report; works offline from saved output (`--from-dir`).
- `fet strings`: streaming ASCII/UTF-16 string carving and IOC extraction.
