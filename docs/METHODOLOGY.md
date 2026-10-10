# Methodology

All detections are **heuristics that produce leads**. Each rule below states what it looks at, why that is suspicious, and what legitimately triggers it.

## Disk imaging (`imaging.py`)

1. Open the source read-only, unbuffered. Size comes from seeking to the end (works for files and block devices).
2. Read in blocks (default 1 MiB). Hash the bytes **as they are read**, before they are written.
3. On a read error, re-read that block sector by sector (512 B). Unreadable sectors are replaced by zeros and recorded in `bad_ranges` (adjacent sectors are merged). The hashes therefore describe the data *as acquired*, zero-fill included; the custody record says how many bytes that is.
4. `fsync` the image, re-read it from disk, hash it again and compare with the acquisition hashes. A mismatch aborts with a non-zero exit and the custody file records `verified: false`.
5. A source that returns end-of-file early is an error, not something to pad silently.

What this does not provide: write protection, acquisition of hidden areas (HPA/DCO), or support for forensic container formats.

## `$MFT` parsing (`mft.py`)

* **Record layout.** Each `FILE` record is 1024 bytes (2048/4096 supported; detected from record 0). The last two bytes of every 512-byte sector are replaced on disk by the update-sequence number; the originals live in the update sequence array. The parser verifies and restores them. A mismatch (torn write or corruption) is reported in `warnings` and the sector is left as is.
* **Attributes.** `$STANDARD_INFORMATION` (0x10), `$FILE_NAME` (0x30; Win32 / POSIX / DOS names, Win32 preferred), `$DATA` (0x80; resident or non-resident size, named streams listed as ADS), `$ATTRIBUTE_LIST` (0x20; detected; the extension records it points to are merged into the base record by record number, and the size of a fragmented `$DATA` stream is taken from the extent that starts at VCN 0).
* **Locating `$MFT` in an image.** Read the NTFS boot sector (bytes/sector, sectors/cluster, `$MFT` start cluster, clusters-per-record), read record 0, decode the data-run list of its unnamed `$DATA` attribute, and stream the runs. Sparse runs are zero-filled.
* **Paths.** Built from the parent reference of the preferred `$FILE_NAME`. If the parent record is missing the path starts with `<orphan>`. If the parent slot's sequence number differs from the one stored in the child's `$FILE_NAME`, the parent was recycled after the child was written; the path is still produced but `path_uncertain=1`. Cycles are cut.
* **Times.** FILETIME ticks (100 ns since 1601) are kept as integers and printed with 7 fractional digits so sub-second precision is never lost.

### Timestomp indicators

`$STANDARD_INFORMATION` (SI) times can be changed with ordinary Win32 calls (`SetFileTime`) and by common tools. `$FILE_NAME` (FN) times in the MFT record are maintained by the NTFS driver and are not changed by those calls, so disagreement between them is informative.

| ID | Condition | Why suspicious | Known benign causes |
|---|---|---|---|
| TS-001 (low) | SI created is earlier than FN created by more than the tolerance (default 1 s) | FN reflects when the name was created on this volume; an SI date before that suggests back-dating | Some archive extractors; files restored or moved with preserved times; cross-volume copies by certain tools |
| TS-002 (low) | SI created **and** modified fall exactly on a whole second while FN created has a non-zero sub-second part | Windows timestamps normally carry a sub-second part; simple timestomp tools write whole seconds. Weak on its own: coarse system-clock ticks can occasionally land on a whole second | Timestamps imported from FAT/exFAT or ZIP (2-second / 1-second resolution); coarse clock ticks |
| TS-003 (low) | SI MFT-change time is earlier than SI modified time (beyond tolerance) | API time changes stamp "MFT changed" with the current time, so it should not be older than a modified time set at the same moment | A user deliberately setting a future modified time |

A record can trigger more than one rule; two or more together is a stronger lead than one. None of these prove tampering. Corroborate with `$UsnJrnl`, `$LogFile`, event logs, Prefetch and other sources.

## Memory triage (`memory.py`)

Volatility 3 locates and decodes the kernel structures; `fet` only interprets its output.

| ID | Rule | Severity | ATT&CK | False-positive notes |
|---|---|---|---|---|
| MEM-001 | In `psscan`, **no exit time**, absent from `pslist` | high | T1014 | Race with a process that was being created/destroyed during acquisition |
| MEM-002 | In `psscan`, **has exit time**, absent from `pslist` | info | - | Normal: exited processes linger in pool memory |
| MEM-010 | A known system process (`svchost`, `lsass`, `services`, `smss`, ...) whose parent exists but is not an expected parent | high | T1036.005 | Rare OS-version differences; extend `EXPECTED_PARENT` if you see one |
| MEM-011 | More than one live `lsass`/`wininit`/`services`/`lsm` | high | T1036.005 | None known on a healthy system |
| MEM-012 | Process name within edit distance 2 of a critical system process and not itself a known system name | medium | T1036.005 | Third-party software with similar names |
| MEM-013 | `svchost.exe` command line without `-k` | medium | T1036.005 | Rare legitimate standalone svchost use |
| MEM-014 | System binary name running from outside `System32` (path from the command line) | high | T1036.005 | `System32`, `SysWOW64` and `\SystemRoot` forms are accepted; other legitimate layouts need `SYSTEM_DIRS` extended |
| MEM-015 | Command line matches an attack pattern (encoded PowerShell, hidden window, download cradle, `certutil -urlcache`, `mshta` URL, `regsvr32` scriptlet, `bitsadmin /transfer`, ...) | high | per pattern | Admin scripts and software installers also use these |
| MEM-020 | Malfind region (private RWX memory); higher severity if it starts with `MZ` | high/medium | T1055 | JIT compilers (.NET, browsers, Java), some security products |
| MEM-030 | External (public) connection owned by a process that normally has no network traffic (`lsass`, `services`, `csrss`, `notepad`, ...) | high | T1071 | Extremely rare |

Rules that depend on a process's parent are skipped when the parent no longer exists (for example `wininit.exe`'s parent `smss.exe` exits by design).

**Triage never replaces analysis.** For each finding, confirm with the appropriate Volatility plugin (`windows.vadinfo`, `windows.dumpfiles`, `windows.dlllist`, `windows.handles`) and with disk and log evidence.

## Strings and IOCs (`strings_ioc.py`)

ASCII and UTF-16LE runs of at least `--min-len` printable characters. The file is streamed in 8 MiB chunks; the trailing printable run of each chunk is carried into the next so that strings across a boundary are reported whole and once (tested with chunk sizes from 1 byte up). Strings longer than 1 MiB are split into 1 MiB pieces. IOC patterns: URLs, e-mail addresses, IPv4 (public only by default; version-number lookalikes such as `v8.8.8.8` are skipped), registry keys.
