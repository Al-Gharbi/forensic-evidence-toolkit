# Validation status

What was checked, on what, how to repeat it, and what is **not** covered. Results are from **2026-10-09**; nothing here is a claim about data that was not run.

## 1. Real-data checks

### 1.1 `$MFT` parser vs an independent parser (dfir_ntfs)

`tools/validate_mft.py` parses each file with fet and with [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs) (a different author, GPLv3, imported from a checkout only for this script) and compares, per record: in-use flag, directory flag, sequence number, base-record reference, the four `$STANDARD_INFORMATION` timestamps, the set of `$FILE_NAME` (parent, name, namespace) tuples and the unnamed `$DATA` size.

| Data | Source | Records compared | Differences in any field |
|---|---|---|---|
| `samples/MFT` (13.4 MB, 1 KiB records, real Windows volume) | [omerbenamram/mft](https://github.com/omerbenamram/mft) | 13,068 | **0** |
| `nist-hacking-case.mft` (12.6 MB) | NIST Hacking Case, via dfir_ntfs `test_data/` | 12,304 | **0** |
| `4k-large.mft` (4 KiB records) | dfir_ntfs `test_data/` | 36 | **0** |

* The comparison is not vacuous: three deliberately broken copies of the parser (swapped `$SI` fields, shifted file-name offset, fix-ups disabled) produced 7,270 / 13,057 / 59+12 reported differences on the first file.
* fet and dfir_ntfs both skip the same blank slots (no record is parsed by only one of them).
* All 13 `*.mft` / `.bin` files in dfir_ntfs `test_data/` (slack, orphan, compressed/sparse, unicode, mapping-pairs, fragmented) parse without error.

```bash
git clone --depth 1 https://github.com/msuhanov/dfir_ntfs
python tools/validate_mft.py --dfir-ntfs dfir_ntfs dfir_ntfs/test_data/nist-hacking-case.mft
```

### 1.2 Reconstructed paths vs Sleuth Kit `fls`

`tools/validate_paths_fls.py` compares fet's paths and file sizes with the `fls` listing that ships with the NIST Hacking Case `$MFT` (Sleuth Kit output, produced by a third party).

| | Result |
|---|---|
| `fls` lines | 12,180 (12,176 distinct records) |
| Paths identical | **12,171** |
| Path differences | **0** |
| File-size differences | **0** |
| `fls` record not in fet | 1: `$OrphanFiles`, a virtual Sleuth Kit entry, not a real MFT record |

This check found two real bugs, both fixed: (a) long names stored in extension records were missed, so 8 records showed their 8.3 name (before the fix: 8 path differences); (b) a fragmented file's size was read from a later extent and came out as 0 (before the fix: 1 size difference). Only paths and sizes are compared; the timestamps in the `fls` file were not compared.

### 1.3 Imaging a real block device

A 96 MiB file attached as `/dev/loop0` (a kernel block device) was acquired with `fet image`:

| | |
|---|---|
| Bytes read | 100,663,296 (= `blockdev --getsize64`) |
| SHA-256 reported by fet | `3f2e8537...b3febc` |
| SHA-256 from `sha256sum /dev/loop0` | identical |
| Post-copy verification | passed; `sha256sum` of the written image identical |

### 1.4 Timestomp rules on real, unmanipulated data

Two real `$MFT` files, files in use with both `$SI` and `$FN`:

| Data | Files | Any indicator | TS-001 and TS-002 together |
|---|---|---|---|
| `samples/MFT` | 10,854 | 4,980 (45.9 %) | 4,288 (39.5 %) |
| NIST Hacking Case | 11,409 | 334 (2.9 %) | 231 (2.0 %) |

The flagged files are overwhelmingly installer- or CAB-extracted files that keep their original timestamps (`\WINDOWS\system32`, `\Program Files\...`; `.dll`, `.inf`, `.exe`). **The rules are weak leads, not detections**; all three are now `low` severity. No data set with genuinely back-dated files was available, so the **true-positive rate is unknown**.

### 1.5 Memory triage against Volatility 3's source (no image was run)

Checked by reading the Volatility 3 source (`volatilityfoundation/volatility3`, stable, commit `3fcb731`), not by running it:

* The column names used by the loader exist: `PID`, `PPID`, `ImageFileName`, `Offset(V)`/`Offset(P)`, `CreateTime`, `ExitTime` (pslist, psscan), `PID`/`Process`/`Args` (cmdline), `Start VPN`, `End VPN`, `Protection`, `Hexdump` (malfind), `LocalAddr`, `ForeignAddr`, `State`, `Owner` (netscan).
* The JSON renderer emits nested `__children`, hex values as `0x..` strings, datetimes in ISO format, missing values as `null`, and `Hexdump` as space-separated hex bytes, which matches what the rules read (including the `4d 5a` PE-header test).
* **Found and fixed:** `malfind` now lives in `windows.malware.malfind`; the old `windows.malfind.Malfind` is a deprecated alias announced for removal on 2026-06-07. fet now calls the new name and falls back to the old one.

## 2. Automated tests (synthetic data)

`PYTHONPATH=src python -m unittest discover -s tests -t . -v`: 95 tests, passing on Python 3.11, 3.12 and 3.13. They use hand-built NTFS records and hand-written Volatility-style JSON, so they show the logic, not behaviour on real evidence. Section 1 is what ties the code to real data.

## 3. Not verified

* **A real Windows memory image and a live Volatility 3 run.** No public memory image was reachable from the environment used. `fet mem-triage` is exercised only against hand-written JSON and a stand-in script.
* **Detection of a genuinely back-dated file** (see 1.4).
* **A real NTFS volume image** (`--volume` mode, partition offsets). `iter_mft_volume` is tested only on synthetic volumes; the real data above are extracted `$MFT` files.
* **Real I/O errors** (bad sectors on failing hardware) and sources larger than 100 GB.
* Windows as a host OS; Python 3.9 / 3.10; E01/AFF containers (unsupported).
* Memory-rule false-positive rate on a healthy system.

## 4. To close the memory gap

1. Obtain a Windows memory image with a known answer (for example a MemLabs challenge or a Volatility sample; check its licence).
2. `pip install volatility3`, then `fet mem-triage --image <mem> --out-dir raw/ --report report.md`.
3. Compare each finding with Volatility's own output and the published solution; classify as true positive, false positive or expected benign; add the trimmed, non-sensitive JSON as a test.
