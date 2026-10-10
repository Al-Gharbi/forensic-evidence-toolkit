# forensic-evidence-toolkit (`fet`)

A small, **dependency-free** (Python standard library only) DFIR toolkit that covers three kinds of evidence:

| Evidence | Command | What it does |
|---|---|---|
| Disk / device | `fet image`, `fet verify` | Raw acquisition with streaming MD5/SHA-1/SHA-256/SHA-512, bad-sector zero-fill with a recorded list of bad ranges, post-copy re-hash verification, JSON chain-of-custody record |
| NTFS `$MFT` | `fet mft` | Parses an extracted `$MFT` **or finds and reads it inside an NTFS image**; reconstructs paths; flags deleted entries and alternate data streams; **timestomp indicators** by comparing `$STANDARD_INFORMATION` with `$FILE_NAME`; CSV / JSON / Sleuth Kit bodyfile output |
| Memory image | `fet mem-triage`, `fet strings` | Runs [Volatility 3](https://github.com/volatilityfoundation/volatility3) (pslist, psscan, cmdline, malfind, netscan), **keeps the raw plugin output**, applies documented triage rules (hidden processes, wrong parents, masquerading, suspicious command lines, RWX regions with PE headers, odd network activity) and writes a Markdown + JSON report. `strings` carves ASCII/UTF-16 strings and IOCs from any file without Volatility |

## Status: v0.1.0 - read this before relying on it

* 95 automated tests on **synthetic, hand-built data**, plus a real-data cross-check done on 2026-10-09: the `$MFT` parser agrees with an independent parser (dfir_ntfs) on all 25,408 records of two real `$MFT` files, and with a Sleuth Kit `fls` listing on 12,171 paths of the NIST Hacking Case image; a raw acquisition of a real block device has the same SHA-256 as `sha256sum`.
* **Not validated:** the memory module has never been run against a real memory image or a live Volatility 3 (only checked against Volatility's source), and timestomp detection has never been tested on a genuinely back-dated file. The timestomp rules also flag many ordinary files (2 % and 40 % on the two real MFTs), so treat them as weak leads. Everything, with commands and limits, is in `docs/VALIDATION.md`.
* The memory module needs Volatility 3 installed; it was tested against a stand-in that emits Volatility's documented JSON shape, **not against a live Volatility run**.
* It is **not a write blocker** and does not replace one. See [Limitations](#limitations).

## Install

```bash
git clone https://github.com/Al-Gharbi/forensic-evidence-toolkit.git
cd forensic-evidence-toolkit
pip install .                   # no runtime dependencies
pip install ".[memory]"         # optional: also installs Volatility 3
fet --help
```

Python 3.11+.

## Usage

### 1. Acquire and verify a disk image

```bash
fet image /dev/sdb evidence/suspect.dd --case 2026-014 --examiner "A. Examiner" --hash md5,sha256
fet verify evidence/suspect.dd            # later: re-hash and compare with the custody record
```

Creates `suspect.dd` and `suspect.dd.custody.json` (case, examiner, UTC times, host, source size, hashes of the data read, hashes of the written image, verification result, every unreadable byte range). Existing images are never overwritten unless you pass `--overwrite`. Exit code `2` from `verify` means the image no longer matches.

### 2. Parse the MFT and look for timestomping

```bash
# from an extracted $MFT
fet mft extracted/\$MFT -o mft.csv
fet mft extracted/\$MFT --only-flagged

# straight out of an NTFS image (give the partition start in bytes for whole-disk images)
fet mft suspect.dd --volume --offset $((2048*512)) --format bodyfile -o body.txt
mactime -b body.txt -d > timeline.csv      # Sleuth Kit
```

Timestomp indicators (`TS-001`..`TS-003`) are described, with their false-positive causes, in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

### 3. Triage a Windows memory image

```bash
fet mem-triage --image memory.raw --out-dir case/mem-raw --report case/memory-report.md
# re-run the analysis later (or elsewhere) from the saved plugin output, without the image:
fet mem-triage --from-dir case/mem-raw --report case/memory-report.md
```

Exit code `3` means at least one high-severity finding. Every finding names the evidence that triggered it and its MITRE ATT&CK technique.

### 4. Strings and IOCs from any file

```bash
fet strings memory.raw --min-len 8 -o strings.tsv
fet strings memory.raw --iocs -o iocs.json     # URLs, e-mails, public IPs, registry keys
```

### Try it without any evidence

```bash
python examples/make_demo.py demo/
fet mft demo/demo.mft --only-flagged
fet mem-triage --from-dir demo/memory
```

The demo data is invented; the "attacker" artefacts exist only to show what each detection looks like.

## Example output (synthetic demo data)

```text
## [HIGH] MEM-001 - Process hidden from the active process list
- Detail: implant.exe (PID 1337) is in psscan, has no exit time, but is absent from pslist (possible DKOM / unlinking).
- MITRE ATT&CK: T1014

## [HIGH] MEM-010 - Unexpected parent process
- Detail: svchost.exe (PID 3300) has parent explorer.exe (PID 2100); expected one of services.exe.
```

```text
19,1,1,0,/Users/Public/svch0st.exe,0,5000,2019-01-01 12:00:00.0000000,...,2024-03-05 10:11:12.1234567,...,TS-001;TS-002
```

## How it is built

```
src/fet/
  imaging.py      acquisition, hashing, bad-sector handling, custody record, verify
  mft.py          FILE record + fixup parsing, SI/FN/DATA attributes, data runs,
                  NTFS boot sector -> $MFT location, path building, timestomp rules, exporters
  memory.py       Volatility 3 runner, JSON loader, rule engine (MEM-0xx), report
  strings_ioc.py  streaming string carving (chunk-boundary safe) and IOC extraction
  cli.py          argparse front end
tests/            95 unittest tests; mft_builder.py writes format-correct NTFS records/volumes
```

Measured on the development machine (a real 13 MB `$MFT` parses and analyses in about 0.5 s; the figures below are synthetic data): 400 MB imaged with post-copy verification in about 3 s; a 200,000-record (205 MB) `$MFT` parsed and analysed (paths, timestomp rules) in about 3 s using about 270 MB of RAM (CSV export of it adds roughly 8 s) (all entries are held in memory to resolve paths, so a multi-million-record MFT needs several GB); 100 MB of strings carved in about 5 s.

## Limitations

* **No write protection.** Reading a device read-only from user space does not stop the OS from touching it. Use a hardware write blocker or a read-only forensic boot environment for physical media.
* **Raw output only.** No E01/AFF containers, no compression, no split images.
* **MFT:** extension records are merged into their base record (names, `$DATA` size, streams); `$ATTRIBUTE_LIST` entries themselves are not interpreted, so a record whose base record is missing stays partial. `$UsnJrnl`, `$LogFile`, compressed/encrypted content and resident-data extraction are out of scope.
* **Timestomp and memory rules are heuristics.** They generate leads, not verdicts. JIT-compiled code, archive extraction, AV hooks and user-set times all cause legitimate hits (see METHODOLOGY).
* **Memory:** Windows only; depends on Volatility 3's plugin output format. A clean report does not prove an image is clean.

## Roadmap

- Run `fet mem-triage` on a real Windows memory image with Volatility 3 and record the result (`docs/VALIDATION.md`)
- Test timestomp detection on files back-dated with real tools
- `$UsnJrnl` / `$LogFile` parsing
- E01 reading, additional memory plugins (dlllist, handles, vadinfo)

## License

MIT. See [LICENSE](LICENSE).
