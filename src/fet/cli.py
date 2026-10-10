"""Command-line interface: ``fet <command>`` / ``python -m fet <command>``."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, imaging, memory, mft, strings_ioc


def _progress(done: int, total: int) -> None:
    if total:
        sys.stderr.write(f"\r  {done / total * 100:5.1f}%  {done:,}/{total:,} bytes")
        sys.stderr.flush()
        if done >= total:
            sys.stderr.write("\n")


def cmd_image(a: argparse.Namespace) -> int:
    rec = imaging.acquire(
        a.source, a.dest, case_id=a.case, examiner=a.examiner, algorithms=a.hash.split(","),
        block_size=a.block_size, notes=a.notes or "", overwrite=a.overwrite,
        custody_path=a.custody, progress=None if a.quiet else _progress,
    )
    print(f"Image:      {rec['image']['path']} ({rec['image']['size_bytes']:,} bytes)")
    for k, v in rec["acquisition_hashes"].items():
        print(f"{k.upper():<11} {v}")
    print(f"Verified:   {'YES' if rec['verified'] else 'NO'}")
    if rec["bad_ranges"]:
        print(f"WARNING: {rec['bad_bytes']:,} unreadable bytes zero-filled in {len(rec['bad_ranges'])} range(s)")
    print(f"Custody:    {rec['custody_file']}")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    res = imaging.verify(a.image, a.custody)
    for k, v in res["computed"].items():
        print(f"{k.upper():<8} {v}  {'OK' if k not in res['mismatches'] else 'MISMATCH'}")
    print("RESULT:", "image matches custody record" if res["ok"] else "IMAGE DOES NOT MATCH")
    return 0 if res["ok"] else 2


def cmd_mft(a: argparse.Namespace) -> int:
    with open(a.input, "rb") as f:
        if a.volume:
            entries = list(mft.iter_mft_volume(f, a.offset))
        else:
            entries = list(mft.iter_mft_file(f, a.record_size))
    entries = mft.analyze(entries, a.tolerance)
    if a.only_flagged:
        entries = [e for e in entries if e.indicators]
    renderer = {"csv": mft.to_csv, "json": mft.to_json, "bodyfile": mft.to_bodyfile}[a.format]
    text = renderer(entries)
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
        print(f"wrote {a.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    summary = mft.summarize(entries)
    print("summary: " + ", ".join(f"{k}={v}" for k, v in summary.items()), file=sys.stderr)
    return 0


def cmd_mem(a: argparse.Namespace) -> int:
    if a.from_dir:
        snap = memory.load_dir(a.from_dir)
    else:
        if not a.image:
            print("error: give --image or --from-dir", file=sys.stderr)
            return 1
        out_dir = a.out_dir or "mem-triage-output"
        vol = shlex.split(a.vol_cmd) if a.vol_cmd else None
        snap = memory.collect(a.image, out_dir, vol, a.timeout)
        print(f"raw plugin output saved to {out_dir}/", file=sys.stderr)
    result = memory.triage(snap)
    md = memory.render_markdown(result)
    if a.report:
        Path(a.report).write_text(md, encoding="utf-8")
        Path(a.report).with_suffix(".json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"wrote {a.report} (+ .json)", file=sys.stderr)
    else:
        sys.stdout.write(md)
    return 3 if result["counts"]["high"] else 0


def cmd_strings(a: argparse.Namespace) -> int:
    with open(a.input, "rb") as f:
        if a.iocs:
            res = strings_ioc.extract_iocs(strings_ioc.iter_strings(f, a.min_len), not a.all_ips)
            text = json.dumps(res, indent=2)
        else:
            text = "".join(f"{off}\t{enc}\t{s}\n" for off, enc, s in strings_ioc.iter_strings(f, a.min_len))
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fet", description="forensic-evidence-toolkit: imaging, $MFT and memory triage")
    p.add_argument("--version", action="version", version=f"fet {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("image", help="acquire a file/device to a raw image with hashes and a custody record")
    s.add_argument("source"); s.add_argument("dest")
    s.add_argument("--case", required=True, help="case identifier")
    s.add_argument("--examiner", required=True, help="examiner name")
    s.add_argument("--hash", default="md5,sha256", help="comma list: md5,sha1,sha256,sha512")
    s.add_argument("--block-size", type=int, default=imaging.DEFAULT_BLOCK)
    s.add_argument("--notes"); s.add_argument("--custody", help="custody JSON path")
    s.add_argument("--overwrite", action="store_true"); s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_image)

    s = sub.add_parser("verify", help="re-hash an image and compare with its custody record")
    s.add_argument("image"); s.add_argument("--custody")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("mft", help="parse an extracted $MFT (or read it from an NTFS volume image)")
    s.add_argument("input", help="extracted $MFT file, or an NTFS volume/disk image with --volume")
    s.add_argument("--volume", action="store_true", help="input is an NTFS image; locate and read $MFT from it")
    s.add_argument("--offset", type=int, default=0, help="byte offset of the NTFS partition inside the image")
    s.add_argument("--record-size", type=int, choices=(1024, 2048, 4096))
    s.add_argument("--format", choices=("csv", "json", "bodyfile"), default="csv")
    s.add_argument("--only-flagged", action="store_true", help="only entries with timestomp indicators")
    s.add_argument("--tolerance", type=float, default=1.0, help="timestomp tolerance in seconds (default 1)")
    s.add_argument("-o", "--output")
    s.set_defaults(func=cmd_mft)

    s = sub.add_parser("mem-triage", help="Volatility 3 triage of a Windows memory image")
    s.add_argument("--image"); s.add_argument("--from-dir", help="re-analyse saved plugin JSON instead of running Volatility")
    s.add_argument("--out-dir", help="where to save raw plugin JSON (default mem-triage-output)")
    s.add_argument("--vol-cmd", help='Volatility command, e.g. "python3 /opt/volatility3/vol.py"')
    s.add_argument("--timeout", type=int, default=3600); s.add_argument("--report", help="write Markdown (+ .json) report")
    s.set_defaults(func=cmd_mem)

    s = sub.add_parser("strings", help="extract ASCII/UTF-16 strings (optionally IOCs) from any file")
    s.add_argument("input"); s.add_argument("--min-len", type=int, default=6)
    s.add_argument("--iocs", action="store_true", help="extract URLs, e-mails, IPs, registry keys")
    s.add_argument("--all-ips", action="store_true", help="include private/loopback IPs")
    s.add_argument("-o", "--output")
    s.set_defaults(func=cmd_strings)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (imaging.ImagingError, mft.MftError, memory.MemoryError_, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
