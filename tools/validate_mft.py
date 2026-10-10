#!/usr/bin/env python3
"""Cross-check fet's $MFT parser against an independent parser (dfir_ntfs).

    python tools/validate_mft.py --dfir-ntfs /path/to/dfir_ntfs_checkout MFT_FILE [...]

dfir_ntfs (https://github.com/msuhanov/dfir_ntfs, GPLv3) is NOT a dependency of
fet; it is only imported here, from a checkout you point at. For every record
both parsers can read, the script compares: in-use flag, directory flag,
sequence number, base-record reference, $STANDARD_INFORMATION timestamps,
the set of $FILE_NAME (parent, name, namespace) tuples and the size of the
unnamed $DATA stream. Differences are listed, not hidden.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from fet import mft  # noqa: E402


def ft(ticks):
    try:
        return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ticks / 10)
    except OverflowError:
        return None


def independent(path, dfir_root, record_size):
    sys.path.insert(0, dfir_root)
    from dfir_ntfs import Attributes as A
    from dfir_ntfs import MFT as M

    out = {}
    with open(path, "rb") as fh:
        n = 0
        while True:
            raw = fh.read(record_size)
            if len(raw) < record_size:
                break
            try:
                frs = M.FileRecordSegment(raw, True, n)
                rec = {
                    "in_use": frs.is_in_use(),
                    "dir": bool(frs.get_flags() & 0x02),
                    "seq": frs.get_sequence_number(),
                    "base": frs.get_base_file_record_segment() & 0xFFFFFFFFFFFF,
                    "si": None, "fn": set(), "data": None,
                }
                for a in frs.attributes():
                    if a.type_code == A.ATTR_TYPE_STANDARD_INFORMATION and hasattr(a, "value"):
                        si = A.StandardInformation(a.value)
                        rec["si"] = (si.get_ctime(), si.get_mtime(), si.get_etime(), si.get_atime())
                    elif a.type_code == A.ATTR_TYPE_FILE_NAME and hasattr(a, "value"):
                        f = A.FileName(a.value)
                        rec["fn"].add((f.get_parent_directory() & 0xFFFFFFFFFFFF, f.get_file_name(), f.get_flags()))
                    elif a.type_code == A.ATTR_TYPE_DATA and not a.name:
                        rec["data"] = len(a.value) if hasattr(a, "value") else a.file_size
                out[n] = rec
            except Exception:
                out[n] = None  # dfir_ntfs rejected the record
            n += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dfir-ntfs", required=True)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--show", type=int, default=8, help="max example differences per field")
    args = ap.parse_args()

    for path in args.files:
        with open(path, "rb") as fh:
            first = fh.read(4096)
        rs = mft.detect_record_size(first)
        with open(path, "rb") as fh:
            mine = {e.record_number: e for e in mft.iter_mft_file(fh)}
        theirs = independent(path, args.dfir_ntfs, rs)
        both = [n for n in mine if theirs.get(n)]
        only_mine = [n for n in mine if n in theirs and theirs[n] is None]
        only_theirs = [n for n, r in theirs.items() if r and n not in mine]
        diffs = collections.defaultdict(list)
        for n in both:
            m, t = mine[n], theirs[n]
            if m.in_use != t["in_use"]:
                diffs["in_use"].append((n, m.in_use, t["in_use"]))
            if m.is_directory != t["dir"]:
                diffs["directory"].append((n, m.is_directory, t["dir"]))
            if m.sequence != t["seq"]:
                diffs["sequence"].append((n, m.sequence, t["seq"]))
            if (m.base_record or 0) != t["base"]:
                diffs["base_record"].append((n, m.base_record, t["base"]))
            if t["si"] and m.si:
                mt = (ft(m.si.created), ft(m.si.modified), ft(m.si.mft_modified), ft(m.si.accessed))
                if mt != t["si"]:
                    diffs["si_times"].append((n, mt, t["si"]))
            elif bool(t["si"]) != bool(m.si):
                diffs["si_presence"].append((n, bool(m.si), bool(t["si"])))
            mf = {(f.parent_record, f.name, f.namespace) for f in m.fn}
            if t["base"] == 0 and mf != t["fn"] and not m.has_attribute_list:
                diffs["file_names"].append((n, sorted(mf)[:2], sorted(t["fn"])[:2]))
            if t["base"] == 0 and not m.has_attribute_list and (m.data_size or None) != (t["data"] or None):
                diffs["data_size"].append((n, m.data_size, t["data"]))
        print(f"\n== {os.path.basename(path)}  (record size {rs}, {os.path.getsize(path)} bytes)")
        print(f"   records parsed by fet: {len(mine)} | by dfir_ntfs: {sum(1 for r in theirs.values() if r)} | compared: {len(both)}")
        print(f"   parsed only by fet: {len(only_mine)}  only by dfir_ntfs: {len(only_theirs)}")
        for field in ("in_use", "directory", "sequence", "base_record", "si_presence", "si_times", "file_names", "data_size"):
            d = diffs.get(field, [])
            print(f"   {field:<12} differences: {len(d)}")
            for ex in d[: args.show]:
                print("      ", ex)
        if only_mine[:5] or only_theirs[:5]:
            print("   examples only-fet:", only_mine[:5], " only-dfir:", only_theirs[:5])


if __name__ == "__main__":
    main()
