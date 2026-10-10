#!/usr/bin/env python3
"""Compare fet's reconstructed paths with a Sleuth Kit `fls -r -m`-style listing.

    python tools/validate_paths_fls.py MFT_FILE FLS_LISTING

Reference data used for the published check: the NIST Hacking Case $MFT and
its fls listing, both shipped in the dfir_ntfs test data. Only the PATH and
the SIZE columns are compared. Deleted entries are listed by fls with a '*'
marker and are compared too.
"""
from __future__ import annotations

import collections
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from fet import mft  # noqa: E402

LINE = re.compile(r"^(?P<type>\S+)\s+(?P<deleted>\*\s*)?(?P<inode>\d+)(?:-\d+-\d+)?:\t(?P<path>[^\t]*)\t(?P<t1>[^\t]*)\t(?P<t2>[^\t]*)\t(?P<t3>[^\t]*)\t(?P<t4>[^\t]*)\t(?P<size>\d+)")


def main(mft_path: str, fls_path: str) -> None:
    with open(mft_path, "rb") as fh:
        entries = mft.analyze(mft.iter_mft_file(fh))
    by_rec = {e.record_number: e for e in entries}

    ref = collections.defaultdict(list)
    skipped = 0
    with open(fls_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LINE.match(line.rstrip("\n"))
            if not m:
                skipped += 1
                continue
            ref[int(m["inode"])].append((m["path"], int(m["size"]), bool(m["deleted"]), m["type"]))

    n_lines = sum(len(v) for v in ref.values())
    missing = path_diff = size_diff = ok = 0
    examples = []
    for rec, rows in ref.items():
        e = by_rec.get(rec)
        if e is None:
            missing += 1
            continue
        mine = e.path.lstrip("/")
        paths = {p for p, *_ in rows if ":" not in p.rsplit("/", 1)[-1]}  # ignore ADS-style rows
        if mine in paths:
            ok += 1
        elif not paths:
            continue
        else:
            path_diff += 1
            if len(examples) < 10:
                examples.append((rec, mine, sorted(paths)[:2]))
        sizes = {s for p, s, *_ in rows if p in paths}
        if e.data_size is not None and sizes and e.data_size not in sizes and not e.is_directory:
            size_diff += 1
    print(f"fls lines parsed: {n_lines} (unparsed lines: {skipped}); distinct records: {len(ref)}")
    print(f"records missing from fet output: {missing}")
    print(f"path matches: {ok}   path differences: {path_diff}   size differences (files): {size_diff}")
    for ex in examples:
        print("  diff example:", ex)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
