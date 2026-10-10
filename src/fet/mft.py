"""NTFS ``$MFT`` parser with timeline export and timestomp indicators.

Scope (honest summary)
----------------------
Parsed: ``FILE`` record header, update-sequence (fixup) verification and
repair, ``$STANDARD_INFORMATION`` (0x10), ``$FILE_NAME`` (0x30, all
namespaces), ``$DATA`` (0x80, resident / non-resident size, alternate data
stream names), in-use / directory flags, parent references and full path
reconstruction.

Not parsed (reported as a per-record warning where it matters):
``$ATTRIBUTE_LIST`` / extension records (very fragmented files may be
incomplete), ``$LOGFILE`` / ``$UsnJrnl``, compressed or encrypted content.
Resident file *content* is not extracted.

All times are UTC. Raw 100 ns FILETIME ticks are kept so sub-second precision
(needed for timestomp heuristics) is never lost.
"""

from __future__ import annotations

import csv
import io
import json
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import BinaryIO, Dict, Iterable, Iterator, List, Optional, Tuple

SECTOR = 512
FILETIME_EPOCH_DIFF = 116444736000000000  # 100ns ticks between 1601-01-01 and 1970-01-01
TICKS_PER_SECOND = 10_000_000
ATTR_SI, ATTR_ATTRLIST, ATTR_FN, ATTR_DATA, ATTR_END = 0x10, 0x20, 0x30, 0x80, 0xFFFFFFFF
ROOT_RECORD = 5

FLAG_IN_USE = 0x0001
FLAG_DIRECTORY = 0x0002

NS_POSIX, NS_WIN32, NS_DOS, NS_WIN32_DOS = 0, 1, 2, 3


class MftError(Exception):
    pass


# ----------------------------------------------------------------- timestamps
def filetime_to_iso(ticks: Optional[int]) -> str:
    """FILETIME -> ``YYYY-MM-DD HH:MM:SS.fffffff`` (UTC), '' for 0/None."""
    if not ticks:
        return ""
    try:
        base = datetime(1601, 1, 1) + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return "invalid"
    return f"{base:%Y-%m-%d %H:%M:%S}.{ticks % TICKS_PER_SECOND:07d}"


def filetime_to_epoch(ticks: Optional[int]) -> int:
    if not ticks:
        return 0
    return (ticks - FILETIME_EPOCH_DIFF) // TICKS_PER_SECOND


# --------------------------------------------------------------------- models
@dataclass(slots=True)
class SiTimes:
    created: int
    modified: int
    mft_modified: int
    accessed: int
    flags: int = 0


@dataclass(slots=True)
class FnAttr:
    parent_record: int
    parent_sequence: int
    created: int
    modified: int
    mft_modified: int
    accessed: int
    allocated_size: int
    real_size: int
    flags: int
    namespace: int
    name: str


@dataclass(slots=True)
class MftEntry:
    record_number: int
    sequence: int
    in_use: bool
    is_directory: bool
    base_record: int = 0
    si: Optional[SiTimes] = None
    fn: List[FnAttr] = field(default_factory=list)
    data_size: Optional[int] = None
    data_resident: Optional[bool] = None
    ads: List[str] = field(default_factory=list)
    has_attribute_list: bool = False
    extension_records: int = 0          # extension records merged into this entry
    warnings: List[str] = field(default_factory=list)
    path: str = ""
    path_uncertain: bool = False
    indicators: List[Dict[str, str]] = field(default_factory=list)

    @property
    def best_fn(self) -> Optional[FnAttr]:
        """Preferred name: Win32 / Win32+DOS, then POSIX, then DOS."""
        for ns_set in ((NS_WIN32, NS_WIN32_DOS), (NS_POSIX,), (NS_DOS,)):
            for f in self.fn:
                if f.namespace in ns_set:
                    return f
        return None

    @property
    def name(self) -> str:
        f = self.best_fn
        return f.name if f else ""

    @property
    def parent_record(self) -> Optional[int]:
        f = self.best_fn
        return f.parent_record if f else None


# -------------------------------------------------------------------- parsing
def _apply_fixups(buf: bytearray, warnings: List[str]) -> None:
    usa_off, usa_cnt = struct.unpack_from("<HH", buf, 4)
    if usa_cnt < 2 or usa_off + usa_cnt * 2 > len(buf):
        warnings.append("invalid update sequence array")
        return
    usn = bytes(buf[usa_off : usa_off + 2])
    for i in range(1, usa_cnt):
        end = i * SECTOR - 2
        if end + 2 > len(buf):
            warnings.append("update sequence array larger than record")
            break
        if bytes(buf[end : end + 2]) != usn:
            warnings.append(f"fixup mismatch in sector {i} (torn write or corruption)")
            continue
        orig = buf[usa_off + 2 * i : usa_off + 2 * i + 2]
        buf[end : end + 2] = orig


def parse_record(raw: bytes, record_number: int) -> Optional[MftEntry]:
    """Parse one MFT record. Returns ``None`` for unused/zeroed/non-FILE slots."""
    if len(raw) < 48 or raw[:4] != b"FILE":
        return None
    buf = bytearray(raw)
    warnings: List[str] = []
    _apply_fixups(buf, warnings)

    sequence, _links, first_attr, flags, used_size, _alloc = struct.unpack_from("<HHHHII", buf, 0x10)
    (base_ref,) = struct.unpack_from("<Q", buf, 0x20)
    entry = MftEntry(
        record_number=record_number,
        sequence=sequence,
        in_use=bool(flags & FLAG_IN_USE),
        is_directory=bool(flags & FLAG_DIRECTORY),
        base_record=base_ref & 0x0000FFFFFFFFFFFF,
        warnings=warnings,
    )
    limit = min(used_size, len(buf)) if used_size else len(buf)
    off = first_attr
    guard = 0
    while off + 8 <= limit and guard < 256:
        guard += 1
        atype, alen = struct.unpack_from("<II", buf, off)
        if atype == ATTR_END:
            break
        if alen < 16 or off + alen > len(buf):
            warnings.append(f"bad attribute length at offset {off}")
            break
        non_resident = buf[off + 8]
        name_len = buf[off + 9]
        (name_off,) = struct.unpack_from("<H", buf, off + 10)
        attr_name = ""
        if name_len:
            raw_name = bytes(buf[off + name_off : off + name_off + name_len * 2])
            attr_name = raw_name.decode("utf-16le", errors="replace")

        if atype == ATTR_ATTRLIST:
            entry.has_attribute_list = True
        elif not non_resident:
            content_size, content_off = struct.unpack_from("<IH", buf, off + 0x10)
            content = bytes(buf[off + content_off : off + content_off + content_size])
            if atype == ATTR_SI and len(content) >= 32:
                c, m, mm, a = struct.unpack_from("<QQQQ", content, 0)
                flags_si = struct.unpack_from("<I", content, 32)[0] if len(content) >= 36 else 0
                entry.si = SiTimes(c, m, mm, a, flags_si)
            elif atype == ATTR_FN and len(content) >= 66:
                entry.fn.append(_parse_fn(content, warnings))
            elif atype == ATTR_DATA:
                if attr_name:
                    entry.ads.append(attr_name)
                else:
                    entry.data_size, entry.data_resident = content_size, True
        else:
            if atype == ATTR_DATA:
                (lowest_vcn,) = struct.unpack_from("<Q", buf, off + 0x10)
                (real_size,) = struct.unpack_from("<Q", buf, off + 0x30)
                if attr_name:
                    entry.ads.append(attr_name)
                elif lowest_vcn == 0:
                    # Only the first extent (starting VCN 0) carries the real
                    # size; later extents of a fragmented stream hold zeros.
                    entry.data_size, entry.data_resident = real_size, False
        off += alen

    if entry.has_attribute_list:
        entry.warnings.append("has $ATTRIBUTE_LIST: attributes in extension records are not merged")
    if entry.base_record:
        entry.warnings.append(f"extension record of base record {entry.base_record}")
    return entry


def _parse_fn(content: bytes, warnings: List[str]) -> FnAttr:
    (parent,) = struct.unpack_from("<Q", content, 0)
    c, m, mm, a, alloc, real, fflags, _reparse = struct.unpack_from("<QQQQQQII", content, 8)
    name_len, ns = content[64], content[65]
    name_bytes = content[66 : 66 + name_len * 2]
    if len(name_bytes) != name_len * 2:
        warnings.append("truncated $FILE_NAME")
    return FnAttr(
        parent_record=parent & 0x0000FFFFFFFFFFFF,
        parent_sequence=parent >> 48,
        created=c,
        modified=m,
        mft_modified=mm,
        accessed=a,
        allocated_size=alloc,
        real_size=real,
        flags=fflags,
        namespace=ns,
        name=name_bytes.decode("utf-16le", errors="replace"),
    )


# ------------------------------------------------------------------ iteration
def detect_record_size(first: bytes) -> int:
    """Record size from the allocated-size field of record 0 (default 1024)."""
    if len(first) >= 0x20 and first[:4] == b"FILE":
        (alloc,) = struct.unpack_from("<I", first, 0x1C)
        if alloc in (1024, 2048, 4096):
            return alloc
    return 1024


def iter_mft_file(f: BinaryIO, record_size: Optional[int] = None) -> Iterator[MftEntry]:
    """Yield entries from an extracted ``$MFT`` file object."""
    start = f.tell()
    head = f.read(4096)
    f.seek(start)
    rs = record_size or detect_record_size(head)
    n = 0
    while True:
        raw = f.read(rs)
        if len(raw) < rs:
            break
        entry = parse_record(raw, n)
        n += 1
        if entry is not None:
            yield entry


def _read_ntfs_geometry(f: BinaryIO, offset: int) -> Tuple[int, int, int]:
    """Return (cluster_size, mft_byte_offset, record_size) from the NTFS boot sector."""
    f.seek(offset)
    boot = f.read(512)
    if len(boot) < 512 or boot[3:11] != b"NTFS    ":
        raise MftError(
            f"no NTFS boot sector at byte offset {offset}; for a whole-disk image pass "
            "--offset <partition start in bytes> (e.g. start sector * 512)"
        )
    bps, spc = struct.unpack_from("<HB", boot, 0x0B)
    (mft_cluster,) = struct.unpack_from("<Q", boot, 0x30)
    (cpr,) = struct.unpack_from("<b", boot, 0x40)
    if bps == 0 or spc == 0:
        raise MftError("corrupt NTFS boot sector (zero sector or cluster size)")
    cluster = bps * spc
    record_size = cpr * cluster if cpr > 0 else 1 << (-cpr)
    return cluster, offset + mft_cluster * cluster, record_size


def parse_runlist(data: bytes) -> List[Tuple[Optional[int], int]]:
    """Decode an NTFS data-run list into ``[(lcn or None for sparse, length_in_clusters)]``."""
    runs: List[Tuple[Optional[int], int]] = []
    pos, lcn = 0, 0
    while pos < len(data) and data[pos] != 0:
        header = data[pos]
        len_size, off_size = header & 0x0F, header >> 4
        pos += 1
        if len_size == 0 or pos + len_size + off_size > len(data):
            raise MftError("corrupt data run list")
        length = int.from_bytes(data[pos : pos + len_size], "little")
        pos += len_size
        if off_size == 0:
            runs.append((None, length))
        else:
            delta = int.from_bytes(data[pos : pos + off_size], "little", signed=True)
            lcn += delta
            runs.append((lcn, length))
        pos += off_size
    return runs


def _record0_runs(raw0: bytes) -> Tuple[List[Tuple[Optional[int], int]], int]:
    buf = bytearray(raw0)
    _apply_fixups(buf, [])
    (first_attr,) = struct.unpack_from("<H", buf, 0x14)
    off = first_attr
    while off + 8 <= len(buf):
        atype, alen = struct.unpack_from("<II", buf, off)
        if atype == ATTR_END or alen < 16:
            break
        if atype == ATTR_DATA and buf[off + 8] == 1 and buf[off + 9] == 0:
            (rl_off,) = struct.unpack_from("<H", buf, off + 0x20)
            (real,) = struct.unpack_from("<Q", buf, off + 0x30)
            return parse_runlist(bytes(buf[off + rl_off : off + alen])), real
        off += alen
    raise MftError("record 0 ($MFT) has no non-resident unnamed $DATA attribute")


def iter_mft_volume(f: BinaryIO, offset: int = 0) -> Iterator[MftEntry]:
    """Yield entries by reading the ``$MFT`` straight out of an NTFS volume image."""
    cluster, mft_off, rs = _read_ntfs_geometry(f, offset)
    f.seek(mft_off)
    raw0 = f.read(rs)
    if raw0[:4] != b"FILE":
        raise MftError("MFT record 0 not found at the location given by the boot sector")
    runs, real_size = _record0_runs(raw0)
    remaining = real_size
    n = 0
    carry = b""
    for lcn, length in runs:
        if remaining <= 0:
            break
        run_bytes = min(length * cluster, remaining)
        if lcn is None:
            data = b"\x00" * run_bytes
        else:
            f.seek(offset + lcn * cluster)
            data = f.read(run_bytes)
        remaining -= run_bytes
        data = carry + data
        usable = len(data) - (len(data) % rs)
        for i in range(0, usable, rs):
            entry = parse_record(data[i : i + rs], n)
            n += 1
            if entry is not None:
                yield entry
        carry = data[usable:]


# --------------------------------------------------------------------- paths
def merge_extensions(entries: Iterable[MftEntry]) -> List[MftEntry]:
    """Fold extension records into their base records.

    A file with many attributes (or many hard links) keeps some of them in
    *extension records* that point back to the base record; the base record
    only has an ``$ATTRIBUTE_LIST``. Without merging, a long Win32 name that
    lives in an extension record is missed and the path falls back to the
    8.3 name. Merged extension records are removed from the returned list.
    An extension record whose base record is not present is kept as-is.
    """
    items = list(entries)
    by_num = {e.record_number: e for e in items}
    merged: set = set()
    for ext in items:
        if not ext.base_record:
            continue
        base = by_num.get(ext.base_record)
        if base is None or base.base_record or base is ext:
            continue
        known = {(f.parent_record, f.name, f.namespace) for f in base.fn}
        for f in ext.fn:
            if (f.parent_record, f.name, f.namespace) not in known:
                base.fn.append(f)
        if base.si is None and ext.si is not None:
            base.si = ext.si
        if base.data_size is None and ext.data_size is not None:
            base.data_size, base.data_resident = ext.data_size, ext.data_resident
        base.ads.extend(a for a in ext.ads if a not in base.ads)
        base.extension_records += 1
        merged.add(ext.record_number)
    for e in items:
        if e.extension_records:
            msg = "has $ATTRIBUTE_LIST: attributes in extension records are not merged"
            e.warnings = [w for w in e.warnings if w != msg]
            e.warnings.append(f"merged {e.extension_records} extension record(s) via $ATTRIBUTE_LIST")
    return [e for e in items if e.record_number not in merged]


def build_paths(entries: Iterable[MftEntry]) -> List[MftEntry]:
    """Fill ``path`` / ``path_uncertain`` for every entry (returns the list)."""
    items = list(entries)
    by_num = {e.record_number: e for e in items}
    cache: Dict[int, Tuple[str, bool]] = {ROOT_RECORD: ("", False)}

    def resolve(num: int, depth: int = 0) -> Tuple[str, bool]:
        if num in cache:
            return cache[num]
        e = by_num.get(num)
        if e is None or depth > 128 or not e.name:
            return ("<orphan>", True)
        cache[num] = ("<cycle>", True)  # cycle guard
        pnum = e.parent_record
        if pnum is None:
            result = ("<orphan>/" + e.name, True)
        elif pnum == num:
            result = ("<orphan>/" + e.name, True)
        else:
            ppath, uncertain = resolve(pnum, depth + 1)
            parent = by_num.get(pnum)
            fn = e.best_fn
            if parent is not None and fn is not None and parent.sequence != fn.parent_sequence:
                uncertain = True  # parent slot was re-used after this entry was written
            result = (f"{ppath}/{e.name}", uncertain)
        cache[num] = result
        return result

    for e in items:
        if e.record_number == ROOT_RECORD:
            e.path, e.path_uncertain = "/", False
            continue
        p, u = resolve(e.record_number)
        e.path = p if p.startswith("/") or p.startswith("<") else "/" + p
        e.path_uncertain = u
    return items


# ----------------------------------------------------------- timestomp checks
def detect_timestomp(entry: MftEntry, tolerance_seconds: float = 1.0) -> List[Dict[str, str]]:
    """Heuristic indicators of timestamp manipulation. **Indicators, not proof.**

    Measured on two real, unmanipulated Windows XP-era $MFT files (see
    docs/VALIDATION.md), TS-001 + TS-002 flagged 2.0 % and 39.5 % of ordinary
    files, almost all of them installer- or CAB-extracted files that keep
    their original timestamps. All three are therefore ``low`` severity and
    only useful for ranking or when combined with other evidence (file
    location, creation time vs. the incident window, USN journal).

    TS-001  $SI created is earlier than $FN created (beyond ``tolerance``).
            ``$FN`` times cannot be set through the normal Win32 time APIs,
            so a file whose ``$SI`` says it is older than its ``$FN`` was
            probably back-dated. Benign causes: some archive extraction and
            cross-volume moves.
    TS-002  $SI created *and* modified have zero sub-second precision while
            $FN created does not. Windows timestamps are normally not on an
            exact second, but simple timestomp tools write whole seconds.
            Coarse clock ticks (and FAT/ZIP-derived times) can also land on
            a whole second, so on its own this is a weak indicator; it is
            only evaluated when $SI and $FN disagree.
    TS-003  $SI MFT-change time is earlier than $SI modified time. Setting
            times through the API stamps "MFT changed" with the current
            time, so an MFT-change time *older* than the modified time is
            unusual. Benign cause: a user-set future modified time.
    """
    out: List[Dict[str, str]] = []
    si, fn = entry.si, entry.best_fn
    if si is None or fn is None or not si.created or not fn.created:
        return out
    tol = int(tolerance_seconds * TICKS_PER_SECOND)
    if fn.created - si.created > tol:
        out.append(
            {
                "id": "TS-001",
                "severity": "low",
                "description": "$STANDARD_INFORMATION created ("
                + filetime_to_iso(si.created)
                + ") is earlier than $FILE_NAME created ("
                + filetime_to_iso(fn.created)
                + ")",
            }
        )
    if (
        si.created % TICKS_PER_SECOND == 0
        and si.modified % TICKS_PER_SECOND == 0
        and fn.created % TICKS_PER_SECOND != 0
    ):
        out.append(
            {
                "id": "TS-002",
                "severity": "low",
                "description": "$STANDARD_INFORMATION created/modified have zero sub-second precision "
                "but $FILE_NAME created does",
            }
        )
    if si.mft_modified and si.modified and si.mft_modified < si.modified - tol:
        out.append(
            {
                "id": "TS-003",
                "severity": "low",
                "description": "$STANDARD_INFORMATION MFT-change time is earlier than its modified time",
            }
        )
    return out


def analyze(entries: Iterable[MftEntry], tolerance_seconds: float = 1.0) -> List[MftEntry]:
    items = build_paths(merge_extensions(entries))
    for e in items:
        e.indicators = detect_timestomp(e, tolerance_seconds)
    return items


# -------------------------------------------------------------------- exports
CSV_FIELDS = [
    "record", "sequence", "in_use", "is_directory", "path", "path_uncertain", "size",
    "si_created", "si_modified", "si_mft_modified", "si_accessed",
    "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
    "ads", "indicators", "warnings",
]


def _row(e: MftEntry) -> Dict[str, str]:
    si, fn = e.si, e.best_fn
    return {
        "record": e.record_number,
        "sequence": e.sequence,
        "in_use": int(e.in_use),
        "is_directory": int(e.is_directory),
        "path": e.path,
        "path_uncertain": int(e.path_uncertain),
        "size": "" if e.data_size is None else e.data_size,
        "si_created": filetime_to_iso(si.created) if si else "",
        "si_modified": filetime_to_iso(si.modified) if si else "",
        "si_mft_modified": filetime_to_iso(si.mft_modified) if si else "",
        "si_accessed": filetime_to_iso(si.accessed) if si else "",
        "fn_created": filetime_to_iso(fn.created) if fn else "",
        "fn_modified": filetime_to_iso(fn.modified) if fn else "",
        "fn_mft_modified": filetime_to_iso(fn.mft_modified) if fn else "",
        "fn_accessed": filetime_to_iso(fn.accessed) if fn else "",
        "ads": ";".join(e.ads),
        "indicators": ";".join(i["id"] for i in e.indicators),
        "warnings": ";".join(e.warnings),
    }


def to_csv(entries: Iterable[MftEntry]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    for e in entries:
        w.writerow(_row(e))
    return buf.getvalue()


def to_bodyfile(entries: Iterable[MftEntry]) -> str:
    """Sleuth Kit 3.x bodyfile (feed to ``mactime``). Uses $STANDARD_INFORMATION times."""
    lines = []
    for e in entries:
        if e.si is None:
            continue
        name = e.path + (" (deleted)" if not e.in_use else "")
        mode = "d/drwxrwxrwx" if e.is_directory else "r/rrwxrwxrwx"
        size = e.data_size if e.data_size is not None else 0
        lines.append(
            "|".join(
                [
                    "0",
                    name.replace("|", "%7C"),
                    f"{e.record_number}-128-{e.sequence}",
                    mode,
                    "0",
                    "0",
                    str(size),
                    str(filetime_to_epoch(e.si.accessed)),
                    str(filetime_to_epoch(e.si.modified)),
                    str(filetime_to_epoch(e.si.mft_modified)),
                    str(filetime_to_epoch(e.si.created)),
                ]
            )
        )
    return "\n".join(lines) + ("\n" if lines else "")


def to_json(entries: Iterable[MftEntry]) -> str:
    rows = []
    for e in entries:
        r = _row(e)
        r["indicators"] = e.indicators
        r["warnings"] = e.warnings
        r["ads"] = e.ads
        rows.append(r)
    return json.dumps(rows, indent=2)


def summarize(entries: List[MftEntry]) -> Dict[str, int]:
    return {
        "records": len(entries),
        "in_use": sum(1 for e in entries if e.in_use),
        "deleted": sum(1 for e in entries if not e.in_use),
        "directories": sum(1 for e in entries if e.is_directory),
        "with_ads": sum(1 for e in entries if e.ads),
        "timestomp_indicators": sum(len(e.indicators) for e in entries),
        "records_with_warnings": sum(1 for e in entries if e.warnings),
    }
