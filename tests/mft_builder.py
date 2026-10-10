"""Builds synthetic but format-correct NTFS MFT records and volumes for tests.

Everything here is *original, hand-constructed test data*: no real evidence and
no third-party samples are bundled. It follows the on-disk layout documented
for NTFS (FILE record header, update sequence array, resident/non-resident
attribute headers, data runs, $FILE_NAME structure).
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence, Tuple

SECTOR = 512
EPOCH_DIFF = 116444736000000000


def ft(y, mo, d, h=0, mi=0, s=0, ticks=0) -> int:
    """FILETIME for a UTC wall-clock time plus extra 100 ns ticks (0..9_999_999)."""
    dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
    return int(dt.timestamp()) * 10_000_000 + EPOCH_DIFF + ticks


def _pad8(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % 8)


def attr_resident(atype: int, content: bytes, name: str = "") -> bytes:
    name_b = name.encode("utf-16le")
    name_off = 24
    content_off = 24 + len(name_b)
    content_off += (-content_off) % 8
    total = content_off + len(content)
    total += (-total) % 8
    head = struct.pack("<IIBBHHH", atype, total, 0, len(name), name_off if name else 0, 0, 0)
    head += struct.pack("<IHBB", len(content), content_off, 0, 0)
    body = head + name_b
    body = body + b"\x00" * (content_off - len(body)) + content
    return body + b"\x00" * (total - len(body))


def attr_nonresident(atype: int, runlist: bytes, real_size: int, alloc_size: int, name: str = "",
                     lowest_vcn: int = 0) -> bytes:
    name_b = name.encode("utf-16le")
    rl_off = 0x40 + len(name_b)
    rl_off += (-rl_off) % 8
    total = rl_off + len(runlist)
    total += (-total) % 8
    head = struct.pack("<IIBBHHH", atype, total, 1, len(name), 0x40 if name else 0, 0, 0)
    head += struct.pack("<QQHHIQQQ", lowest_vcn, lowest_vcn + max(0, alloc_size // 1024 - 1), rl_off, 0, 0, alloc_size, real_size, real_size)
    body = head + name_b
    body = body + b"\x00" * (rl_off - len(body)) + runlist
    return body + b"\x00" * (total - len(body))


def si_attr(created, modified, mft_modified, accessed) -> bytes:
    content = struct.pack("<QQQQI", created, modified, mft_modified, accessed, 0) + b"\x00" * 36
    return attr_resident(0x10, content)


def fn_attr(parent: int, parent_seq: int, name: str, times: Tuple[int, int, int, int],
            namespace: int = 1, real_size: int = 0) -> bytes:
    name_b = name.encode("utf-16le")
    content = struct.pack("<Q", parent | (parent_seq << 48))
    content += struct.pack("<QQQQQQII", *times, real_size, real_size, 0, 0)
    content += struct.pack("<BB", len(name), namespace) + name_b
    return attr_resident(0x30, content)


def encode_runlist(runs: Sequence[Tuple[int, int]]) -> bytes:
    out, prev = b"", 0
    for lcn, length in runs:
        len_b = length.to_bytes((length.bit_length() + 7) // 8 or 1, "little")
        delta = lcn - prev
        off_n = max(1, (delta.bit_length() + 8) // 8)
        off_b = delta.to_bytes(off_n, "little", signed=True)
        out += bytes([(off_n << 4) | len(len_b)]) + len_b + off_b
        prev = lcn
    return out + b"\x00"


def build_record(
    seq: int = 1,
    in_use: bool = True,
    directory: bool = False,
    attrs: Iterable[bytes] = (),
    record_size: int = 1024,
    base_ref: int = 0,
    corrupt_sector: Optional[int] = None,
) -> bytes:
    usa_count = record_size // SECTOR + 1
    usa_off = 0x30
    first_attr = usa_off + usa_count * 2
    first_attr += (-first_attr) % 8
    body = b"".join(attrs) + struct.pack("<I", 0xFFFFFFFF)
    body += b"\x00" * ((-len(body)) % 8)
    used = first_attr + len(body)
    if used > record_size:
        raise ValueError("record too large")
    flags = (1 if in_use else 0) | (2 if directory else 0)
    header = b"FILE" + struct.pack("<HH", usa_off, usa_count) + struct.pack("<Q", 0)
    header += struct.pack("<HHHHII", seq, 1, first_attr, flags, used, record_size)
    header += struct.pack("<QH", base_ref, 0) + b"\x00" * 6
    buf = bytearray(header.ljust(first_attr, b"\x00") + body)
    buf.extend(b"\x00" * (record_size - len(buf)))
    usn = b"\x01\x00"
    saved = []
    for i in range(1, usa_count):
        end = i * SECTOR - 2
        saved.append(bytes(buf[end : end + 2]))
        buf[end : end + 2] = usn
    buf[usa_off : usa_off + 2] = usn
    for i, s in enumerate(saved):
        buf[usa_off + 2 + 2 * i : usa_off + 4 + 2 * i] = s
    if corrupt_sector is not None:
        end = corrupt_sector * SECTOR - 2
        buf[end : end + 2] = b"\xde\xad"
    return bytes(buf)


def file_record(name: str, parent: int, parent_seq: int, created, modified=None, mft_mod=None,
                accessed=None, fn_times=None, size: int = 0, in_use: bool = True, directory: bool = False,
                seq: int = 1, ads: Sequence[str] = (), content: bytes = b"", extra_fn: Sequence[Tuple[str, int]] = ()) -> bytes:
    modified = modified if modified is not None else created
    mft_mod = mft_mod if mft_mod is not None else created
    accessed = accessed if accessed is not None else created
    times = fn_times or (created, modified, mft_mod, accessed)
    attrs = [si_attr(created, modified, mft_mod, accessed)]
    for nm, ns in extra_fn:
        attrs.append(fn_attr(parent, parent_seq, nm, times, ns, size))
    attrs.append(fn_attr(parent, parent_seq, name, times, 1, size))
    if not directory:
        attrs.append(attr_resident(0x80, content or b"x" * size) if size <= 64 else
                     attr_nonresident(0x80, encode_runlist([(100, 1)]), size, 1024))
    for a in ads:
        attrs.append(attr_resident(0x80, b"[ZoneTransfer]\r\nZoneId=3\r\n", name=a))
    return build_record(seq=seq, in_use=in_use, directory=directory, attrs=attrs)


def build_mft(records: dict, total: Optional[int] = None, record_size: int = 1024) -> bytes:
    """``records``: {record_number: bytes}. Missing numbers become zeroed slots."""
    total = total or (max(records) + 1)
    return b"".join(records.get(i, b"\x00" * record_size) for i in range(total))


def build_volume(records: dict, partition_offset: int = 0, mft_cluster: int = 4) -> bytes:
    """Wrap records in a minimal NTFS volume (boot sector + MFT described by record 0 runs)."""
    cluster, rec = 1024, 1024
    total = max(records) + 1
    mft_bytes_len = total * rec
    clusters = -(-mft_bytes_len // cluster)
    root_ts = ft(2020, 1, 1, 0, 0, 0, 1)
    rec0 = build_record(
        seq=1,
        attrs=[
            si_attr(root_ts, root_ts, root_ts, root_ts),
            fn_attr(5, 5, "$MFT", (root_ts,) * 4),
            attr_nonresident(0x80, encode_runlist([(mft_cluster, clusters)]), mft_bytes_len, clusters * cluster),
        ],
    )
    full = dict(records)
    full[0] = rec0
    mft = build_mft(full, total)
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 0x0B, 512, 2)           # bytes/sector, sectors/cluster
    struct.pack_into("<Q", boot, 0x30, mft_cluster)       # $MFT start cluster
    struct.pack_into("<b", boot, 0x40, -10)               # 2**10 = 1024-byte records
    boot[510:512] = b"\x55\xaa"
    volume = bytes(boot).ljust(mft_cluster * cluster, b"\x00") + mft
    return b"\x00" * partition_offset + volume
