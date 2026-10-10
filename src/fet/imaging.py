"""Forensic acquisition of a file or block device into a raw (dd-style) image.

What it does
------------
* reads the source **read-only** in fixed-size blocks,
* hashes the data *as it is read* (MD5 / SHA-1 / SHA-256 / SHA-512 selectable),
* on a read error retries sector by sector, zero-fills the unreadable
  sectors and records every bad range (so the image keeps its geometry),
* re-reads the finished image and compares its hashes with the acquisition
  hashes (verification),
* writes a JSON chain-of-custody record next to the image.

What it deliberately does NOT do
--------------------------------
It is **not a write blocker**. Opening a device read-only in user space does
not stop the operating system from mounting or touching it. For physical
evidence use a hardware write blocker or a read-only forensic boot
environment. This tool documents *what was read and what hash it had*; it
does not protect the source.

If a device had unreadable sectors the image hash covers the zero-filled
data, and the custody record says so explicitly (``bad_ranges``).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable, Dict, Iterable, List, Optional, Tuple

from . import __version__

SECTOR = 512
DEFAULT_BLOCK = 1024 * 1024
SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


class ImagingError(Exception):
    """Raised for conditions that make a trustworthy acquisition impossible."""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hashers(algorithms: Iterable[str]) -> Dict[str, "hashlib._Hash"]:
    out = {}
    for name in algorithms:
        name = name.lower()
        if name not in SUPPORTED_ALGORITHMS:
            raise ImagingError(
                f"unsupported hash '{name}' (choose from {', '.join(SUPPORTED_ALGORITHMS)})"
            )
        out[name] = hashlib.new(name)
    if not out:
        raise ImagingError("at least one hash algorithm is required")
    return out


def _stream_size(f: BinaryIO) -> int:
    """Size of a regular file or block device (seek-to-end works for both)."""
    pos = f.tell()
    try:
        return f.seek(0, os.SEEK_END)
    finally:
        f.seek(pos)


def copy_stream(
    src: BinaryIO,
    dst: BinaryIO,
    size: int,
    hashers: Dict[str, "hashlib._Hash"],
    block_size: int = DEFAULT_BLOCK,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Tuple[int, List[Dict[str, int]]]:
    """Copy ``size`` bytes from ``src`` to ``dst``, hashing what is written.

    Returns ``(bytes_written, bad_ranges)``. A bad range is
    ``{"offset": int, "length": int}`` and covers sectors that could not be
    read and were replaced by zeros.
    """
    offset = 0
    bad: List[Dict[str, int]] = []

    def emit(data: bytes) -> None:
        dst.write(data)
        for h in hashers.values():
            h.update(data)

    def add_bad(off: int, length: int) -> None:
        if bad and bad[-1]["offset"] + bad[-1]["length"] == off:
            bad[-1]["length"] += length
        else:
            bad.append({"offset": off, "length": length})

    while offset < size:
        want = min(block_size, size - offset)
        try:
            src.seek(offset)
            data = src.read(want)
        except OSError:
            data = None

        if data is None:
            # Fall back to sector-granular reads so one bad sector does not
            # cost a whole block.
            chunks = []
            pos = offset
            end = offset + want
            while pos < end:
                step = min(SECTOR, end - pos)
                try:
                    src.seek(pos)
                    piece = src.read(step)
                except OSError:
                    piece = None
                if piece is None or len(piece) != step:
                    piece = b"\x00" * step
                    add_bad(pos, step)
                chunks.append(piece)
                pos += step
            data = b"".join(chunks)
        elif len(data) == 0:
            # Source shrank or reported a wrong size: refuse to pad silently.
            raise ImagingError(
                f"unexpected end of source at offset {offset} (expected {size} bytes)"
            )

        emit(data)
        offset += len(data)
        if progress:
            progress(offset, size)

    return offset, bad


def _hash_file(path: Path, algorithms: Iterable[str], block_size: int = DEFAULT_BLOCK) -> Dict[str, str]:
    hs = _hashers(algorithms)
    with open(path, "rb") as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            for h in hs.values():
                h.update(block)
    return {k: v.hexdigest() for k, v in hs.items()}


def acquire(
    source: str,
    dest: str,
    *,
    case_id: str,
    examiner: str,
    algorithms: Iterable[str] = ("md5", "sha256"),
    block_size: int = DEFAULT_BLOCK,
    notes: str = "",
    overwrite: bool = False,
    custody_path: Optional[str] = None,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Dict:
    """Acquire ``source`` into the raw image ``dest`` and return the custody record."""
    if not case_id or not examiner:
        raise ImagingError("case_id and examiner are required for a custody record")
    src_path = Path(source)
    dst_path = Path(dest)
    if not src_path.exists():
        raise ImagingError(f"source does not exist: {source}")
    if dst_path.exists() and src_path.exists() and os.path.samefile(src_path, dst_path):
        raise ImagingError("source and destination are the same file")
    if dst_path.exists() and not overwrite:
        raise ImagingError(f"destination exists (use --overwrite to replace): {dest}")

    algos = tuple(a.lower() for a in algorithms)
    hashers = _hashers(algos)
    started = utcnow()

    mode = "wb" if overwrite else "xb"
    with open(src_path, "rb", buffering=0) as src, open(dst_path, mode) as dst:
        size = _stream_size(src)
        written, bad = copy_stream(src, dst, size, hashers, block_size, progress)
        dst.flush()
        os.fsync(dst.fileno())

    acquisition_hashes = {k: v.hexdigest() for k, v in hashers.items()}
    image_hashes = _hash_file(dst_path, algos, block_size)
    verified = acquisition_hashes == image_hashes

    record = {
        "tool": {"name": "forensic-evidence-toolkit", "version": __version__, "module": "imaging"},
        "case_id": case_id,
        "examiner": examiner,
        "notes": notes,
        "started_utc": started,
        "finished_utc": utcnow(),
        "host": {"node": socket.gethostname(), "platform": platform.platform(), "python": platform.python_version()},
        "source": {
            "path": str(src_path),
            "size_bytes": size,
            "is_block_device": _is_block_device(src_path),
        },
        "image": {"path": str(dst_path), "size_bytes": dst_path.stat().st_size, "format": "raw"},
        "block_size": block_size,
        "bytes_acquired": written,
        "bad_ranges": bad,
        "bad_bytes": sum(r["length"] for r in bad),
        "acquisition_hashes": acquisition_hashes,
        "image_hashes": image_hashes,
        "verified": verified,
        "write_protection": "none-enforced-by-tool (use a hardware write blocker for physical media)",
    }
    out = Path(custody_path) if custody_path else Path(str(dst_path) + ".custody.json")
    out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    record["custody_file"] = str(out)
    if not verified:
        raise ImagingError(
            "verification FAILED: image hashes differ from acquisition hashes "
            f"(see {out}); do not rely on this image"
        )
    return record


def _is_block_device(p: Path) -> bool:
    import stat

    try:
        return stat.S_ISBLK(p.stat().st_mode)
    except OSError:
        return False


def verify(image: str, custody_file: Optional[str] = None, expected: Optional[Dict[str, str]] = None) -> Dict:
    """Re-hash ``image`` and compare with a custody file or explicit hashes.

    Returns ``{"ok": bool, "computed": {...}, "expected": {...}, "mismatches": [...]}``.
    """
    if expected is None:
        cf = Path(custody_file) if custody_file else Path(str(image) + ".custody.json")
        if not cf.exists():
            raise ImagingError(f"custody file not found: {cf}")
        data = json.loads(cf.read_text(encoding="utf-8"))
        expected = data.get("acquisition_hashes") or {}
    if not expected:
        raise ImagingError("no expected hashes to compare against")
    computed = _hash_file(Path(image), expected.keys())
    mismatches = [k for k in expected if computed.get(k, "").lower() != expected[k].lower()]
    return {"ok": not mismatches, "computed": computed, "expected": expected, "mismatches": mismatches}
