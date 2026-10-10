"""Streaming string carving and IOC extraction for raw memory / disk images.

Works on any file (no Volatility needed). Strings are found in ASCII and
UTF-16LE, streamed in chunks (a 16 GB image does not need 16 GB of RAM) and
strings that straddle a chunk boundary are carried over, not cut in half.
"""

from __future__ import annotations

import ipaddress
import re
from typing import BinaryIO, Dict, Iterator, List, Tuple

CHUNK = 8 * 1024 * 1024

IOC_PATTERNS = {
    "url": re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "registry_key": re.compile(r"\bHK(?:EY_LOCAL_MACHINE|EY_CURRENT_USER|LM|CU)\\[^\x00\r\n\"]{3,}"),
}


def _compile(min_len: int, kind: str) -> "re.Pattern[bytes]":
    if kind == "ascii":
        return re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)


MAX_CARRY = 1 << 20  # strings longer than 1 MiB are split into 1 MiB pieces


def _trailing_run_start(data: bytes, enc: str) -> int:
    """Index where the string-like run that touches the end of ``data`` begins."""
    i = len(data)
    if enc == "ascii":
        while i > 0 and 0x20 <= data[i - 1] <= 0x7E:
            i -= 1
        return i
    if i > 0 and 0x20 <= data[i - 1] <= 0x7E:  # dangling first half of a UTF-16 pair
        i -= 1
    while i >= 2 and data[i - 1] == 0 and 0x20 <= data[i - 2] <= 0x7E:
        i -= 2
    return i


def iter_strings(f: BinaryIO, min_len: int = 6, chunk_size: int = CHUNK) -> Iterator[Tuple[int, str, str]]:
    """Yield ``(offset, encoding, text)``; ``offset`` is the byte offset in the file.

    The trailing printable run of every chunk is carried into the next one, so a
    string that straddles a chunk boundary is reported once and whole, even if the
    part before the boundary is shorter than ``min_len``.
    """
    patterns = {"ascii": _compile(min_len, "ascii"), "utf16le": _compile(min_len, "utf16le")}
    carry = {"ascii": b"", "utf16le": b""}
    carry_off = {"ascii": 0, "utf16le": 0}
    base = f.tell()
    while True:
        chunk = f.read(chunk_size)
        eof = not chunk
        for enc, pat in patterns.items():
            data = carry[enc] + chunk
            data_off = carry_off[enc] if carry[enc] else base
            if eof:
                keep_from = len(data)
            else:
                keep_from = _trailing_run_start(data, enc)
                excess = (len(data) - keep_from) - MAX_CARRY
                if excess > 0:
                    keep_from += excess + (excess % 2 if enc == "utf16le" else 0)
            for m in pat.finditer(data):
                if m.start() >= keep_from:
                    continue
                raw = m.group()[: keep_from - m.start()]
                if enc == "utf16le" and len(raw) % 2:
                    raw = raw[:-1]
                if len(raw) < (min_len if enc == "ascii" else 2 * min_len):
                    continue
                text = raw.decode("ascii") if enc == "ascii" else raw.decode("utf-16le")
                yield data_off + m.start(), enc, text
            carry[enc] = data[keep_from:]
            carry_off[enc] = data_off + keep_from
        base += len(chunk)
        if eof:
            break


def extract_iocs(strings: Iterator[Tuple[int, str, str]], public_ips_only: bool = True) -> Dict[str, List[Dict]]:
    """Scan strings for IOCs. Returns ``{type: [{"value", "count", "first_offset"}]}``."""
    found: Dict[str, Dict[str, Dict]] = {k: {} for k in IOC_PATTERNS}
    for off, _enc, text in strings:
        for kind, pat in IOC_PATTERNS.items():
            for m in pat.finditer(text):
                val = m.group()
                if kind == "ipv4":
                    ip = ipaddress.ip_address(val)
                    if public_ips_only and (ip.is_private or ip.is_loopback or ip.is_unspecified
                                            or ip.is_multicast or ip.is_link_local or ip.is_reserved):
                        continue
                    # drop version-number lookalikes such as 1.2.3.4 inside "v1.2.3.4"
                    if m.start() > 0 and text[m.start() - 1].lower() in "v.":
                        continue
                slot = found[kind].setdefault(val, {"value": val, "count": 0, "first_offset": off})
                slot["count"] += 1
    return {k: sorted(v.values(), key=lambda d: (-d["count"], d["value"])) for k, v in found.items()}
