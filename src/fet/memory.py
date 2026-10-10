"""Memory-forensics triage on top of Volatility 3.

Design
------
Volatility 3 does the hard part (locating kernel structures in a memory
image). This module:

1. runs a fixed set of Windows plugins through the ``vol`` command line with
   the JSON renderer and **saves the raw plugin output** next to the report
   (so every finding can be traced to tool output),
2. loads that output (or a directory of previously saved output, so triage
   can be re-run or reviewed without the image),
3. applies explicit, documented detection rules (see ``docs/METHODOLOGY.md``)
   and emits findings with severity and MITRE ATT&CK technique IDs.

Volatility itself is *not* a dependency of this package and is *not*
re-implemented here. Rules are heuristics: every finding names the evidence
that triggered it and should be confirmed manually (e.g. with
``windows.dumpfiles`` or ``windows.vadinfo``).

Volatility 3 JSON renderer: a list of row objects keyed by column title;
tree plugins nest rows under ``__children``. Column lookup here is
case-insensitive and tolerates the aliases in ``ALIASES`` so small naming
differences between Volatility releases do not break triage.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "psscan": "windows.psscan.PsScan",
    "cmdline": "windows.cmdline.CmdLine",
    # Moved to windows.malware.malfind in current Volatility 3; the old name is a
    # deprecated shim (announced removal date 2026-06-07), so it is only a fallback.
    "malfind": "windows.malware.malfind.Malfind",
    "netscan": "windows.netscan.NetScan",
}

FALLBACK_PLUGINS = {"malfind": "windows.malfind.Malfind"}

ALIASES = {
    "pid": ("PID", "Pid"),
    "ppid": ("PPID", "PPid", "InheritedFromUniqueProcessId"),
    "name": ("ImageFileName", "Name", "Process", "Owner"),
    "offset": ("Offset(V)", "Offset", "Offset(P)"),
    "create": ("CreateTime",),
    "exit": ("ExitTime",),
    "args": ("Args", "CommandLine", "Cmdline"),
    "start": ("Start VPN", "Start"),
    "end": ("End VPN", "End"),
    "protection": ("Protection",),
    "hexdump": ("Hexdump", "HexDump"),
    "proto": ("Proto", "Protocol"),
    "laddr": ("LocalAddr", "LocalAddress"),
    "lport": ("LocalPort",),
    "faddr": ("ForeignAddr", "ForeignAddress"),
    "fport": ("ForeignPort",),
    "state": ("State",),
    "owner": ("Owner", "Process"),
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class MemoryError_(Exception):
    """Raised when Volatility cannot be run or its output cannot be parsed."""


# ------------------------------------------------------------ running / loading
def find_volatility() -> List[str]:
    for exe in ("vol", "vol3", "volatility3"):
        path = shutil.which(exe)
        if path:
            return [path]
    try:
        import importlib.util

        if importlib.util.find_spec("volatility3"):
            return [sys.executable, "-m", "volatility3"]
    except Exception:  # pragma: no cover - defensive
        pass
    raise MemoryError_(
        "Volatility 3 not found. Install it (pip install volatility3) or pass --vol-cmd, "
        "or analyse previously saved output with --from-dir."
    )


def run_plugin(image: str, plugin: str, vol_cmd: Optional[Sequence[str]] = None, timeout: int = 3600) -> Any:
    cmd = list(vol_cmd) if vol_cmd else find_volatility()
    full = [*cmd, "-q", "-f", image, "-r", "json", plugin]
    try:
        proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise MemoryError_(f"{plugin} timed out after {timeout}s") from exc
    if proc.returncode != 0:
        raise MemoryError_(f"{plugin} failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise MemoryError_(f"{plugin} did not return JSON: {exc}") from exc


def flatten(rows: Any) -> List[Dict[str, Any]]:
    """Flatten Volatility's ``__children`` tree into a plain list of rows."""
    out: List[Dict[str, Any]] = []
    if isinstance(rows, dict):
        rows = [rows]
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        children = row.get("__children") or []
        clean = {k: v for k, v in row.items() if k != "__children"}
        out.append(clean)
        out.extend(flatten(children))
    return out


def get(row: Dict[str, Any], key: str, default: Any = None) -> Any:
    lowered = {k.lower(): v for k, v in row.items()}
    for alias in ALIASES.get(key, (key,)):
        if alias in row:
            return row[alias]
        if alias.lower() in lowered:
            return lowered[alias.lower()]
    return default


@dataclass
class Snapshot:
    pslist: List[Dict[str, Any]] = field(default_factory=list)
    psscan: List[Dict[str, Any]] = field(default_factory=list)
    cmdline: List[Dict[str, Any]] = field(default_factory=list)
    malfind: List[Dict[str, Any]] = field(default_factory=list)
    netscan: List[Dict[str, Any]] = field(default_factory=list)
    source: str = ""


def collect(image: str, out_dir: str, vol_cmd: Optional[Sequence[str]] = None, timeout: int = 3600) -> Snapshot:
    """Run every plugin, save raw output to ``out_dir/<name>.json``, return a snapshot."""
    os.makedirs(out_dir, exist_ok=True)
    snap = Snapshot(source=f"volatility3 run on {image}")
    for key, plugin in PLUGINS.items():
        try:
            data = run_plugin(image, plugin, vol_cmd, timeout)
        except MemoryError_:
            old = FALLBACK_PLUGINS.get(key)
            if old is None:
                raise
            data = run_plugin(image, old, vol_cmd, timeout)  # older Volatility 3 releases
        Path(out_dir, f"{key}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        setattr(snap, key, flatten(data))
    return snap


def load_dir(path: str) -> Snapshot:
    """Load previously saved plugin output (``pslist.json`` ...). Missing files are allowed."""
    snap = Snapshot(source=f"saved output in {path}")
    found = False
    for key in PLUGINS:
        p = Path(path, f"{key}.json")
        if p.exists():
            found = True
            try:
                setattr(snap, key, flatten(json.loads(p.read_text(encoding="utf-8"))))
            except json.JSONDecodeError as exc:
                raise MemoryError_(f"{p}: invalid JSON ({exc})") from exc
    if not found:
        raise MemoryError_(f"no plugin output (pslist.json, psscan.json, ...) found in {path}")
    return snap


# --------------------------------------------------------------------- helpers
def _pid(row: Dict[str, Any]) -> Optional[int]:
    v = get(row, "pid")
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _name(row: Dict[str, Any]) -> str:
    return str(get(row, "name", "") or "").strip()


def _alive(row: Dict[str, Any]) -> bool:
    ex = get(row, "exit")
    return ex in (None, "", "N/A") or str(ex).startswith("-")


def _finding(fid: str, severity: str, title: str, detail: str, pid: Optional[int] = None,
             process: str = "", mitre: str = "", evidence: str = "") -> Dict[str, Any]:
    return {
        "id": fid, "severity": severity, "title": title, "detail": detail,
        "pid": pid, "process": process, "mitre": mitre, "evidence": evidence,
    }


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ------------------------------------------------------------------- the rules
def find_hidden_processes(pslist: List[Dict[str, Any]], psscan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Processes found by pool scanning (psscan) but missing from the active list (pslist).

    A process that has *exited* legitimately stays in psscan for a while, so
    those are reported as informational; a still-running process that is not
    on the active list is the classic DKOM unlinking signature.
    """
    active_pids = {_pid(r) for r in pslist}
    active_offsets = {get(r, "offset") for r in pslist if get(r, "offset") is not None}
    out = []
    for row in psscan:
        pid = _pid(row)
        off = get(row, "offset")
        in_list = pid in active_pids or (off is not None and off in active_offsets)
        if in_list:
            continue
        name = _name(row)
        if _alive(row):
            out.append(_finding(
                "MEM-001", "high", "Process hidden from the active process list",
                f"{name} (PID {pid}) is in psscan, has no exit time, but is absent from pslist "
                "(possible DKOM / unlinking).", pid, name, "T1014",
                f"psscan offset={off} create={get(row, 'create')}"))
        else:
            out.append(_finding(
                "MEM-002", "info", "Terminated process still present in pool scan",
                f"{name} (PID {pid}) exited at {get(row, 'exit')}.", pid, name, "",
                f"psscan offset={off}"))
    return out


EXPECTED_PARENT = {
    "smss.exe": {"system"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsm.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
    "spoolsv.exe": {"services.exe"},
    "taskhost.exe": {"services.exe", "svchost.exe"},
    "taskhostw.exe": {"services.exe", "svchost.exe"},
    "runtimebroker.exe": {"svchost.exe"},
}
SINGLETONS = {"lsass.exe", "wininit.exe", "services.exe", "lsm.exe"}
SYSTEM32_ONLY = {
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
    "smss.exe", "wininit.exe", "spoolsv.exe", "lsm.exe",
}
KNOWN_PROCESS_NAMES = SYSTEM32_ONLY | {
    "system", "explorer.exe", "taskhost.exe", "taskhostw.exe", "conhost.exe", "dwm.exe",
    "sihost.exe", "fontdrvhost.exe", "audiodg.exe", "dllhost.exe", "msdtc.exe", "ctfmon.exe",
    "runtimebroker.exe", "searchindexer.exe", "wmiprvse.exe", "smartscreen.exe", "lsaiso.exe",
    "userinit.exe", "winlogon.exe", "csrss.exe", "msmpeng.exe", "cmd.exe", "powershell.exe",
}
MASQUERADE_TARGETS = ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
                      "explorer.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "taskhost.exe")

SUSPICIOUS_CMDLINE = [
    (re.compile(r"-(?:e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I), "Encoded PowerShell command", "T1059.001"),
    (re.compile(r"-w(?:indowstyle)?\s+hidden", re.I), "Hidden window style", "T1564.003"),
    (re.compile(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient", re.I), "Download cradle", "T1105"),
    (re.compile(r"\binvoke-expression\b|\biex\b", re.I), "Invoke-Expression", "T1059.001"),
    (re.compile(r"frombase64string", re.I), "Base64 decoding in command line", "T1027"),
    (re.compile(r"certutil.*-(?:urlcache|decode)", re.I), "certutil used to fetch/decode", "T1105"),
    (re.compile(r"mshta(?:\.exe)?\s+(?:https?:|vbscript:|javascript:)", re.I), "mshta executing remote/script content", "T1218.005"),
    (re.compile(r"regsvr32.*(?:/i:https?:|scrobj\.dll)", re.I), "regsvr32 remote scriptlet (Squiblydoo)", "T1218.010"),
    (re.compile(r"bitsadmin.*/transfer", re.I), "bitsadmin transfer", "T1197"),
    (re.compile(r"rundll32(?:\.exe)?\s+javascript:", re.I), "rundll32 javascript:", "T1218.011"),
]


SYSTEM_DIRS = (
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
    "\\systemroot\\system32\\", "\\??\\c:\\windows\\system32\\", "%systemroot%\\system32\\",
)


def _first_token_path(args: str) -> str:
    args = args.strip()
    if args.startswith('"'):
        end = args.find('"', 1)
        return args[1:end] if end > 0 else args[1:]
    return args.split(" ", 1)[0]


def check_process_tree(pslist: List[Dict[str, Any]], cmdline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    live = [r for r in pslist if _alive(r)]
    by_pid = {_pid(r): r for r in pslist if _pid(r) is not None}
    args_by_pid = {_pid(r): str(get(r, "args", "") or "") for r in cmdline}

    # parent / child relationships (only when the parent still exists)
    for r in live:
        name, pid, ppid = _name(r).lower(), _pid(r), None
        try:
            ppid = int(get(r, "ppid"))
        except (TypeError, ValueError):
            pass
        expected = EXPECTED_PARENT.get(name)
        parent = by_pid.get(ppid)
        if expected and parent is not None:
            pname = _name(parent).lower()
            if pname not in expected:
                out.append(_finding(
                    "MEM-010", "high", "Unexpected parent process",
                    f"{_name(r)} (PID {pid}) has parent {_name(parent)} (PID {ppid}); expected one of "
                    f"{', '.join(sorted(expected))}.", pid, _name(r), "T1036.005",
                    f"ppid={ppid}"))

    # singletons
    counts: Dict[str, List[int]] = {}
    for r in live:
        counts.setdefault(_name(r).lower(), []).append(_pid(r))
    for nm in SINGLETONS:
        pids = counts.get(nm, [])
        if len(pids) > 1:
            out.append(_finding(
                "MEM-011", "high", "Multiple instances of a singleton system process",
                f"{nm} should run once; found PIDs {pids}.", pids[0], nm, "T1036.005", f"pids={pids}"))

    # masquerading by name similarity
    for r in live:
        nm = _name(r).lower()
        if not nm or nm in KNOWN_PROCESS_NAMES:
            continue
        for target in MASQUERADE_TARGETS:
            if levenshtein(nm, target) <= 2 and abs(len(nm) - len(target)) <= 2:
                out.append(_finding(
                    "MEM-012", "medium", "Process name resembles a critical system process",
                    f"{_name(r)} (PID {_pid(r)}) is within edit distance 2 of {target}.",
                    _pid(r), _name(r), "T1036.005", f"similar_to={target}"))
                break

    # command-line based rules
    for r in live:
        pid, name = _pid(r), _name(r)
        args = args_by_pid.get(pid, "")
        if not args or args.lower() == "required memory at 0x0 is not valid (processes exited)":
            continue
        low = name.lower()
        if low == "svchost.exe" and not re.search(r"\s-k\s", " " + args + " ", re.I):
            out.append(_finding("MEM-013", "medium", "svchost.exe without -k service group argument",
                                f"Command line: {args}", pid, name, "T1036.005", args))
        if low in SYSTEM32_ONLY:
            path = _first_token_path(args).replace("/", "\\").lower()
            if "\\" in path and not path.startswith(SYSTEM_DIRS):
                out.append(_finding("MEM-014", "high", "System process name running from a non-system path",
                                    f"{name} (PID {pid}) was started from {path}.", pid, name, "T1036.005", args))
        for pattern, title, mitre in SUSPICIOUS_CMDLINE:
            if pattern.search(args):
                out.append(_finding("MEM-015", "high", f"Suspicious command line: {title}",
                                    f"{name} (PID {pid})", pid, name, mitre, args[:300]))
    return out


def analyze_malfind(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every malfind hit is private RWX memory; flag PE headers higher.

    Known benign sources: JIT compilers (.NET, JavaScript engines), some AV/EDR
    hooks. Treat as a lead to verify, not a verdict.
    """
    out = []
    for r in rows:
        dump = str(get(r, "hexdump", "") or "").strip().lower()
        has_pe = dump.startswith("4d 5a") or dump.startswith("mz")
        pid, name = _pid(r), _name(r)
        out.append(_finding(
            "MEM-020", "high" if has_pe else "medium",
            "Executable private memory region" + (" containing a PE header" if has_pe else ""),
            f"{name} (PID {pid}) {get(r, 'start')}-{get(r, 'end')} protection={get(r, 'protection')}",
            pid, name, "T1055", dump[:60]))
    return out


NO_NETWORK = {"lsass.exe", "services.exe", "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe",
              "notepad.exe", "calc.exe", "mspaint.exe"}


def _is_external(addr: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(addr).strip("[]"))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def analyze_network(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in rows:
        owner = str(get(r, "owner", "") or "").lower()
        faddr, state = get(r, "faddr"), str(get(r, "state", "") or "").upper()
        if owner in NO_NETWORK and _is_external(faddr) and state in ("ESTABLISHED", "SYN_SENT", ""):
            out.append(_finding(
                "MEM-030", "high", "External connection from a process that normally has none",
                f"{owner} PID {_pid(r)} -> {faddr}:{get(r, 'fport')} ({state or 'n/a'})",
                _pid(r), owner, "T1071", f"{get(r, 'laddr')}:{get(r, 'lport')} -> {faddr}:{get(r, 'fport')}"))
    return out


# ---------------------------------------------------------------------- report
def triage(snap: Snapshot) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    notes: List[str] = []
    if snap.pslist and snap.psscan:
        findings += find_hidden_processes(snap.pslist, snap.psscan)
    else:
        notes.append("hidden-process check skipped: needs both pslist.json and psscan.json")
    if snap.pslist:
        findings += check_process_tree(snap.pslist, snap.cmdline)
    else:
        notes.append("process-tree checks skipped: no pslist.json")
    if snap.malfind:
        findings += analyze_malfind(snap.malfind)
    if snap.netscan:
        findings += analyze_network(snap.netscan)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["id"], f["pid"] or 0))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    return {
        "source": snap.source,
        "counts": counts,
        "plugin_rows": {k: len(getattr(snap, k)) for k in PLUGINS},
        "notes": notes,
        "findings": findings,
    }


def render_markdown(result: Dict[str, Any]) -> str:
    c = result["counts"]
    lines = [
        "# Memory triage report", "",
        f"Source: {result['source']}", "",
        f"Findings: **{c['high']} high**, {c['medium']} medium, {c['low']} low, {c['info']} info", "",
        "Rows analysed: " + ", ".join(f"{k}={v}" for k, v in result["plugin_rows"].items()), "",
    ]
    for n in result["notes"]:
        lines.append(f"> Note: {n}")
    if result["notes"]:
        lines.append("")
    if not result["findings"]:
        lines += ["No findings from the implemented rules. This is **not** proof the image is clean.", ""]
    for f in result["findings"]:
        lines.append(f"## [{f['severity'].upper()}] {f['id']} - {f['title']}")
        lines.append(f"- Detail: {f['detail']}")
        if f["mitre"]:
            lines.append(f"- MITRE ATT&CK: {f['mitre']}")
        if f["evidence"]:
            lines.append(f"- Evidence: `{f['evidence']}`")
        lines.append("")
    lines.append("_Heuristic output. Confirm every finding manually before reporting it._")
    return "\n".join(lines) + "\n"
