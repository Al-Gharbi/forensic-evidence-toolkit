"""Generate a small SYNTHETIC demo dataset (no real evidence) to try the tools.

    python examples/make_demo.py demo/
    fet mft demo/demo.mft --only-flagged
    fet mem-triage --from-dir demo/memory --report demo/memory-report.md

Everything produced here is invented. The 'attacker' artefacts exist only to
show what the detections look like.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.mft_builder import build_mft, build_volume, file_record, ft  # noqa: E402


def main(out: str) -> None:
    out_dir = Path(out)
    (out_dir / "memory").mkdir(parents=True, exist_ok=True)
    normal = ft(2023, 6, 7, 8, 9, 10, 7654321)
    recs = {
        5: file_record(".", 5, 5, normal, directory=True),
        16: file_record("Users", 5, 1, normal, directory=True),
        17: file_record("Public", 16, 1, normal, directory=True),
        18: file_record("report.docx", 17, 1, normal, size=10),
        # back-dated $STANDARD_INFORMATION (exact second, older than $FILE_NAME)
        19: file_record("svch0st.exe", 17, 1, ft(2019, 1, 1, 12, 0, 0, 0), modified=ft(2019, 1, 1, 12, 0, 0, 0),
                        fn_times=(ft(2024, 3, 5, 10, 11, 12, 1234567),) * 4, size=5000),
        20: file_record("old-notes.txt", 17, 1, normal, size=10, in_use=False),
        21: file_record("invoice.pdf", 17, 1, normal, size=10, ads=["Zone.Identifier"]),
    }
    (out_dir / "demo.mft").write_bytes(build_mft(recs))
    (out_dir / "demo-ntfs.img").write_bytes(build_volume(recs))

    def p(pid, ppid, name, off, exit_time=None):
        return {"PID": pid, "PPID": ppid, "ImageFileName": name, "Offset(V)": off, "ExitTime": exit_time}

    ps = [p(4, 0, "System", 0x1000), p(300, 4, "smss.exe", 0x2000), p(500, 400, "wininit.exe", 0x3000),
          p(620, 500, "services.exe", 0x4000), p(640, 500, "lsass.exe", 0x5000), p(760, 620, "svchost.exe", 0x6000),
          p(2100, 2000, "explorer.exe", 0x7000), p(3300, 2100, "svchost.exe", 0x8000),
          p(3400, 2100, "powershell.exe", 0x8100)]
    scan = ps + [p(1337, 620, "implant.exe", 0x9000), p(999, 620, "old.exe", 0x9100, "2024-05-01T11:00:00+00:00")]
    cmd = [
        {"PID": 760, "Process": "svchost.exe", "Args": r"C:\Windows\system32\svchost.exe -k DcomLaunch -p"},
        {"PID": 3300, "Process": "svchost.exe", "Args": r"C:\Users\Public\svchost.exe"},
        {"PID": 3400, "Process": "powershell.exe",
         "Args": "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"},
    ]
    mal = [{"PID": 2100, "Process": "explorer.exe", "Start VPN": 0x2A0000, "End VPN": 0x2A0FFF,
            "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d 5a 90 00 03 00 00 00"}]
    net = [{"PID": 640, "Owner": "lsass.exe", "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49152,
            "ForeignAddr": "93.184.216.34", "ForeignPort": 443, "State": "ESTABLISHED"}]
    for name, data in (("pslist", ps), ("psscan", scan), ("cmdline", cmd), ("malfind", mal), ("netscan", net)):
        (out_dir / "memory" / f"{name}.json").write_text(json.dumps(data, indent=2))
    print(f"demo data written to {out_dir}/")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo")
