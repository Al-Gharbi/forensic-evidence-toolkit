import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from fet import __version__
from fet.cli import main
from tests.mft_builder import build_mft, build_volume
from tests.test_mft import sample_records


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_image_then_verify_then_detect_tampering(self):
        src = self.d / "disk.bin"
        src.write_bytes(os.urandom(100_000))
        code, out, _ = run("image", str(src), str(self.d / "disk.dd"), "--case", "C-9", "--examiner", "QA", "--quiet")
        self.assertEqual(code, 0)
        self.assertIn("Verified:   YES", out)
        self.assertTrue((self.d / "disk.dd.custody.json").exists())
        code, out, _ = run("verify", str(self.d / "disk.dd"))
        self.assertEqual(code, 0)
        self.assertIn("image matches custody record", out)
        raw = bytearray((self.d / "disk.dd").read_bytes())
        raw[5] ^= 0xFF
        (self.d / "disk.dd").write_bytes(bytes(raw))
        code, out, _ = run("verify", str(self.d / "disk.dd"))
        self.assertEqual(code, 2)
        self.assertIn("DOES NOT MATCH", out)

    def test_image_refuses_existing_destination(self):
        src = self.d / "a"
        src.write_bytes(b"data" * 100)
        run("image", str(src), str(self.d / "o.dd"), "--case", "c", "--examiner", "e", "--quiet")
        code, _, err = run("image", str(src), str(self.d / "o.dd"), "--case", "c", "--examiner", "e", "--quiet")
        self.assertEqual(code, 1)
        self.assertIn("destination exists", err)

    def test_mft_from_extracted_file_csv_and_flagged(self):
        f = self.d / "$MFT"
        f.write_bytes(build_mft(sample_records()))
        code, out, err = run("mft", str(f), "--only-flagged")
        self.assertEqual(code, 0)
        self.assertIn("evil.exe", out)
        self.assertNotIn("normal.txt", out)
        self.assertIn("timestomp_indicators=2", err)

    def test_mft_from_volume_to_bodyfile(self):
        img = self.d / "vol.img"
        img.write_bytes(build_volume(sample_records(), partition_offset=1048576))
        out_file = self.d / "body.txt"
        code, _, _ = run("mft", str(img), "--volume", "--offset", "1048576", "--format", "bodyfile", "-o", str(out_file))
        self.assertEqual(code, 0)
        self.assertIn("/Users/evil.exe", out_file.read_text())

    def test_mft_volume_wrong_offset_is_clean_error(self):
        img = self.d / "vol.img"
        img.write_bytes(build_volume(sample_records(), partition_offset=1048576))
        code, _, err = run("mft", str(img), "--volume")
        self.assertEqual(code, 1)
        self.assertIn("--offset", err)

    def test_strings_and_iocs(self):
        f = self.d / "mem.raw"
        f.write_bytes(b"\x00\x01http://c2.example/beacon\x00\xff\xff" + "cmd.exe /c whoami".encode("utf-16le") + b"\x00\x00")
        code, out, _ = run("strings", str(f))
        self.assertEqual(code, 0)
        self.assertIn("utf16le\tcmd.exe /c whoami", out)
        code, out, _ = run("strings", str(f), "--iocs")
        self.assertEqual(json.loads(out)["url"][0]["value"], "http://c2.example/beacon")

    def test_mem_triage_from_dir_exit_code_reflects_high_findings(self):
        def p(pid, ppid, name, off, ex=None):
            return {"PID": pid, "PPID": ppid, "ImageFileName": name, "Offset(V)": off, "ExitTime": ex}
        base = [p(4, 0, "System", 1), p(300, 4, "smss.exe", 2)]
        (self.d / "pslist.json").write_text(json.dumps(base))
        (self.d / "psscan.json").write_text(json.dumps(base))
        code, out, _ = run("mem-triage", "--from-dir", str(self.d))
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)
        (self.d / "psscan.json").write_text(json.dumps(base + [p(666, 4, "hidden.exe", 3)]))
        report = self.d / "report.md"
        code, _, _ = run("mem-triage", "--from-dir", str(self.d), "--report", str(report))
        self.assertEqual(code, 3)
        self.assertIn("MEM-001", report.read_text())
        self.assertEqual(json.loads(report.with_suffix(".json").read_text())["counts"]["high"], 1)

    def test_mem_triage_requires_input(self):
        code, _, err = run("mem-triage")
        self.assertEqual(code, 1)

    def test_version(self):
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(io.StringIO()) as out:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(__version__, out.getvalue())


if __name__ == "__main__":
    unittest.main()
