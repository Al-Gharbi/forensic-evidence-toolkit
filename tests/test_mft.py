import io
import unittest

from fet import mft
from tests.mft_builder import (build_mft, build_record, build_volume, encode_runlist, file_record, fn_attr,
                               ft, si_attr)

ROOT, USERS = 5, 16


def sample_records():
    t_old = ft(2019, 1, 1, 12, 0, 0, 0)                     # exact second: typical of timestomp tools
    t_new = ft(2024, 3, 5, 10, 11, 12, 1234567)
    normal = ft(2023, 6, 7, 8, 9, 10, 7654321)
    recs = {
        5: file_record(".", 5, 5, normal, directory=True),
        16: file_record("Users", 5, 1, normal, directory=True),
        # back-dated $SI, genuine $FN
        17: file_record("evil.exe", 16, 1, t_old, modified=t_old, fn_times=(t_new, t_new, t_new, t_new), size=5000),
        # consistent timestamps
        18: file_record("normal.txt", 16, 1, normal, size=10),
        # deleted file
        19: file_record("gone.doc", 16, 1, normal, size=10, in_use=False),
        # file with an alternate data stream
        20: file_record("doc.pdf", 16, 1, normal, size=10, ads=["Zone.Identifier"]),
        # parent does not exist
        21: file_record("orphan.bin", 99, 1, normal, size=10),
        # DOS + Win32 names: Win32 must be preferred
        22: file_record("LongFileName.txt", 16, 1, normal, size=10, extra_fn=[("LONGFI~1.TXT", 2)]),
        # parent slot re-used (sequence 7 in FN, parent record has sequence 1)
        23: file_record("stale.txt", 16, 7, normal, size=10),
    }
    return recs


class ExtensionRecordTests(unittest.TestCase):
    def build(self):
        normal = ft(2023, 6, 7, 8, 9, 10, 7654321)
        from tests.mft_builder import attr_resident
        base = build_record(seq=3, attrs=[
            si_attr(normal, normal, normal, normal),
            fn_attr(16, 1, "LONGFI~1.TXT", (normal,) * 4, 2, 10),
            attr_resident(0x20, b"\x00" * 32),                      # $ATTRIBUTE_LIST marker
        ])
        ext = build_record(seq=3, base_ref=30 | (3 << 48), attrs=[
            fn_attr(16, 1, "A long file name.txt", (normal,) * 4, 1, 10),
            attr_resident(0x80, b"x" * 10),
        ])
        recs = {5: file_record(".", 5, 5, normal, directory=True),
                16: file_record("Users", 5, 1, normal, directory=True),
                30: base, 31: ext}
        return list(mft.iter_mft_file(io.BytesIO(build_mft(recs))))

    def test_long_name_in_extension_record_is_used_and_extension_dropped(self):
        out = mft.analyze(self.build())
        by = {e.record_number: e for e in out}
        self.assertNotIn(31, by)
        self.assertEqual(by[30].path, "/Users/A long file name.txt")
        self.assertEqual(by[30].data_size, 10)
        self.assertEqual(by[30].extension_records, 1)
        self.assertTrue(any("merged 1 extension" in w for w in by[30].warnings))
        self.assertFalse(any("not merged" in w for w in by[30].warnings))

    def test_size_comes_from_the_first_extent_of_a_fragmented_stream(self):
        from tests.mft_builder import attr_nonresident
        normal = ft(2023, 6, 7, 8, 9, 10, 7654321)
        base = build_record(seq=3, attrs=[
            si_attr(normal, normal, normal, normal),
            fn_attr(16, 1, "big.log", (normal,) * 4, 1, 706832),
            attr_nonresident(0x80, encode_runlist([(100, 1)]), 706832, 1024),
        ])
        ext = build_record(seq=3, base_ref=30 | (3 << 48), attrs=[
            attr_nonresident(0x80, encode_runlist([(300, 1)]), 0, 1024, lowest_vcn=5),
        ])
        recs = {5: file_record(".", 5, 5, normal, directory=True),
                16: file_record("Users", 5, 1, normal, directory=True), 30: base, 31: ext}
        out = {e.record_number: e for e in mft.analyze(mft.iter_mft_file(io.BytesIO(build_mft(recs))))}
        self.assertEqual(out[30].data_size, 706832)
        # and when the base record has no $DATA, the VCN-0 extent in the extension record is used
        base2 = build_record(seq=3, attrs=[si_attr(normal, normal, normal, normal),
                                           fn_attr(16, 1, "big.log", (normal,) * 4, 1, 1)])
        ext0 = build_record(seq=3, base_ref=30 | (3 << 48), attrs=[
            attr_nonresident(0x80, encode_runlist([(100, 1)]), 4242, 1024)])
        recs[30], recs[31] = base2, ext0
        out = {e.record_number: e for e in mft.analyze(mft.iter_mft_file(io.BytesIO(build_mft(recs))))}
        self.assertEqual(out[30].data_size, 4242)

    def test_orphan_extension_record_is_kept(self):
        ents = [e for e in self.build() if e.record_number != 30]
        self.assertIn(31, {e.record_number for e in mft.merge_extensions(ents)})

    def test_merge_is_idempotent(self):
        once = mft.merge_extensions(self.build())
        twice = mft.merge_extensions(once)
        self.assertEqual([e.record_number for e in once], [e.record_number for e in twice])
        self.assertEqual(len(once[2].fn) if len(once) > 2 else 0, len(twice[2].fn) if len(twice) > 2 else 0)


class TimeTests(unittest.TestCase):
    def test_filetime_roundtrip(self):
        self.assertEqual(mft.filetime_to_iso(ft(2024, 3, 5, 10, 11, 12, 1234567)), "2024-03-05 10:11:12.1234567")
        self.assertEqual(mft.filetime_to_iso(0), "")
        self.assertEqual(mft.filetime_to_epoch(ft(2024, 3, 5, 10, 11, 12)), 1709633472)

    def test_huge_value_does_not_crash(self):
        self.assertEqual(mft.filetime_to_iso(2**63), "invalid")


class RecordParsingTests(unittest.TestCase):
    def test_basic_fields(self):
        e = mft.parse_record(file_record("a.txt", 5, 1, ft(2023, 1, 2, 3, 4, 5, 6), size=10), 30)
        self.assertEqual((e.record_number, e.sequence, e.in_use, e.is_directory), (30, 1, True, False))
        self.assertEqual(e.name, "a.txt")
        self.assertEqual(e.parent_record, 5)
        self.assertEqual((e.data_size, e.data_resident), (10, True))
        self.assertEqual(e.si.created, ft(2023, 1, 2, 3, 4, 5, 6))

    def test_non_resident_size_and_directory_flag(self):
        e = mft.parse_record(file_record("big.bin", 5, 1, ft(2023, 1, 1), size=5000), 1)
        self.assertEqual((e.data_size, e.data_resident), (5000, False))
        d = mft.parse_record(file_record("dir", 5, 1, ft(2023, 1, 1), directory=True), 2)
        self.assertTrue(d.is_directory)
        self.assertIsNone(d.data_size)

    def test_fixups_restore_bytes_that_cross_a_sector_boundary(self):
        long_name = "x" * 200 + ".txt"  # $FILE_NAME content spans byte 510/511
        e = mft.parse_record(file_record(long_name, 5, 1, ft(2023, 1, 1, 0, 0, 0, 5)), 1)
        self.assertEqual(e.name, long_name)
        self.assertEqual(e.warnings, [])

    def test_fixup_mismatch_is_reported_not_fatal(self):
        raw = build_record(attrs=[si_attr(*(ft(2023, 1, 1, 0, 0, 0, 3),) * 4)], corrupt_sector=2)
        e = mft.parse_record(raw, 1)
        self.assertIsNotNone(e)
        self.assertTrue(any("fixup mismatch" in w for w in e.warnings))

    def test_zeroed_and_garbage_slots_return_none(self):
        self.assertIsNone(mft.parse_record(b"\x00" * 1024, 0))
        self.assertIsNone(mft.parse_record(b"BAAD" + b"\x00" * 1020, 0))
        self.assertIsNone(mft.parse_record(b"FILE", 0))

    def test_truncated_attribute_length_does_not_crash(self):
        raw = bytearray(file_record("a.txt", 5, 1, ft(2023, 1, 1)))
        raw[0x38 + 4 : 0x38 + 8] = (0x7FFFFFFF).to_bytes(4, "little")  # first attribute length
        e = mft.parse_record(bytes(raw), 1)
        self.assertIsNotNone(e)
        self.assertTrue(any("bad attribute length" in w for w in e.warnings))

    def test_ads_names(self):
        e = mft.parse_record(file_record("doc.pdf", 5, 1, ft(2023, 1, 1), size=10, ads=["Zone.Identifier"]), 1)
        self.assertEqual(e.ads, ["Zone.Identifier"])
        self.assertEqual(e.data_size, 10)  # unnamed stream size is unaffected by the ADS

    def test_win32_name_preferred_over_dos(self):
        e = mft.parse_record(file_record("LongFileName.txt", 5, 1, ft(2023, 1, 1), extra_fn=[("LONGFI~1.TXT", 2)]), 1)
        self.assertEqual(len(e.fn), 2)
        self.assertEqual(e.name, "LongFileName.txt")


class RunlistTests(unittest.TestCase):
    def test_roundtrip_with_negative_delta(self):
        runs = [(100, 8), (50, 4), (4000, 300)]
        self.assertEqual(mft.parse_runlist(encode_runlist(runs)), runs)

    def test_sparse_run(self):
        self.assertEqual(mft.parse_runlist(bytes([0x01, 0x05, 0x00])), [(None, 5)])

    def test_corrupt_runlist_raises(self):
        with self.assertRaises(mft.MftError):
            mft.parse_runlist(bytes([0x44, 0x01]))


class FileIterationAndPaths(unittest.TestCase):
    def setUp(self):
        self.entries = mft.analyze(mft.iter_mft_file(io.BytesIO(build_mft(sample_records()))))
        self.by = {e.record_number: e for e in self.entries}

    def test_record_numbers_follow_position(self):
        self.assertEqual(sorted(self.by), [5, 16, 17, 18, 19, 20, 21, 22, 23])

    def test_paths(self):
        self.assertEqual(self.by[5].path, "/")
        self.assertEqual(self.by[16].path, "/Users")
        self.assertEqual(self.by[17].path, "/Users/evil.exe")
        self.assertEqual(self.by[22].path, "/Users/LongFileName.txt")

    def test_orphan_and_stale_parent_are_flagged_uncertain(self):
        self.assertTrue(self.by[21].path.startswith("<orphan>"))
        self.assertTrue(self.by[21].path_uncertain)
        self.assertTrue(self.by[23].path_uncertain)
        self.assertEqual(self.by[23].path, "/Users/stale.txt")
        self.assertFalse(self.by[18].path_uncertain)

    def test_deleted_and_summary(self):
        self.assertFalse(self.by[19].in_use)
        s = mft.summarize(self.entries)
        self.assertEqual((s["records"], s["deleted"], s["with_ads"]), (9, 1, 1))

    def test_parent_cycle_terminates(self):
        t = ft(2023, 1, 1, 0, 0, 0, 9)
        recs = {20: file_record("a", 21, 1, t, directory=True), 21: file_record("b", 20, 1, t, directory=True)}
        entries = mft.analyze(mft.iter_mft_file(io.BytesIO(build_mft(recs))))
        self.assertEqual(len(entries), 2)  # must simply return

    def test_record_size_4096(self):
        t = ft(2023, 1, 1, 0, 0, 0, 9)
        rec = build_record(record_size=4096, attrs=[si_attr(t, t, t, t), fn_attr(5, 5, "big.rec", (t,) * 4)])
        entries = list(mft.iter_mft_file(io.BytesIO(rec), record_size=4096))
        self.assertEqual(entries[0].name, "big.rec")


class TimestompTests(unittest.TestCase):
    def setUp(self):
        entries = mft.analyze(mft.iter_mft_file(io.BytesIO(build_mft(sample_records()))))
        self.by = {e.record_number: e for e in entries}

    def test_backdated_file_triggers_ts001_and_ts002(self):
        ids = {i["id"] for i in self.by[17].indicators}
        self.assertEqual(ids, {"TS-001", "TS-002"})

    def test_normal_file_is_clean(self):
        self.assertEqual(self.by[18].indicators, [])

    def test_ts003_mft_change_older_than_modified(self):
        c = ft(2023, 1, 1, 0, 0, 0, 11)
        e = mft.parse_record(
            file_record("x", 5, 1, c, modified=ft(2024, 1, 1, 0, 0, 0, 5), mft_mod=ft(2023, 1, 2, 0, 0, 0, 7),
                        fn_times=(c, c, c, c), size=1), 1)
        self.assertEqual([i["id"] for i in mft.detect_timestomp(e)], ["TS-003"])

    def test_tolerance_suppresses_small_differences(self):
        si_c = ft(2023, 1, 1, 0, 0, 0, 100)
        fn_c = si_c + 5_000_000  # 0.5 s later
        e = mft.parse_record(file_record("x", 5, 1, si_c, fn_times=(fn_c,) * 4, size=1), 1)
        self.assertEqual(mft.detect_timestomp(e, tolerance_seconds=1.0), [])
        self.assertTrue(mft.detect_timestomp(e, tolerance_seconds=0.1))

    def test_no_indicators_when_fn_missing(self):
        raw = build_record(attrs=[si_attr(*(ft(2023, 1, 1, 0, 0, 0, 1),) * 4)])
        self.assertEqual(mft.detect_timestomp(mft.parse_record(raw, 1)), [])


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.entries = mft.analyze(mft.iter_mft_file(io.BytesIO(build_mft(sample_records()))))

    def test_csv_has_header_and_flags(self):
        out = mft.to_csv(self.entries).splitlines()
        self.assertEqual(out[0].split(",")[0], "record")
        row = [l for l in out if "evil.exe" in l][0]
        self.assertIn("TS-001;TS-002", row)
        self.assertEqual(len(out), 1 + len(self.entries))

    def test_bodyfile_format(self):
        lines = mft.to_bodyfile(self.entries).splitlines()
        for l in lines:
            self.assertEqual(len(l.split("|")), 11)
        deleted = [l for l in lines if "gone.doc" in l][0]
        self.assertIn("(deleted)", deleted)
        evil = [l for l in lines if "evil.exe" in l][0].split("|")
        self.assertEqual(evil[10], str(mft.filetime_to_epoch(ft(2019, 1, 1, 12))))  # crtime from $SI

    def test_json_is_valid(self):
        import json

        data = json.loads(mft.to_json(self.entries))
        evil = [d for d in data if d["path"].endswith("evil.exe")][0]
        self.assertEqual({i["id"] for i in evil["indicators"]}, {"TS-001", "TS-002"})


class VolumeTests(unittest.TestCase):
    def test_reads_mft_from_ntfs_volume(self):
        vol = build_volume(sample_records())
        entries = mft.analyze(mft.iter_mft_volume(io.BytesIO(vol)))
        names = {e.name for e in entries}
        self.assertIn("evil.exe", names)
        self.assertIn("$MFT", names)

    def test_partition_offset(self):
        vol = build_volume(sample_records(), partition_offset=2048 * 512)
        entries = list(mft.iter_mft_volume(io.BytesIO(vol), offset=2048 * 512))
        self.assertIn("normal.txt", {e.name for e in entries})

    def test_wrong_offset_gives_helpful_error(self):
        vol = build_volume(sample_records(), partition_offset=4096)
        with self.assertRaises(mft.MftError) as cm:
            list(mft.iter_mft_volume(io.BytesIO(vol), offset=0))
        self.assertIn("--offset", str(cm.exception))

    def test_volume_and_file_results_agree(self):
        recs = sample_records()
        from_file = {e.record_number: e.name for e in mft.iter_mft_file(io.BytesIO(build_mft(recs)))}
        from_vol = {e.record_number: e.name for e in mft.iter_mft_volume(io.BytesIO(build_volume(recs)))}
        for k, v in from_file.items():
            self.assertEqual(from_vol[k], v)


if __name__ == "__main__":
    unittest.main()
