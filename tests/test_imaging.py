import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from fet import imaging


class FlakySource:
    """File-like object that raises OSError for reads touching 'bad' byte ranges."""

    def __init__(self, data: bytes, bad=()):
        self.data, self.bad, self.pos = data, list(bad), 0

    def seek(self, pos, whence=0):
        self.pos = pos
        return pos

    def tell(self):
        return self.pos

    def read(self, n):
        end = self.pos + n
        for lo, hi in self.bad:
            if self.pos < hi and end > lo:
                raise OSError(5, "Input/output error")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk


class AcquireTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.data = os.urandom(3 * 1024 * 1024 + 123)  # not a multiple of the block size
        self.src = self.dir / "evidence.bin"
        self.src.write_bytes(self.data)

    def tearDown(self):
        self.tmp.cleanup()

    def acquire(self, **kw):
        return imaging.acquire(str(self.src), str(self.dir / "out.dd"), case_id="C-1", examiner="A. Tester",
                               block_size=kw.pop("block_size", 1 << 20), **kw)

    def test_hashes_match_independent_computation_and_image_is_identical(self):
        rec = self.acquire(algorithms=("md5", "sha1", "sha256", "sha512"))
        for algo in ("md5", "sha1", "sha256", "sha512"):
            self.assertEqual(rec["acquisition_hashes"][algo], hashlib.new(algo, self.data).hexdigest())
        self.assertEqual((self.dir / "out.dd").read_bytes(), self.data)
        self.assertTrue(rec["verified"])
        self.assertEqual(rec["bytes_acquired"], len(self.data))
        self.assertEqual(rec["bad_ranges"], [])

    def test_custody_record_contents(self):
        rec = self.acquire(notes="laptop #4")
        cf = json.loads(Path(rec["custody_file"]).read_text())
        self.assertEqual((cf["case_id"], cf["examiner"], cf["notes"]), ("C-1", "A. Tester", "laptop #4"))
        self.assertEqual(cf["source"]["size_bytes"], len(self.data))
        self.assertTrue(cf["started_utc"].endswith("Z"))
        self.assertIn("hardware write blocker", cf["write_protection"])

    def test_refuses_to_overwrite_without_flag(self):
        self.acquire()
        with self.assertRaises(imaging.ImagingError):
            self.acquire()
        self.acquire(overwrite=True)  # explicit opt-in works

    def test_refuses_same_file(self):
        with self.assertRaises(imaging.ImagingError):
            imaging.acquire(str(self.src), str(self.src), case_id="C", examiner="E", overwrite=True)

    def test_requires_case_and_examiner(self):
        with self.assertRaises(imaging.ImagingError):
            imaging.acquire(str(self.src), str(self.dir / "o"), case_id="", examiner="E")

    def test_unknown_hash_and_missing_source(self):
        with self.assertRaises(imaging.ImagingError):
            self.acquire(algorithms=("crc32",))
        with self.assertRaises(imaging.ImagingError):
            imaging.acquire(str(self.dir / "nope"), str(self.dir / "o"), case_id="C", examiner="E")

    def test_source_is_not_modified(self):
        before = hashlib.sha256(self.src.read_bytes()).hexdigest()
        self.acquire()
        self.assertEqual(hashlib.sha256(self.src.read_bytes()).hexdigest(), before)


class BadSectorTests(unittest.TestCase):
    def test_bad_sectors_are_zero_filled_and_recorded(self):
        data = bytes([0xAA]) * 4096
        src = FlakySource(data, bad=[(1024, 1536)])  # exactly one sector
        import io

        dst = io.BytesIO()
        hs = imaging._hashers(["sha256"])
        written, bad = imaging.copy_stream(src, dst, len(data), hs, block_size=2048)
        out = dst.getvalue()
        self.assertEqual(written, 4096)
        self.assertEqual(bad, [{"offset": 1024, "length": 512}])
        self.assertEqual(out[1024:1536], b"\x00" * 512)
        self.assertEqual(out[:1024], data[:1024])
        self.assertEqual(out[1536:], data[1536:])
        self.assertEqual(hs["sha256"].hexdigest(), hashlib.sha256(out).hexdigest())  # hash covers zero-fill

    def test_adjacent_bad_sectors_merge(self):
        import io

        src = FlakySource(b"\x01" * 4096, bad=[(512, 1536)])
        _, bad = imaging.copy_stream(src, io.BytesIO(), 4096, imaging._hashers(["md5"]), block_size=4096)
        self.assertEqual(bad, [{"offset": 512, "length": 1024}])

    def test_source_that_ends_early_is_an_error(self):
        import io

        src = FlakySource(b"\x01" * 1000)
        with self.assertRaises(imaging.ImagingError):
            imaging.copy_stream(src, io.BytesIO(), 4096, imaging._hashers(["md5"]), block_size=512)


class VerifyTests(unittest.TestCase):
    def test_detects_tampering(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d, "s"), Path(d, "i.dd")
            src.write_bytes(os.urandom(200_000))
            rec = imaging.acquire(str(src), str(dst), case_id="C", examiner="E")
            self.assertTrue(imaging.verify(str(dst), rec["custody_file"])["ok"])
            raw = bytearray(dst.read_bytes())
            raw[1000] ^= 0x01  # single bit flip
            dst.write_bytes(bytes(raw))
            res = imaging.verify(str(dst), rec["custody_file"])
            self.assertFalse(res["ok"])
            self.assertEqual(sorted(res["mismatches"]), ["md5", "sha256"])

    def test_missing_custody_file(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "x").write_bytes(b"1")
            with self.assertRaises(imaging.ImagingError):
                imaging.verify(str(Path(d, "x")))


if __name__ == "__main__":
    unittest.main()
