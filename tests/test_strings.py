import io
import unittest

from fet import strings_ioc as s


def run(data: bytes, chunk: int, min_len=6):
    return list(s.iter_strings(io.BytesIO(data), min_len, chunk))


class StringTests(unittest.TestCase):
    def test_ascii_and_utf16(self):
        data = b"\x00\x00hello world\x00\x01" + "wide string".encode("utf-16le") + b"\x00\x00ab\x00"
        out = run(data, 1 << 20)
        self.assertIn((2, "ascii", "hello world"), out)
        wide = [x for x in out if x[1] == "utf16le"]
        self.assertEqual(wide[0][2], "wide string")
        self.assertEqual(wide[0][0], 2 + len("hello world") + 2)
        self.assertFalse(any(t == "ab" for _, _, t in out))  # below min length

    def test_chunk_boundaries_do_not_split_or_duplicate(self):
        data = (b"\x00" * 7 + b"alpha-string-1" + b"\x00" * 3 + "beta-wide-two".encode("utf-16le")
                + b"\x00\x00" + b"gamma-ascii-3" + b"\xff" * 5 + b"tail-string")
        expected = sorted(run(data, 1 << 20))
        self.assertEqual(len(expected), 4)
        for chunk in (1, 2, 3, 5, 7, 8, 13, 16, 31):
            # order between ASCII/UTF-16 hits may differ with chunking; the *set* must not
            self.assertEqual(sorted(run(data, chunk)), expected, f"chunk={chunk}")

    def test_offsets_are_absolute(self):
        data = b"\x00" * 100 + b"findme-please"
        self.assertEqual(run(data, 10)[0][0], 100)

    def test_empty_input(self):
        self.assertEqual(run(b"", 16), [])


class IocTests(unittest.TestCase):
    def iocs(self, text, **kw):
        return s.extract_iocs(iter([(0, "ascii", text)]), **kw)

    def test_url_email_ip_registry(self):
        r = self.iocs("GET http://evil.example/payload.bin from 93.184.216.34 mail bob@corp.test "
                      r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\x")
        self.assertEqual(r["url"][0]["value"], "http://evil.example/payload.bin")
        self.assertEqual(r["ipv4"][0]["value"], "93.184.216.34")
        self.assertEqual(r["email"][0]["value"], "bob@corp.test")
        self.assertTrue(r["registry_key"][0]["value"].startswith("HKEY_CURRENT_USER"))

    def test_private_ips_hidden_by_default(self):
        text = "10.0.0.5 192.168.1.1 127.0.0.1 8.8.8.8"
        self.assertEqual([x["value"] for x in self.iocs(text)["ipv4"]], ["8.8.8.8"])
        self.assertEqual(len(self.iocs(text, public_ips_only=False)["ipv4"]), 4)

    def test_version_numbers_are_not_ips(self):
        self.assertEqual(self.iocs("module v8.8.8.8 loaded")["ipv4"], [])

    def test_counts_and_first_offset(self):
        r = s.extract_iocs(iter([(5, "ascii", "http://a.test/x"), (99, "ascii", "http://a.test/x")]))
        self.assertEqual((r["url"][0]["count"], r["url"][0]["first_offset"]), (2, 5))


if __name__ == "__main__":
    unittest.main()
