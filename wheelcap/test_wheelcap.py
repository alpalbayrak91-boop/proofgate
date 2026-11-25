import hashlib
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile
from wheelcap import scan, diff, receipt, merkle, sarif, sbom


class WheelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def wheel(self, name, entries):
        path = self.root / (name+".whl")
        with ZipFile(path, "w") as archive:
            for member, data in entries.items():
                archive.writestr(member, data)
        return path

    def test_aliases_and_nonexecution(self):
        f = self.wheel("a", {"demo.py": 'raise RuntimeError("do not execute")\nimport socket as s\ns.gethostname()\n'})
        rows = scan(f)["findings"]
        self.assertEqual({(r["kind"],r["symbol"]) for r in rows}, {("import","socket"),("call","socket.gethostname")})

    def test_change_and_line_shifts(self):
        a = self.wheel("a", {"f.py":"open('a')\n"})
        b = self.wheel("b", {"f.py":"\nopen('a')\nimport socket\n"})
        out = diff(scan(a),scan(b))
        self.assertEqual(out["removed"], [])
        self.assertEqual([r["rule"] for r in out["added"]], ["net"])

    def test_partial_coverage(self):
        f = self.wheel("p", {"lib.so":b"x", "bad.py":"(", "path.pth":"import site\n"})
        report = scan(f)
        self.assertEqual({f["rule"] for f in report["findings"]},{"install_hook","native_ext"})
        self.assertEqual(len(report["warnings"]),2)

    def test_receipt_binds_header(self):
        f = self.wheel("a", {"f.py":"pass"})
        report = scan(f)
        before = receipt(report)
        report["name"] = "changed"
        self.assertNotEqual(receipt(report), before)

    def test_odd_tree(self):
        h=lambda x: hashlib.sha256(x).digest()
        a,b,c=[h(b'\x00'+x) for x in (b'a',b'b',b'c')]
        self.assertEqual(merkle([b'a',b'b',b'c']),h(b'\x01'+h(b'\x01'+a+b)+c))
        self.assertEqual(merkle([]), h(b""))

    def test_source_tree(self):
        src=self.root/"src"; src.mkdir()
        (src/"f.py").write_text("import urllib\n")
        f = self.wheel("a", {"f.py":"import urllib\n"})
        change=diff(scan(src),scan(f))
        self.assertEqual(change["added"],[])
        self.assertEqual(change["removed"],[])

    def test_metadata_and_location(self):
        f=self.wheel("pkg", {"pkg-1.dist-info/METADATA":"Name: pkg\nVersion: 1\n","pkg/m.py":"\nimport socket"})
        report=scan(f)
        self.assertEqual(sbom(report)["metadata"]["component"]["version"],"1")
        loc=sarif(report)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["region"]["startLine"],2)

    def test_ambiguous_paths_rejected(self):
        f=self.wheel("a", {"../outside.py":"pass"})
        with self.assertRaises(ValueError):
            scan(f)


if __name__ == "__main__":
    unittest.main()
