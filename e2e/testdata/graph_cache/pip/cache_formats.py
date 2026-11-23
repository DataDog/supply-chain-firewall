import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pip._vendor import msgpack
from pip._vendor.cachecontrol.controller import CacheController


class CacheFormats(unittest.TestCase):
    url = "https://files.pythonhosted.org/packages/example.whl"
    body = b"exact cached artifact bytes"
    inspector = Path(__file__).with_name("inspect_cache.py")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def entry(self, layout, body=None):
        key = hashlib.sha224(CacheController.cache_url(self.url).encode()).hexdigest()
        path = self.root / layout / Path(*key[:5]) / key
        path.parent.mkdir(parents=True, exist_ok=True)
        value = self.body if body is None else body
        path.write_bytes(b"cc=4," + msgpack.dumps({"response": {"body": value}}, use_bin_type=True))
        return path

    def inspect(self, failure=False):
        before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.root.rglob("*") if p.is_file()}
        command = subprocess.run([sys.executable, str(self.inspector), str(self.root), self.url],
                                 capture_output=True, text=True, timeout=10,
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        after = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after, "cache inspection changed native cache files")
        if failure:
            self.assertNotEqual(command.returncode, 0, command.stdout)
            return
        self.assertEqual(command.returncode, 0, command.stderr)
        return json.loads(command.stdout)[self.url]

    def expected(self, body=None):
        value = self.body if body is None else body
        return {"present": True, "sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}

    def test_inline_legacy_body(self):
        self.entry("http")
        self.assertEqual(self.inspect(), self.expected())

    def test_separate_current_body(self):
        path = self.entry("http-v2", b"")
        Path(str(path) + ".body").write_bytes(self.body)
        self.assertEqual(self.inspect(), self.expected())

    def test_current_layout_takes_precedence(self):
        self.entry("http", b"older body")
        path = self.entry("http-v2", b"")
        Path(str(path) + ".body").write_bytes(self.body)
        self.assertEqual(self.inspect(), self.expected())

    def test_missing_entries(self):
        self.assertEqual(self.inspect(), {"present": False})

    def test_missing_separate_body(self):
        self.entry("http-v2", b"")
        self.assertEqual(self.inspect(), {"present": False})

    def test_unknown_serialization_fails(self):
        path = self.entry("http-v2", b"")
        path.write_bytes(b"cc=99,unknown")
        Path(str(path) + ".body").write_bytes(self.body)
        self.inspect(failure=True)

    def test_malformed_metadata_fails(self):
        path = self.entry("http-v2", b"")
        path.write_bytes(b"cc=4,\xc1")
        Path(str(path) + ".body").write_bytes(self.body)
        self.inspect(failure=True)

    def test_invalid_inline_body_fails(self):
        self.entry("http", "not bytes")
        self.inspect(failure=True)

    def test_oversized_metadata_fails(self):
        path = self.entry("http-v2", b"")
        path.write_bytes(b"cc=4," + b"x" * (17 * 1024 * 1024))
        Path(str(path) + ".body").write_bytes(self.body)
        self.inspect(failure=True)

    def test_oversized_body_fails(self):
        path = self.entry("http-v2", b"")
        Path(str(path) + ".body").write_bytes(b"x" * (16 * 1024 * 1024 + 1))
        self.inspect(failure=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
