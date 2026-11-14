"""Checks that the comparator cannot hide failures, output drift or missing functions."""
import tempfile
from pathlib import Path
import unittest

from regression import compare, sha256


class RegressionTests(unittest.TestCase):
    def row(self, name="NtClose", digest="same", error=None):
        return {"name": name, "sha256": digest, "error": error}

    def test_equal_output_including_known_failure(self):
        rows = [self.row(), self.row("KiChainedDispatch", error="call analysis failed")]
        self.assertEqual(compare(rows, rows), [])

    def test_output_and_error_changes_are_detected(self):
        for changed in (self.row(digest="changed"), self.row(error="decompile failed")):
            with self.subTest(changed=changed):
                self.assertEqual(compare([self.row()], [changed]), ["NtClose"])

    def test_missing_and_reordered_functions_are_rejected(self):
        rows = [self.row(), self.row("NtCreateFile")]
        for changed in (rows[:1], rows[::-1]):
            with self.assertRaisesRegex(ValueError, "names/order"):
                compare(rows, changed)

    def test_content_hash_detects_corruption(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pseudocode.c"
            path.write_bytes(b"original")
            before = sha256(path)
            path.write_bytes(b"changed")
            self.assertNotEqual(before, sha256(path))


if __name__ == "__main__":
    unittest.main()
