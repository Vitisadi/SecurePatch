import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "source"))

from fingerprint import fingerprint


class FingerprintTests(unittest.TestCase):
    def test_deterministic(self):
        # Any hash algorithm is deterministic, so a fix (e.g. sha256) keeps this.
        self.assertEqual(fingerprint("hello"), fingerprint("hello"))

    def test_distinct_inputs_differ(self):
        self.assertNotEqual(fingerprint("hello"), fingerprint("world"))


if __name__ == "__main__":
    unittest.main()
