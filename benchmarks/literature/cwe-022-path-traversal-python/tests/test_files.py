import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "source"))

from files import read_document


class ReadDocumentTests(unittest.TestCase):
    def test_reads_a_known_document(self):
        # A containment fix still serves legitimate documents unchanged.
        self.assertEqual(read_document("hello.txt").strip(), "hello world")


if __name__ == "__main__":
    unittest.main()
