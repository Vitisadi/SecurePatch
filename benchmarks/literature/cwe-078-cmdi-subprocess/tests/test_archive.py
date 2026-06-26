import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "source"))

from archive import build_tar_command


class ArchiveTests(unittest.TestCase):
    def test_builds_command_for_plain_path(self):
        # A safe path (e.g. shlex.quote) leaves an ordinary filename untouched.
        self.assertEqual(build_tar_command("report.txt"), "tar czf archive.tgz report.txt")


if __name__ == "__main__":
    unittest.main()
