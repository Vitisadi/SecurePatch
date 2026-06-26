import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "source"))

from app import build_ping_command


class PingTests(unittest.TestCase):
    def test_builds_command_for_plain_host(self):
        # Benign hosts must round-trip unchanged. A safe fix (e.g. shlex.quote)
        # leaves a plain hostname untouched, so this contract survives fixing.
        self.assertEqual(build_ping_command("example.com"), "ping -c 1 example.com")


if __name__ == "__main__":
    unittest.main()
