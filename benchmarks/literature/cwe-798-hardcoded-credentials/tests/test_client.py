import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "source"))

from client import get_api_key


class ClientTests(unittest.TestCase):
    def test_environment_key_is_used(self):
        # The supported configuration path is an env var; a fix that removes the
        # hard-coded fallback keeps this behaviour.
        os.environ["BILLING_API_KEY"] = "from-env"
        try:
            self.assertEqual(get_api_key(), "from-env")
        finally:
            del os.environ["BILLING_API_KEY"]


if __name__ == "__main__":
    unittest.main()
