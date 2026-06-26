import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "source"))

from users import find_user


class FindUserTests(unittest.TestCase):
    def test_finds_existing_user(self):
        self.assertEqual(find_user(1)["name"], "ada")

    def test_missing_user_is_none(self):
        self.assertIsNone(find_user(999))


if __name__ == "__main__":
    unittest.main()
