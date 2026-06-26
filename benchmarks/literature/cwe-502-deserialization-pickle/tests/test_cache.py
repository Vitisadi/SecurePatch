import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "source"))

from cache import serialize, load_cached


class CacheTests(unittest.TestCase):
    def test_round_trips_a_value(self):
        # A safe serializer (e.g. JSON) still round-trips plain data.
        self.assertEqual(load_cached(serialize({"a": 1})), {"a": 1})


if __name__ == "__main__":
    unittest.main()
