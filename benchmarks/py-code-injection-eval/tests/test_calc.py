import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "source"))

from calc import evaluate


class CalcTests(unittest.TestCase):
    def test_addition(self):
        self.assertEqual(evaluate("2 + 3"), 5)

    def test_operator_precedence(self):
        # A safe arithmetic evaluator (e.g. an AST walker) must keep precedence.
        self.assertEqual(evaluate("2 + 3 * 4"), 14)


if __name__ == "__main__":
    unittest.main()
