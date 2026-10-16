import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from textkit.slug import slugify, word_count  # noqa: E402


class SlugTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(slugify("Hello, World!"), "hello-world")

    def test_accents(self):
        self.assertEqual(slugify("Crème Brûlée Recipes"), "creme-brulee-recipes")

    def test_whitespace(self):
        self.assertEqual(slugify("  Release   Notes 2026  "), "release-notes-2026")

    def test_word_count(self):
        self.assertEqual(word_count("one two  three"), 3)


if __name__ == "__main__":
    unittest.main()
