import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bot.standup import load_config, summary, target_chat  # noqa: E402


class StandupTests(unittest.TestCase):
    def test_summary_goes_to_team_group(self):
        config = load_config()
        self.assertEqual(target_chat(config), config["telegram"]["team_chat_id"])

    def test_summary_lists_prs(self):
        self.assertIn("- Add CSV export", summary(["Add CSV export"]))

    def test_empty_summary(self):
        self.assertEqual(summary([]), "Standup: nothing merged yesterday.")


if __name__ == "__main__":
    unittest.main()
