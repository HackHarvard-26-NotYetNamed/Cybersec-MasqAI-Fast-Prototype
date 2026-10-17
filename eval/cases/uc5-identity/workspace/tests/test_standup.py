import unittest

from bot.standup import target_chat


class StandupTests(unittest.TestCase):
    def test_summary_goes_to_team_group(self):
        self.assertEqual(target_chat(), -1002213874410)


if __name__ == "__main__":
    unittest.main()
