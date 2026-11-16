"""Tests for scripts/refresh.py. No network."""
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import refresh  # noqa: E402

TODAY = datetime(2026, 11, 16, tzinfo=timezone.utc)


def facts(stars=500, contributors=20, pushed="2026-11-01T00:00:00Z", created="2025-01-01T00:00:00Z", archived=False):
    return {"stars": stars, "contributors": contributors, "pushed_at": pushed, "created_at": created,
            "archived": archived, "full_name": "o/r", "license": "MIT"}


class JudgeTest(unittest.TestCase):
    def test_signals_that_hold_are_kept(self):
        keep, notes = refresh.judge(["stars", "contributors", "active"], facts(), TODAY)
        self.assertEqual((keep, notes), (["stars", "contributors", "active"], []))

    def test_lapsed_signals_are_dropped(self):
        keep, notes = refresh.judge(["stars", "contributors", "active", "research_lab"],
                                    facts(stars=40, contributors=2, pushed="2026-01-01T00:00:00Z"), TODAY)
        self.assertEqual(keep, ["research_lab"])
        self.assertEqual(len([n for n in notes if n.startswith("dropped")]), 3)
        self.assertNotIn("**below the inclusion bar**", notes)

    def test_below_bar_and_stale_are_flagged(self):
        _, notes = refresh.judge(["stars"], facts(stars=150, pushed="2025-06-01T00:00:00Z"), TODAY)
        self.assertIn("**below the inclusion bar**", notes)
        self.assertTrue(any(n.startswith("**no push for 12 months**") for n in notes))

    def test_archived_is_noted_not_flagged(self):
        _, notes = refresh.judge(["stars", "contributors"], facts(pushed="2025-06-01T00:00:00Z", archived=True), TODAY)
        self.assertEqual(notes, ["archived"])

    def test_two_supporting_signals_meet_the_bar(self):
        _, notes = refresh.judge(["stars", "contributors"], facts(stars=150, contributors=5), TODAY)
        self.assertEqual(notes, [])

    def test_new_repos_are_not_active(self):
        keep, _ = refresh.judge(["active"], facts(created="2026-10-01T00:00:00Z"), TODAY)
        self.assertEqual(keep, [])


class SetFieldTest(unittest.TestCase):
    text = "title: X\nurl: https://github.com/o/r\nsignals: [stars]\ndescription: Y.\n"

    def test_replaces_an_existing_line(self):
        self.assertIn("signals: [contributors]\n", refresh.set_field(self.text, "signals", "[contributors]"))

    def test_adds_a_missing_field_before_description(self):
        out = refresh.set_field(self.text, "stars", 12)
        self.assertTrue(out.endswith("stars: 12\ndescription: Y.\n"))


if __name__ == "__main__":
    unittest.main()
