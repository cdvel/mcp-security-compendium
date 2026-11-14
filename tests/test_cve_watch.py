"""Tests for scripts/cve_watch.py and the CVE record checks in scripts/generate.py. No network."""
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import cve_watch  # noqa: E402
import generate  # noqa: E402


def record(rid, name="", summary="", details="", **extra):
    r = {"id": rid, "summary": summary, "details": details,
         "affected": [{"package": {"name": name}}] if name else [], "database_specific": {}}
    r.update(extra)
    return r


class MatcherTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.watch, cls.tracked, cls.excluded = cve_watch.load_state()
        cls.matcher = cve_watch.Matcher(cls.watch, cls.tracked)

    def test_rules_find_tracked_advisories(self):
        # The Claude Code IDE advisory never mentions MCP; it was added by a maintainer and is caught by the watch list.
        misses = {r["id"] for r in self.tracked.values() if not self.matcher.match(r, use_watch=False)}
        self.assertLessEqual(misses, {"GHSA-9f65-56v6-gxw7"})

    def test_watch_list_finds_every_tracked_advisory(self):
        self.assertEqual([r["id"] for r in self.tracked.values() if not self.matcher.match(r)], [])

    def test_mcp_must_be_a_name_token(self):
        for name in ["karma365-mcp", "@go-gost/mcp-darwin-x64", "fast-agent-mcp", "mcp-server-git", "@x/mcp"]:
            self.assertEqual(self.matcher.match(record("X", name)), "name", name)
        for name in ["dowload_ebok_oranges_by_john_mcphee_6dfq3", "lodash"]:
            self.assertIsNone(self.matcher.match(record("X", name)), name)

    def test_text_rules(self):
        self.assertEqual(self.matcher.match(record("X", "tool", "Unauthenticated MCP endpoint")), "text")
        self.assertEqual(self.matcher.match(record("X", "tool", details="writes .cursor/mcp.json")), "text")
        self.assertIsNone(self.matcher.match(record("X", "tool", "RMCPX is not a word match")))

    def test_scope(self):
        self.assertEqual(self.matcher.match(record("X", "@modelcontextprotocol/inspector")), "scope")


class ScanTest(unittest.TestCase):
    def scan(self, records, tracked=None, excluded=frozenset()):
        watch = {"ecosystems": ["npm"], "text": [r"\bMCP\b"], "repos": []}
        feed = {r["id"]: r for r in records}
        orig_ids, orig_get = cve_watch.changed_ids, cve_watch.http_json
        cve_watch.changed_ids = lambda eco, since: iter(feed)
        cve_watch.http_json = lambda url, headers=None: feed[url.rsplit("/", 1)[1][:-5]]
        try:
            return cve_watch.scan("2026-01-01T00:00:00Z", watch, tracked or {}, set(excluded), log=io.StringIO())
        finally:
            cve_watch.changed_ids, cve_watch.http_json = orig_ids, orig_get

    def test_new_candidate_is_pending_with_component_guess(self):
        old = record("GHSA-old", "mcp-x", modified="2026-01-01T00:00:00Z",
                     database_specific={"component": "servers", "summary_short": "Old."})
        new, _ = self.scan([record("GHSA-new", "mcp-x", "flaw")], tracked={"GHSA-old": old})
        db = new["GHSA-new"]["database_specific"]
        self.assertEqual((db["triage"], db["component"]), ("pending", "servers"))

    def test_alias_of_tracked_record_is_not_new(self):
        old = record("GHSA-a", "mcp-x", aliases=["PYSEC-1"], modified="2026-01-01T00:00:00Z",
                     database_specific={"component": "servers", "summary_short": "S."})
        new, updated = self.scan([record("PYSEC-1", "mcp-x", "flaw", aliases=["GHSA-a"])], tracked={"GHSA-a": old})
        self.assertEqual((new, updated), ({}, {}))

    def test_excluded_ids_are_skipped(self):
        new, _ = self.scan([record("GHSA-b", "mcp-y", "flaw", aliases=["CVE-1"])], excluded={"CVE-1"})
        self.assertEqual(new, {})

    def test_update_keeps_compendium_keys_and_flags_withdrawn(self):
        old = record("GHSA-c", "mcp-z", modified="2026-01-01T00:00:00Z",
                     database_specific={"component": "servers", "summary_short": "Kept."})
        fresh = record("GHSA-c", "mcp-z", "changed", modified="2026-02-01T00:00:00Z",
                       withdrawn="2026-02-01T00:00:00Z", database_specific={"severity": "HIGH"})
        _, updated = self.scan([fresh], tracked={"GHSA-c": old})
        db = updated["GHSA-c"]["database_specific"]
        self.assertEqual((db["summary_short"], db["component"], db["severity"]), ("Kept.", "servers", "HIGH"))
        self.assertIn("(withdrawn)", cve_watch.report({}, updated))

    def test_duplicates_and_withdrawn_are_not_new(self):
        new, _ = self.scan([record("GHSA-d", "mcp-a", "Duplicate Advisory: flaw"),
                            record("GHSA-e", "mcp-b", "flaw", withdrawn="2026-03-01T00:00:00Z")])
        self.assertEqual(new, {})

    def test_malware_gets_severity(self):
        new, _ = self.scan([record("MAL-1", "evil-mcp", "Malicious code")])
        self.assertEqual(new["MAL-1"]["database_specific"]["severity"], "MALICIOUS")


class ReportTest(unittest.TestCase):
    def test_untrusted_text_is_neutralized(self):
        text = cve_watch.cell("@octocat <script>|x| `run` [link](http://e) #1")
        for bad in ("@octocat", "<script>", "|x|", "`", "](", "#1"):
            self.assertNotIn(bad, text)


class CheckTest(unittest.TestCase):
    sections = [{"id": "servers"}]

    def test_untriaged_and_incomplete_records_fail(self):
        recs = [record("GHSA-1", database_specific={"component": "servers", "triage": "pending", "summary_short": "S."}),
                record("GHSA-2", database_specific={"component": "", "summary_short": "S."}),
                record("GHSA-3", database_specific={"component": "servers"}),
                record("MAL-1", database_specific={"component": "servers"})]
        errors = generate.check_cves(recs, self.sections)
        self.assertEqual(len(errors), 3)
        self.assertFalse(any(e.startswith("MAL-1") for e in errors))

    def test_tracked_records_pass(self):
        self.assertEqual(generate.check_cves(generate.load_cves(),
                                             generate.yaml.load((generate.DATA / "sections.yml").read_text(),
                                                                generate.Loader)), [])


if __name__ == "__main__":
    unittest.main()
