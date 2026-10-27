import json
import tempfile
import unittest
from pathlib import Path

from hardn import deps, prompt, scanner, scoring
from hardn.models import Finding
from hardn.secrets import _scan_line

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"


class ScanExampleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._home = deps.HOME
        deps.HOME = Path(tempfile.mkdtemp())  # no advisory DB: dependency engine reports, doesn't crash
        cls.result = scanner.run(str(EXAMPLE), external=False)
        cls.ids = {f.rule_id for f in cls.result.findings}

    @classmethod
    def tearDownClass(cls):
        deps.HOME = cls._home

    def test_detects_core_vulns(self):
        # Line-rule hits merge into the richer taint finding for the same CWE on the same line.
        for rid in ("SEC001", "SEC100", "SEC010", "SEC200", "PYT001", "PYT002", "PYT004", "PYT005", "PYT007",
                    "JST001", "JST002", "JST003", "JST004", "JST005", "JST007", "JST008", "DK002", "POS020", "POS003"):
            self.assertIn(rid, self.ids, rid)

    def test_multiline_flows(self):
        flows = {f.location(): f.extra.get("flow", "") for f in self.result.findings}
        self.assertIn("customer", flows["app.py:55"])       # request.args → customer → query → execute()
        self.assertIn("route param `name`", flows["app.py:61"])
        self.assertIn("sql (L57)", flows["server.js:58"])  # destructured req.query → sql → db.query

    def test_stack(self):
        self.assertIn("Express", self.result.stack["frameworks"])
        self.assertIn("Flask", self.result.stack["frameworks"])

    def test_secrets_never_leak_into_prompt_or_report(self):
        text, _, _ = prompt.build(self.result)
        dump = json.dumps([f.to_dict() for f in self.result.findings])
        for raw in ("AKIAZ7Q3HN4LXW2PVT6B", "Sup3rS3cretPw", "9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c", "hunter2-prod-Xk29fQ"):  # hardn:ignore test fixture
            self.assertNotIn(raw, text)
            self.assertNotIn(raw, dump)

    def test_prompt_targets_baseline_from_exposed(self):
        text, target, n = prompt.build(self.result)
        self.assertEqual(scoring.level(self.result.findings), 0)
        self.assertEqual(target, 2)
        self.assertIn("reach **L2 Baseline**", text)
        self.assertGreater(n, 5)
        self.assertNotIn("POS031", text)  # info-level items are not in scope

    def test_no_duplicate_locations_per_rule(self):
        seen = [(f.rule_id, f.file, f.line) for f in self.result.findings]
        self.assertEqual(len(seen), len(set(seen)))


class SecretHeuristicsTest(unittest.TestCase):
    def test_placeholders_ignored(self):
        for line in ('password = "changeme123"', 'API_KEY = os.environ["API_KEY"]', 'token: "${TOKEN_VALUE}"',
                     'password_field = "user_password_input"', 'apiKey: "YOUR_API_KEY_HERE"'):
            self.assertEqual(_scan_line("x.py", 1, line), [], line)

    def test_real_values_caught_and_redacted(self):
        out = _scan_line("x.py", 1, 'client_secret = "q8Fz2LmN9vXw4RtY7"')  # hardn:ignore test fixture
        self.assertEqual(len(out), 1)
        self.assertNotIn("q8Fz2LmN9vXw4RtY7", out[0].snippet)

    def test_anthropic_key_not_double_reported(self):
        out = _scan_line("x.ts", 1, 'const k = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"')  # hardn:ignore test fixture
        self.assertEqual([f.rule_id for f in out], ["SEC005"])


class VersionTest(unittest.TestCase):
    def test_ordering(self):
        k = deps.vkey
        self.assertLess(k("1.0.0-beta.1"), k("1.0.0"))
        self.assertLess(k("1.0rc1"), k("1.0"))
        self.assertEqual(k("1.0"), k("1.0.0"))
        self.assertLess(k("1.0.0"), k("1.0.post1"))
        self.assertLess(k("1.0.post1"), k("1.0.1"))
        self.assertLess(k("v1.9.9"), k("v1.10.0"))

    def test_ranges(self):
        aff = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}
        self.assertTrue(deps.is_affected("4.17.15", aff))
        self.assertFalse(deps.is_affected("4.17.21", aff))
        aff = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.3.0"}]}]}
        self.assertTrue(deps.is_affected("2.3.0", aff))
        self.assertFalse(deps.is_affected("1.9.0", aff))


class OfflineDbTest(unittest.TestCase):
    def test_dependency_finding_with_kev_escalation(self):
        tmp = Path(tempfile.mkdtemp())
        db = tmp / "osv.sqlite"
        con = deps._connect(db)
        affected = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}
        con.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?)",
                    ("npm", "lodash", "GHSA-test", "Prototype pollution", "high", json.dumps(["CVE-2099-0001"]),
                     json.dumps(affected)))
        con.execute("INSERT INTO kev VALUES ('CVE-2099-0001')")
        con.commit()
        con.close()
        (tmp / "package-lock.json").write_text(json.dumps(
            {"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}}}))
        findings, _ = deps.scan(str(tmp), ["package-lock.json"], db=db)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "critical")  # escalated: actively exploited
        self.assertEqual(f.extra["fixed_in"], "4.17.21")
        self.assertIn("actively exploited", f.title)


class LevelTest(unittest.TestCase):
    def mk(self, sev):
        return Finding("X", "x", sev, "code")

    def test_levels(self):
        self.assertEqual(scoring.level([]), 4)
        self.assertEqual(scoring.level([self.mk("info")]), 4)
        self.assertEqual(scoring.level([self.mk("low")]), 3)
        self.assertEqual(scoring.level([self.mk("medium"), self.mk("low")]), 2)
        self.assertEqual(scoring.level([self.mk("high")]), 1)
        self.assertEqual(scoring.level([self.mk("critical"), self.mk("low")]), 0)


if __name__ == "__main__":
    unittest.main()
