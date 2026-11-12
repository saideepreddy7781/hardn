"""The shared guarantees everything else builds on."""
import os
import subprocess
import tempfile
import unittest

from agentharden import context, gitsafe, scoring
from agentharden.models import Finding


def _git(root, *args):
    subprocess.run(["git", "-C", root, "-c", "user.email=t@t", "-c", "user.name=t", *args], check=True,
                   capture_output=True)


@unittest.skipIf(os.name == "nt", "the planted programs are POSIX shell scripts")
class GitSafeTests(unittest.TestCase):
    """A repo's own .git/config must never make agentharden run a program."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "repo")
        os.makedirs(self.root)
        self.marker = os.path.join(self.tmp.name, "pwned")
        self.evil = os.path.join(self.tmp.name, "evil.sh")
        with open(self.evil, "w") as fh:
            fh.write(f'#!/bin/sh\ntouch "{self.marker}"\nexit 0\n')
        os.chmod(self.evil, 0o755)
        _git(self.root, "init", "-q")
        with open(os.path.join(self.root, "a.txt"), "w") as fh:
            fh.write("one\n")
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-qm", "init")

    def _set(self, key):
        _git(self.root, "config", key, self.evil)

    def _touch_worktree(self):
        with open(os.path.join(self.root, "a.txt"), "w") as fh:
            fh.write("two\n")

    def assertNoExecution(self, *args):
        proc = gitsafe.run(self.root, *args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.marker), f"git {args} ran a repo-defined program")

    def test_control_plain_git_runs_the_planted_fsmonitor(self):
        """Proves the planted config is live, so the tests below mean something."""
        self._set("core.fsmonitor")
        subprocess.run(["git", "-C", self.root, "status", "--porcelain"], capture_output=True, check=False,
                       stdin=subprocess.DEVNULL, timeout=20)
        self.assertTrue(os.path.exists(self.marker))

    def test_fsmonitor_blocked(self):
        self._set("core.fsmonitor")
        self.assertNoExecution("status", "--porcelain")

    def test_clean_filter_blocked(self):
        with open(os.path.join(self.root, ".gitattributes"), "w") as fh:
            fh.write("*.txt filter=x\n")
        self._set("filter.x.clean")
        self._touch_worktree()
        self.assertNoExecution("diff", "--no-color")

    def test_external_diff_blocked(self):
        self._set("diff.external")
        self._touch_worktree()
        self.assertNoExecution("diff", "--no-color")

    def test_textconv_blocked(self):
        with open(os.path.join(self.root, ".gitattributes"), "w") as fh:
            fh.write("*.txt diff=x\n")
        self._set("diff.x.textconv")
        self._touch_worktree()
        self.assertNoExecution("diff", "--no-color")

    def test_hooks_blocked(self):
        hook = os.path.join(self.root, ".git", "hooks", "post-checkout")
        with open(hook, "w") as fh:
            fh.write(f'#!/bin/sh\ntouch "{self.marker}"\n')
        os.chmod(hook, 0o755)
        self.assertNoExecution("switch", "-q", "-c", "other")

    def test_odd_subsection_is_refused(self):
        _git(self.root, "config", "filter.a=b.clean", self.evil)
        with self.assertRaises(OSError):
            gitsafe.run(self.root, "status")


class ContextTests(unittest.TestCase):
    def test_classify(self):
        cases = {
            "src/app.py": "app", "app/views/admin.py": "app", "tests/test_a.py": "test", "src/a.test.ts": "test",
            "docs/howto.py": "docs", "README.md": "docs", "examples/x/app.js": "example",
            "third_party/x.js": "vendor", "packages/next/src/compiled/a.js": "vendor",
            "src/__generated__/a.ts": "generated", "api_pb2.py": "generated", "docs_src/a.py": "docs",
            "cypress/e2e/a.js": "test",
        }
        for path, want in cases.items():
            self.assertEqual(context.classify(path), want, path)


class ScoringTests(unittest.TestCase):
    def _f(self, severity, category="code", ctx="app"):
        return Finding("X", "t", severity, category, context=ctx)

    def test_docs_do_not_set_the_level(self):
        self.assertEqual(scoring.level([self._f("critical", ctx="docs")]), 4)
        self.assertEqual(scoring.score([self._f("critical", ctx="docs")]), 100)

    def test_secret_in_tests_still_counts(self):
        self.assertEqual(scoring.level([self._f("critical", "secret", "test")]), 0)

    def test_sample_key_in_docs_does_not_count_but_provider_key_does(self):
        self.assertEqual(scoring.level([Finding("SEC100", "t", "high", "secret", context="docs")]), 4)
        self.assertEqual(scoring.level([Finding("SEC001", "t", "critical", "secret", context="example")]), 0)

    def test_dev_dependency_does_not_set_the_level(self):
        self.assertEqual(scoring.level([self._f("critical", "dependency", "dev-dependency")]), 4)

    def test_gaps_cap_the_level(self):
        self.assertEqual(scoring.level([], gaps=["no advisory data"]), scoring.INCOMPLETE_MAX_LEVEL)
        self.assertEqual(scoring.level([self._f("critical")], gaps=["x"]), 0)


if __name__ == "__main__":
    unittest.main()
