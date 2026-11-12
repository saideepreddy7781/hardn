"""Honest results: blind spots, hidden counts, hostile trees, --diff, baselines, SARIF, rules and CI files."""
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from agentharden import __version__, baseline, cli, deps, gitdiff, output, scanner, taint_py, walker
from agentharden.models import Finding

ROOT = Path(__file__).resolve().parent.parent
GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
SHELL_LINE = "subprocess.run(c, shell=True)\n"  # PY002, high


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV,
                   stdin=subprocess.DEVNULL, timeout=60)


def repo(files: dict, commit: bool = True) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    git(root, "init", "-q", "-b", "main")
    if commit:
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "init")
    return root


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(args))
    return rc, out.getvalue(), err.getvalue()


def run_proc(*args, timeout=60):
    env = {**os.environ, "PYTHONPATH": str(ROOT), "AGENTHARDEN_HOME": tempfile.mkdtemp()}
    return subprocess.run([sys.executable, "-m", "agentharden", *args], check=False, capture_output=True, text=True,
                          timeout=timeout, env=env, stdin=subprocess.DEVNULL, cwd=tempfile.gettempdir())


class _NoDb(unittest.TestCase):
    def setUp(self):
        self._home = deps.HOME
        deps.HOME = Path(tempfile.mkdtemp())
        self.addCleanup(setattr, deps, "HOME", self._home)


class HonestOutputTest(_NoDb):
    def _crash(self, files):
        raise RecursionError("too deep")

    def test_gap_marks_scan_incomplete_everywhere(self):
        root = repo({"a.py": "x = 1\n", ".gitignore": ".agentharden/\n"})
        with mock.patch.object(taint_py, "scan", self._crash):
            rc, out, _ = run_cli("scan", str(root), "--no-external")
            self.assertEqual(rc, 0)
            self.assertIn("Blind spots", out)
            self.assertIn("incomplete", out)
            self.assertNotIn("No issues found", out)
            self.assertNotIn("Top level reached", out)
            report = json.loads((root / ".agentharden" / "report.json").read_text())
            self.assertFalse(report["complete"])
            self.assertLessEqual(report["level"], 2)
            self.assertTrue(any("Python taint" in g for g in report["gaps"]))
            rc, _, err = run_cli("scan", str(root), "--no-external", "-q", "--strict")
            self.assertEqual(rc, 3)
            self.assertIn("blind spot", err)

    def test_findings_outside_app_code_do_not_fail(self):
        root = repo({"docs/howto.py": SHELL_LINE, "app.py": "x = 1\n"})
        rc, out, _ = run_cli("scan", str(root), "--no-external", "--fail-on", "high")
        self.assertEqual(rc, 0, out)
        self.assertIn("Outside app code", out)
        rc, _, _ = run_cli("scan", str(root), "--no-external", "--fail-on", "high", "--untrusted")
        self.assertEqual(rc, 1)  # --untrusted counts every context

    def test_hidden_counts_are_reported(self):
        root = repo({"a.py": SHELL_LINE + "subprocess.run(d, shell=True)  # agentharden:ignore\n" + "y = 2\n",
                     "gen/x.py": SHELL_LINE, "gen/y.py": "z = 1\n", ".agentharden-ignore": "gen\n"})
        run_cli("baseline", str(root), "--no-external")
        rc, out, _ = run_cli("scan", str(root), "--no-external", "--fail-on", "high")
        self.assertEqual(rc, 0, out)
        self.assertIn("1 suppressed inline · 2 files excluded by .agentharden-ignore · ", out)
        report = json.loads((root / ".agentharden" / "report.json").read_text())
        self.assertEqual(report["hidden"]["inline"], 1)
        self.assertEqual(report["hidden"]["ignorefile"], 2)
        self.assertGreaterEqual(report["hidden"]["baselined"], 1)

    def test_untrusted_ignores_repo_config(self):
        root = repo({"a.py": "subprocess.run(d, shell=True)  # agentharden:ignore\n", ".agentharden-ignore": "*\n"})
        run_cli("baseline", str(root), "--no-external")
        rc, _, _ = run_cli("scan", str(root), "--no-external", "--fail-on", "high")
        self.assertEqual(rc, 0)
        rc, out, _ = run_cli("scan", str(root), "--no-external", "--fail-on", "high", "--untrusted")
        self.assertEqual(rc, 1, out)
        self.assertIn("PY002", out)
        rc, _, err = run_cli("scan", str(root), "--untrusted", "--baseline", str(root / baseline.FILENAME))
        self.assertEqual(rc, 2)
        self.assertIn("--untrusted", err)

    @unittest.skipIf(os.name == "nt", "Windows does not allow control characters in file names")
    def test_terminal_escapes_are_stripped(self):
        root = repo({"a.py": "x = 1\n"}, commit=False)
        (root / "e\x1b]0;pwned\x07.py").write_text("subprocess.run(c, shell=True)  # \x1b[2J\x9b\n")
        rc, out, _ = run_cli("scan", str(root), "--no-external", "-v")
        self.assertEqual(rc, 0)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertNotIn("\x9b", out)
        self.assertIn("e?]0;pwned?.py", out)


@unittest.skipIf(os.name == "nt", "POSIX file types")
class HostileTreeTest(unittest.TestCase):
    def test_fifo_device_link_and_unreadable_file(self):
        root = repo({"a.py": SHELL_LINE}, commit=False)
        os.mkfifo(root / "pipe.py")
        os.symlink("/dev/zero", root / "zero.py")
        outside = Path(tempfile.mkdtemp()) / "secret.py"
        outside.write_text('k = "AKIAZ7Q3LMPX4RTY8WQD"\n')  # agentharden:ignore test fixture
        os.symlink(outside, root / "escape.py")
        os.symlink("a.py", root / "alias.py")
        (root / "big.js").write_text("x" * (walker.MAX_BYTES + 10))
        locked = root / "locked.py"
        locked.write_text("x = 1\n")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o600)
        proc = run_proc("scan", str(root), "--no-external", "-q", timeout=60)  # a hang fails here
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads((root / ".agentharden" / "report.json").read_text())
        sk = report["skipped"]
        self.assertIn("pipe.py", sk["special"]["paths"])
        self.assertIn("zero.py", sk["symlinks"]["paths"])
        self.assertIn("escape.py", sk["symlinks"]["paths"])
        self.assertIn("big.js", sk["oversize"]["paths"])
        self.assertNotIn("alias.py", sk["symlinks"]["paths"])  # inside the root: listed, its target is scanned
        self.assertFalse(any(f["file"] in ("escape.py", "alias.py") for f in report["findings"]))
        if os.geteuid() != 0:
            self.assertIn("locked.py", sk["unreadable"]["paths"])
            self.assertFalse(report["complete"])

    def test_env_and_build_are_walked_unless_generated(self):
        root = repo({"config/env/all.js": "x\n", "src/build/index.ts": "x\n", "env/pyvenv.cfg": "home = /usr\n",
                     "env/lib/x.py": "x\n", "build/CMakeCache.txt": "x\n", "build/gen.c": "x\n"}, commit=False)
        report = walker.WalkReport()
        files, _ = walker.walk(str(root), report=report)
        paths = {f.path for f in files}
        self.assertIn("config/env/all.js", paths)
        self.assertIn("src/build/index.ts", paths)
        self.assertNotIn("env/lib/x.py", paths)
        self.assertEqual(sorted(report.generated_dirs), ["build", "env"])

    def _victim(self):
        victim = Path(tempfile.mkdtemp())
        (victim / "report.json").write_text("victim\n")
        return victim

    def test_symlinked_output_dir_is_refused(self):
        root = repo({"a.py": SHELL_LINE})
        victim = self._victim()
        os.symlink(victim, root / ".agentharden")
        rc, _, err = run_cli("scan", str(root), "--no-external", "-q")
        self.assertEqual(rc, 2)
        self.assertIn("symlink", err)
        self.assertEqual(sorted(os.listdir(victim)), ["report.json"])
        self.assertEqual((victim / "report.json").read_text(), "victim\n")

    def test_symlinked_output_file_is_refused(self):
        root = repo({"a.py": SHELL_LINE})
        victim = self._victim()
        (root / ".agentharden").mkdir()
        os.symlink(victim / "report.json", root / ".agentharden" / "report.json")
        rc, _, err = run_cli("scan", str(root), "--no-external", "-q")
        self.assertEqual(rc, 2, err)
        self.assertEqual((victim / "report.json").read_text(), "victim\n")

    def test_gitignore_overwritten_and_reports_private(self):
        root = repo({"a.py": SHELL_LINE})
        (root / ".agentharden").mkdir()
        (root / ".agentharden" / ".gitignore").write_text("!*\n")
        run_cli("scan", str(root), "--no-external", "-q")
        self.assertIn("\n*\n", (root / ".agentharden" / ".gitignore").read_text())
        for name in ("report.json", "FIX_PROMPT.md"):
            self.assertEqual(stat.S_IMODE((root / ".agentharden" / name).stat().st_mode), 0o600)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can write anywhere")
    def test_read_only_repo_is_a_clean_error(self):
        root = repo({"a.py": SHELL_LINE})
        root.chmod(0o555)
        self.addCleanup(root.chmod, 0o755)
        proc = run_proc("scan", str(root), "--no-external", "-q", "--fail-on", "high")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("-o DIR", proc.stderr)
        proc = run_proc("scan", str(root), "--no-external", "--print-prompt")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Security remediation", proc.stdout)  # the prompt still reaches stdout


class DiffTest(_NoDb):
    def _kept(self, root, ref="HEAD"):
        changes = gitdiff.changed_lines(str(root), ref)
        return changes, {(f.file, f.line) for f in gitdiff.keep(scanner.run(str(root), external=False).findings,
                                                                  changes)}

    def test_non_ascii_name(self):
        root = repo({"a.py": "x = 1\n"})
        (root / "café.py").write_text("y = 1\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "c")
        (root / "café.py").write_text("y = 1\n" + SHELL_LINE)
        _, kept = self._kept(root)
        self.assertIn(("café.py", 2), kept)

    def test_repo_prefix_settings_and_b_directory(self):
        for key in ("diff.mnemonicPrefix", "diff.noprefix"):
            root = repo({"b/a.py": "x = 1\n", "c.py": "x = 1\n"})
            git(root, "config", key, "true")
            (root / "b" / "a.py").write_text("x = 1\n" + SHELL_LINE)
            (root / "c.py").write_text(SHELL_LINE + "x = 1\n")
            _, kept = self._kept(root)
            self.assertIn(("b/a.py", 2), kept, key)
            self.assertIn(("c.py", 1), kept, key)

    def test_rename_reports_only_edited_lines(self):
        root = repo({"old.py": SHELL_LINE + "x = 1\n" * 20})
        git(root, "mv", "old.py", "new.py")
        with open(root / "new.py", "a") as fh:
            fh.write("os.system(cmd)\n")
        changes, kept = self._kept(root)
        self.assertEqual(changes["new.py"], {22})
        self.assertNotIn(("new.py", 1), kept)

    def test_plus_plus_content_is_not_a_header(self):
        patch = (b"diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -1,0 +2,2 @@\n+++ i;\n++++ j;\n"
                 b"diff --git a/y.c b/y.c\n--- a/y.c\n+++ \"b/caf\\303\\251 y.c\"\n@@ -3 +3 @@\n-a\n\\ No newline at end of file\n+b\n")
        self.assertEqual(gitdiff._parse_patch(patch), {"x.c": {2, 3}, "café y.c": {3}})

    def test_unparsed_changes_are_an_error(self):
        root = repo({"a.py": "x = 1\n"})
        (root / "a.py").write_text("x = 2\n")
        with mock.patch.object(gitdiff, "_parse_patch", return_value={}):
            with self.assertRaises(gitdiff.DiffError):
                gitdiff.changed_lines(str(root), "HEAD")

    def test_compares_from_merge_base(self):
        root = repo({"feature.py": "x = 1\nx = 2\n" + SHELL_LINE})
        git(root, "switch", "-q", "-c", "feat")
        (root / "other.py").write_text("y = 1\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "feat work")
        git(root, "switch", "-q", "main")
        (root / "feature.py").write_text("x = 1\nx = 2\nsubprocess.run([c])\n")
        git(root, "commit", "-qam", "fix on main")
        git(root, "switch", "-q", "feat")
        changes, kept = self._kept(root, "main")
        self.assertNotIn("feature.py", changes)
        self.assertNotIn(("feature.py", 3), kept)

    def test_lockfile_edit_reports_only_changed_packages(self):
        root = repo({"requirements.txt": "pyyaml==5.3\nrequests==2.20.0\n"})
        with open(root / "requirements.txt", "a") as fh:
            fh.write("flask==0.12\n")
        changes = gitdiff.changed_lines(str(root), "HEAD")

        def dep(name, version):
            return Finding("DEP-PyPI", f"{name}@{version}", "high", "dependency", file="requirements.txt",
                           extra={"package": name, "version": version})

        self.assertFalse(gitdiff.touches(dep("pyyaml", "5.3"), changes))
        self.assertTrue(gitdiff.touches(dep("flask", "0.12"), changes))

    def test_baseline_cannot_hide_a_new_identical_line(self):
        root = repo({".gitignore": ".agentharden/\n", "app.py": SHELL_LINE + "x = 1\n" + SHELL_LINE})
        run_cli("baseline", str(root), "--no-external")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "baseline")
        (root / "app.py").write_text(SHELL_LINE + SHELL_LINE + "x = 1\n" + SHELL_LINE)
        rc, out, _ = run_cli("scan", str(root), "--no-external", "--diff", "HEAD", "--fail-on", "high")
        self.assertEqual(rc, 1, out)
        rc, _, _ = run_cli("scan", str(root), "--no-external", "--fail-on", "high")
        self.assertEqual(rc, 1)

    def test_diff_level_describes_whole_repo(self):
        root = repo({"app.py": SHELL_LINE})
        (root / "b.py").write_text("x = 1\n")
        rc, out, _ = run_cli("scan", str(root), "--no-external", "--diff")
        self.assertNotIn("No issues found", out)
        self.assertIn("whole repository", out)
        self.assertNotIn("Fortified", out)

    def test_empty_and_missing_refs(self):
        root = repo({"a.py": "x = 1\n"})
        rc, _, err = run_cli("scan", str(root), "--diff", "")
        self.assertEqual(rc, 2)
        rc, _, err = run_cli("scan", str(root), "--diff", "origin/nope")
        self.assertEqual(rc, 2)
        self.assertIn("fetch-depth", err)


class BaselineTest(_NoDb):
    def test_file_move_keeps_matching(self):
        root = repo({"app.py": SHELL_LINE + "eval(x)\n"})
        baseline.save(str(root), scanner.run(str(root), external=False).findings)
        (root / "sub").mkdir()
        os.rename(root / "app.py", root / "sub" / "server.py")
        known = baseline.load(baseline.path_for(str(root)))
        new, old = baseline.split(scanner.run(str(root), external=False).findings, known, root=str(root))
        self.assertEqual([f for f in new if f.category == "code"], [])
        self.assertTrue(old)

    def test_copy_into_another_existing_file_is_new(self):
        root = repo({"a.py": SHELL_LINE, "b.py": "x = 1\n"})
        baseline.save(str(root), scanner.run(str(root), external=False).findings)
        (root / "b.py").write_text(SHELL_LINE)
        known = baseline.load(baseline.path_for(str(root)))
        new, _ = baseline.split(scanner.run(str(root), external=False).findings, known, root=str(root))
        self.assertEqual([(f.file, f.rule_id) for f in new if f.rule_id == "PY002"], [("b.py", "PY002")])

    def test_different_secret_on_same_line_is_new_and_value_never_stored(self):
        key1, key2 = "AKIAZ7Q3LMPX4RTY8WQD", "AKIAB2C4D6F8G1H3J5K7"  # agentharden:ignore test fixture
        root = repo({"k.js": f'const k = "{key1}";\n'})
        baseline.save(str(root), scanner.run(str(root), external=False).findings)
        text = Path(baseline.path_for(str(root))).read_text()
        self.assertNotIn(key1, text)
        self.assertNotIn(key1[4:], text)
        known = baseline.load(baseline.path_for(str(root)))
        new, _ = baseline.split(scanner.run(str(root), external=False).findings, known, root=str(root))
        self.assertEqual(new, [])
        (root / "k.js").write_text(f'const k = "{key2}";\n')
        new, _ = baseline.split(scanner.run(str(root), external=False).findings, known, root=str(root))
        self.assertIn("SEC001", {f.rule_id for f in new})

    def test_nearest_line_is_the_old_one(self):
        root = repo({"app.py": SHELL_LINE + "x = 1\n" * 5 + SHELL_LINE})
        baseline.save(str(root), scanner.run(str(root), external=False).findings)
        (root / "app.py").write_text(SHELL_LINE + "x = 1\n" + SHELL_LINE + "x = 1\n" * 4 + SHELL_LINE)
        known = baseline.load(baseline.path_for(str(root)))
        new, _ = baseline.split(scanner.run(str(root), external=False).findings, known)
        self.assertEqual([f.line for f in new if f.rule_id == "PY002"], [3])

    def test_format_one_file_still_loads(self):
        root = repo({"app.py": SHELL_LINE})
        findings = scanner.run(str(root), external=False).findings
        Path(baseline.path_for(str(root))).write_text(json.dumps(
            {"format": 1, "findings": {fp: {} for fp in baseline.fingerprints(findings)}}))
        new, old = baseline.split(findings, baseline.load(baseline.path_for(str(root))))
        self.assertEqual(new, [])

    def test_corrupt_or_linked_baseline_is_a_clean_error(self):
        root = repo({"app.py": SHELL_LINE})
        Path(baseline.path_for(str(root))).write_text("{not json")
        rc, _, err = run_cli("scan", str(root), "--no-external", "-q")
        self.assertEqual(rc, 2)
        self.assertIn("agentharden baseline", err)


class SarifTest(_NoDb):
    def test_subdirectory_paths_locations_and_metadata(self):
        root = repo({"services/api/app.py": SHELL_LINE, "services/api/requirements.txt": "flask\n",
                     "services/api/caf é.py": SHELL_LINE})
        rc, _, _ = run_cli("scan", str(root / "services" / "api"), "--no-external", "-q", "--sarif")
        doc = json.loads((root / "services" / "api" / ".agentharden" / "results.sarif").read_text())
        run = doc["runs"][0]
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]}
        self.assertIn("services/api/app.py", uris)
        self.assertIn("services/api/caf%20%C3%A9.py", uris)
        for r in run["results"]:
            self.assertTrue(r["locations"])
            self.assertGreaterEqual(r["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
            self.assertTrue(r["partialFingerprints"])
        for rule in run["tool"]["driver"]["rules"]:
            self.assertTrue(rule["helpUri"].startswith("https://"))
            self.assertTrue(0 < float(rule["properties"]["security-severity"]) <= 10)


class RulesTest(unittest.TestCase):
    def test_every_rule_id_in_the_demo_report_is_explained(self):
        home = deps.HOME
        deps.HOME = Path(tempfile.mkdtemp())
        try:
            result = scanner.run(str(ROOT / "examples" / "vulnerable-app"), external=False)
        finally:
            deps.HOME = home
        ids = {f.rule_id for f in result.findings} | {"SEC001", "PYT002", "JST001", "POS030", "DEP-npm"}
        for rid in sorted(ids):
            rc, out, _ = run_cli("rules", rid)
            self.assertEqual(rc, 0, rid)
            self.assertIn(rid, out)


class ShippedFilesTest(unittest.TestCase):
    def test_workflow_installs_pinned_github_release(self):
        text = cli.workflow_text("high")
        self.assertIn(f'pip install "git+https://github.com/saideepreddy7781/agentharden@v{__version__}"', text)
        self.assertNotRegex(text, r"pip install agentharden\b")

    def test_actions_pinned_by_sha(self):
        texts = {"init": cli.workflow_text("high")}
        for p in [ROOT / "action.yml", *sorted((ROOT / ".github" / "workflows").glob("*.yml"))]:
            texts[p.name] = p.read_text()
        for name, text in texts.items():
            for ref in re.findall(r"uses:\s*([^\s#]+)", text):
                if ref.startswith("./"):
                    continue
                self.assertRegex(ref, r"@[0-9a-f]{40}$", f"{name}: {ref}")
            for line in text.splitlines():
                if re.search(r"uses:\s*[^.\s][^\s]*@[0-9a-f]{40}", line):
                    self.assertRegex(line, r"#\s*v\d", f"{name}: version comment missing: {line}")

    def test_release_only_on_version_tags(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        self.assertNotIn('tags: ["v*"]', text)
        self.assertIn("v[0-9]+.[0-9]+.[0-9]+*", text)

    def test_action_uploads_sarif(self):
        text = (ROOT / "action.yml").read_text()
        self.assertIn("upload-sarif", text)
        self.assertIn("continue-on-error: true", text)


class CleanTest(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(output.clean("a\x1b[31mb\x9bc‮d"), "a?[31mb?c?d")
        self.assertEqual(output.clean("x\ny\tz", multiline=True), "x\ny\tz")
        self.assertEqual(output.clean("bad\udcff"), "bad�")  # how POSIX decodes a non-UTF-8 file name


if __name__ == "__main__":
    unittest.main()
