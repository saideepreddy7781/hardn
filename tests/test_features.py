"""Taint precision, baseline, --diff, `hardn fix`, and CLI smoke tests."""
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from hardn import baseline, cli, fix, gitdiff, scanner, taint_js, taint_py
from hardn.walker import SourceFile

GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}


def py(code):
    return taint_py.scan([SourceFile("app.py", textwrap.dedent(code))])


def js(code):
    return taint_js.scan([SourceFile("app.js", textwrap.dedent(code))])


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


def make_repo(files: dict) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text))
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    return root


class PythonTaintTest(unittest.TestCase):
    def test_parameterized_sql_is_safe(self):
        self.assertEqual(py('''
            def view(request):
                cur.execute("SELECT * FROM t WHERE id = %s", (request.args["id"],))
        '''), [])

    def test_sanitizer_stops_flow(self):
        self.assertEqual(py('''
            def view(request):
                n = int(request.args["n"])
                os.system(f"echo {n}")
        '''), [])

    def test_fastapi_params(self):
        found = py('''
            @app.get("/run")
            def run(cmd: str, count: int):
                os.system(cmd)
                os.system(f"echo {count}")
        ''')
        self.assertEqual([(f.rule_id, f.line) for f in found], [("PYT002", 4)])

    def test_flow_through_loop_and_fstring(self):
        found = py('''
            def view(request):
                parts = []
                for p in request.json["paths"]:
                    parts.append(p)
                    target = f"/srv/{p}"
                    open(target)
        ''')
        self.assertEqual(found[0].rule_id, "PYT005")
        self.assertIn("p (L4)", found[0].extra["flow"])

    def test_tuple_unpacking_taints_every_target(self):
        found = py('''
            def view(request):
                host, port = request.args["addr"].split(":")
                os.system("nc " + port)
        ''')
        self.assertEqual([f.rule_id for f in found], ["PYT002"])

    def test_safe_yaml_loader(self):
        self.assertEqual(py('''
            def view(request):
                yaml.load(request.data, Loader=yaml.SafeLoader)
        '''), [])


class JsTaintTest(unittest.TestCase):
    def test_parameterized_query_is_safe(self):
        self.assertEqual(js('''
            const { name } = req.query;
            db.query("SELECT * FROM users WHERE name = $1", [name]);
        '''), [])

    def test_sanitized(self):
        self.assertEqual(js('''
            const id = parseInt(req.params.id, 10);
            db.query(`SELECT * FROM users WHERE id = ${id}`);
        '''), [])

    def test_string_literals_do_not_taint(self):
        self.assertEqual(js('''
            const name = req.query.name;
            fetch("https://api.example.com/name");
        '''), [])

    def test_xss_assignment(self):
        found = js('''
            const q = new URLSearchParams(location.search).get("q");
            el.innerHTML = "<b>" + q + "</b>";
        ''')
        self.assertEqual([f.rule_id for f in found], ["JST009"])


class BaselineTest(unittest.TestCase):
    def test_baseline_hides_known_and_survives_line_shifts(self):
        root = make_repo({"app.py": '''
            def view(request):
                eval(request.args["x"])
        '''})
        baseline.save(str(root), scanner.run(str(root), external=False).findings)
        known = baseline.load(baseline.path_for(str(root)))
        # Shift the old finding down and add a new issue.
        (root / "app.py").write_text("import os\n\n\ndef view(request):\n    eval(request.args[\"x\"])\n"
                                     "    os.system(request.args['cmd'])\n")
        new, old = baseline.split(scanner.run(str(root), external=False).findings, known)
        self.assertTrue(any(f.rule_id == "PYT003" for f in old))  # eval: baselined despite moving lines
        self.assertTrue(any(f.rule_id == "PYT002" for f in new))  # os.system: new


class DiffTest(unittest.TestCase):
    def test_only_changed_lines(self):
        root = make_repo({"app.py": '''
            def a(request):
                eval(request.args["x"])
        '''})
        with open(root / "app.py", "a") as fh:
            fh.write("\ndef b(request):\n    os.system(request.args['cmd'])\n")
        (root / "new.js").write_text("eval(req.query.code);\n")
        changed = gitdiff.changed_lines(str(root), "HEAD")
        self.assertIsNone(changed["new.js"])
        kept = {(f.file, f.rule_id) for f in gitdiff.keep(scanner.run(str(root), external=False).findings, changed)}
        self.assertIn(("app.py", "PYT002"), kept)
        self.assertNotIn(("app.py", "PYT003"), kept)
        self.assertTrue(any(f == "new.js" for f, _ in kept))

    def test_bad_ref(self):
        root = make_repo({"a.py": "x = 1\n"})
        with self.assertRaises(gitdiff.DiffError):
            gitdiff.changed_lines(str(root), "no-such-branch")


FAKE_AGENT = textwrap.dedent('''
    import pathlib, sys
    prompt = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    assert "Security remediation task" in prompt
    app = pathlib.Path("app.py")
    app.write_text(app.read_text().replace('eval(request.args["x"])', 'int(request.args["x"])'))
''')


class FixLoopTest(unittest.TestCase):
    def _repo(self):
        return make_repo({".gitignore": ".hardn/\n", "app.py": '''
            def view(request):
                return eval(request.args["x"])
        '''})

    def test_fix_reaches_target(self):
        root = self._repo()
        agent = Path(tempfile.mkdtemp()) / "agent.py"
        agent.write_text(FAKE_AGENT)
        with redirect_stdout(io.StringIO()) as out:
            rc = fix.run(str(root), agent=[sys.executable, str(agent), "{prompt_file}"], yes=True, external=False)
        self.assertEqual(rc, 0, out.getvalue())
        self.assertIn("int(request.args", (root / "app.py").read_text())
        branch = subprocess.run(["git", "-C", str(root), "branch", "--show-current"], check=False,
                                capture_output=True, text=True)
        self.assertTrue(branch.stdout.startswith("hardn/fix-"))

    def test_no_progress_stops(self):
        root = self._repo()
        with redirect_stdout(io.StringIO()) as out:
            rc = fix.run(str(root), agent=[sys.executable, "-c", "pass"], yes=True, external=False, branch=False)
        self.assertEqual(rc, 1)
        self.assertIn("No progress", out.getvalue())

    def test_refuses_dirty_tree(self):
        root = self._repo()
        (root / "app.py").write_text("x = 1\n")
        with self.assertRaises(fix.FixError):
            fix.run(str(root), agent=[sys.executable, "-c", "pass"], yes=True, external=False)


class CliTest(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(list(args))
        return rc, buf.getvalue()

    def test_scan_json_and_fail_on(self):
        root = make_repo({"app.py": "def v(request):\n    eval(request.args['x'])\n"})
        rc, out = self.run_cli("scan", str(root), "--no-external", "--json", "--fail-on", "high")
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["level_name"], "Exposed")

    def test_init_writes_workflow_and_baseline(self):
        root = make_repo({"app.py": "def v(request):\n    eval(request.args['x'])\n"})
        rc, _ = self.run_cli("init", str(root), "--baseline")
        self.assertEqual(rc, 0)
        self.assertIn("--fail-on high", (root / ".github/workflows/hardn.yml").read_text())
        rc, out = self.run_cli("scan", str(root), "--no-external", "--fail-on", "high")
        self.assertEqual(rc, 0, out)  # everything baselined → CI starts green

    def test_rules_explain(self):
        rc, out = self.run_cli("rules", "py004")
        self.assertEqual(rc, 0)
        self.assertIn("CWE-89", out)


if __name__ == "__main__":
    unittest.main()
