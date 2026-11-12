"""Detection accuracy: silent misses, leaks, noise, taint flows and posture scope."""
import json
import os
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from hardn import code_rules, posture, secrets, taint_js, taint_py, walker
from hardn import stack as stack_mod
from hardn.walker import SourceFile

GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
# Assembled at runtime so this file does not itself hold provider-shaped strings.
STRIPE = "sk_" + "live_" + "5gJ3rtVfmSnCBCTmoqAtSWHB"
KEY_BODY = "N7Q98yhXFiNZFRQPvvs51cSsUOwItJXfct2yt9yDrCzQTkofmCWPZOFtg8P1qB9M"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----"


def src(path, text):
    return SourceFile(path, textwrap.dedent(text))


def rules(path, text):
    return code_rules.scan([src(path, text)])


def py(text):
    return taint_py.scan([src("app.py", text)])


def js(text, path="server.js"):
    return taint_js.scan([src(path, text)])


def ids(findings):
    return sorted({f.rule_id for f in findings})


class SecretsTest(unittest.TestCase):
    def test_committed_env_with_provider_key_is_critical(self):
        root = Path(tempfile.mkdtemp())
        (root / ".env").write_text(f"STRIPE_KEY={STRIPE}\n")
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True, env=GIT_ENV)
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, env=GIT_ENV)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "x"], check=True, env=GIT_ENV)
        files, _ = walker.walk(str(root))
        found = secrets.scan(files, str(root))
        self.assertEqual([(f.rule_id, f.severity) for f in found], [("SEC200", "critical")])
        self.assertIn("Stripe", found[0].title)
        self.assertNotIn(STRIPE[8:], found[0].snippet)

    def test_env_flags_and_urls_without_passwords_are_quiet(self):
        root = Path(tempfile.mkdtemp())
        (root / ".env").write_text("ENABLE_TOKEN_AUTH=true\nTOKEN_TTL=3600\nDATABASE_URL=postgres://localhost:5432/app\n")
        files, _ = walker.walk(str(root))
        self.assertEqual(secrets.scan(files, str(root)), [])

    def test_private_key_body_never_reaches_a_snippet(self):
        one_line = f'{{"key": "{PEM}\\n{KEY_BODY}\\n-----END RSA PRIVATE KEY-----"}}\n'
        multi = f"{PEM}\n{KEY_BODY}\n{KEY_BODY[::-1]}\n-----END RSA PRIVATE KEY-----\n"
        for path, text in (("key.json", one_line), ("id_rsa", multi)):
            found = secrets._scan_file(SourceFile(path, text))
            self.assertEqual(ids(found), ["SEC003"], path)
            for f in found:
                self.assertNotIn(KEY_BODY[:20], f.snippet)
        self.assertNotIn(KEY_BODY[:20], secrets.redact_text(one_line))
        self.assertNotIn(KEY_BODY[:20], secrets.redact_text(KEY_BODY))

    def test_header_comparison_is_not_a_key(self):
        self.assertEqual(secrets._scan_file(src("check.py", f'ok = s.startswith("{PEM}")\n')), [])

    def test_provider_placeholders_are_quiet(self):
        for value in ("ghp_" + "x" * 36, "AKIA" + "IOSFODNN7EXAMPLE", "sk-" + "1234567890abcdef" * 2,
                      "AIza" + "X" * 35, "sk-your-openai-api-key-goes-here-please"):
            self.assertEqual(secrets._scan_line("config.py", 1, f'VALUE = "{value}"'), [], value)

    def test_translation_catalogue_is_not_a_credential_store(self):
        text = '{\n  "hide_password": "Jelszó elrejtése",\n  "reset_password": "Passwort zurücksetzen"\n}\n'
        self.assertEqual(secrets.scan([src("packages/i18n/locales/hu/common.json", text)], tempfile.mkdtemp()), [])

    def test_unquoted_config_values(self):
        found = secrets._scan_file(src("docker-compose.yml", "services:\n  db:\n    environment:\n"
                                                            "      POSTGRES_PASSWORD: Xk29fLq7Zr!p\n"))
        self.assertEqual(ids(found), ["SEC100"])
        self.assertEqual(secrets._scan_file(src("a.yaml", "password: ${DB_PASSWORD}\n")), [])


class LineRuleTest(unittest.TestCase):
    def test_ci001_respects_its_own_fix(self):
        bad = """\
            on: issues
            jobs:
              a:
                steps:
                  - run: echo "${{ github.event.issue.title }}"
        """
        good = """\
            on: issues
            jobs:
              a:
                steps:
                  - env:
                      TITLE: ${{ github.event.issue.title }}
                    run: echo "$TITLE"
        """
        self.assertEqual(ids(rules(".github/workflows/ci.yml", bad)), ["CI001"])
        self.assertEqual(rules(".github/workflows/ci.yml", good), [])

    def test_py001_ignores_definitions_strings_and_comments(self):
        self.assertEqual(rules("a.py", '''\
            class Node:
                def eval(self, context):
                    """Never call eval(x) here."""
                    return 1  # eval(x) used to be here
            MSG = "do not use eval(x)"
        '''), [])
        self.assertEqual(ids(rules("a.py", "def f(s):\n    return eval(s)\n")), ["PY001"])

    def test_dompurify_and_compiled_bundles(self):
        self.assertEqual(rules("a.js", "el.innerHTML = DOMPurify.sanitize(x);\n"), [])
        self.assertEqual(ids(rules("a.js", "el.innerHTML = x;\n")), ["JS004"])
        self.assertEqual(rules("packages/next/src/compiled/react-dom/index.js", "el.innerHTML = x;\n"), [])

    def test_py004_catches_format_and_concatenation(self):
        for line in ('c.execute("SELECT * FROM users WHERE username = \'{}\'".format(us))',
                     'cursor.execute("SELECT * FROM t WHERE name = \'" + name + "\'")'):
            self.assertEqual(ids(rules("a.py", line + "\n")), ["PY004"], line)
        self.assertEqual(rules("a.py", 'c.execute("INSERT INTO t VALUES (\'%s\')", (x,))\n'), [])

    def test_php_rules_carry_the_right_cwe(self):
        found = rules("index.php", "<?php\nmysqli_query($c, 'SELECT ' . $_GET['a']);\nsystem('ls ' . $_GET['d']);\n")
        self.assertEqual(sorted((f.rule_id, f.cwe) for f in found), [("PHP001", "CWE-89"), ("PHP004", "CWE-78")])

    def test_tls_verification_off_is_high_everywhere(self):
        severities = {r.severity for r in code_rules.RULES if r.cwe == "CWE-295"}
        self.assertEqual(severities, {"high"})

    def test_multiline_call(self):
        self.assertEqual(ids(rules("a.py", "def f(c):\n    subprocess.run(\n        c,\n        shell=True,\n    )\n")),
                         ["PY002"])
        self.assertEqual(rules("a.py", "def f(b):\n    return yaml.load(\n        b,\n        Loader=yaml.SafeLoader,\n    )\n"),
                         [])


class PythonTaintTest(unittest.TestCase):
    def test_import_alias_and_second_positional(self):
        found = py('''\
            import subprocess as sp
            import aiohttp
            from flask import request
            def handler():
                x = request.args["x"]
                sp.run(f"ls {x}", shell=True)
                aiohttp.request("GET", x)
        ''')
        self.assertEqual(ids(found), ["PYT002", "PYT004"])

    def test_fastapi_optional_and_annotated_params(self):
        found = py('''\
            from typing import Annotated, Optional
            from fastapi import FastAPI, Query
            app = FastAPI()
            @app.get("/a")
            def a(q: Optional[str] = None, n: Annotated[str, Query()] = "", m: str | None = None, k: int = 0):
                cur.execute(f"SELECT {q}")
                cur.execute(f"SELECT {n}")
                cur.execute(f"SELECT {m}")
                cur.execute(f"SELECT {k}")
        ''')
        self.assertEqual(sorted(f.line for f in found), [6, 7, 8])

    def test_reflected_xss_and_reassignment(self):
        found = py('''\
            from flask import Flask, request
            app = Flask(__name__)
            @app.route("/x")
            def x():
                name = request.args["n"]
                return f"<h1>{name}</h1>"
            @app.route("/y")
            def y():
                uid = request.args["id"]
                uid = int(uid)
                cur.execute(f"SELECT * FROM u WHERE id={uid}")
                return "ok"
        ''')
        self.assertEqual([(f.rule_id, f.line) for f in found], [("PYT010", 6)])

    def test_same_file_helper(self):
        found = py('''\
            from flask import Flask, request
            app = Flask(__name__)
            def run_q(q):
                cur.execute(q)
            @app.route("/x")
            def handler():
                run_q("SELECT * FROM u WHERE id=" + request.args["id"])
        ''')
        self.assertEqual([(f.rule_id, f.line) for f in found], [("PYT001", 4)])

    def test_deep_concatenation_does_not_crash(self):
        text = "from flask import request\ndef v():\n    x = " + " + ".join(['"a"'] * 4000) + \
               ' + request.args["q"]\n    eval(x)\n'
        self.assertEqual(ids(taint_py.scan([SourceFile("deep.py", text)])), ["PYT003"])

    def test_inline_suppression(self):
        self.assertEqual(py('''\
            def view(request):
                eval(request.args["x"])  # hardn:ignore reviewed
                os.system(request.args["c"])  # nosec
        '''), [])


class JsTaintTest(unittest.TestCase):
    def test_multiline_call_and_block_scope(self):
        found = js('''\
            app.get('/a', (req, res) => {
              const id = req.query.id;
              db.query(
                `SELECT * FROM u WHERE id=${id}`
              );
            });
            app.get('/b', (req, res) => {
              const id = 42;
              db.query("SELECT * FROM u WHERE id=" + id);
            });
        ''')
        self.assertEqual([(f.rule_id, f.line) for f in found], [("JST001", 3)])

    def test_kill_reflected_xss_and_helper(self):
        found = js('''\
            function run(q) {
              db.query(q);
            }
            app.get('/x', (req, res) => {
              let id = req.query.id;
              id = parseInt(id, 10);
              db.query("SELECT * FROM u WHERE id=" + id);
              run("SELECT * FROM u WHERE n=" + req.query.n);
              res.send(`<h1>${req.query.x}</h1>`);
            });
        ''')
        self.assertEqual(sorted((f.rule_id, f.line) for f in found), [("JST001", 2), ("JST010", 9)])

    def test_inline_suppression(self):
        self.assertEqual(js("const n = req.query.n;\neval(n); // hardn:ignore\n"), [])


class PostureTest(unittest.TestCase):
    def _check(self, files: dict):
        root = Path(tempfile.mkdtemp())
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        loaded, all_paths = walker.walk(str(root))
        return ids(posture.check(str(root), loaded, all_paths, stack_mod.detect(str(root), loaded, all_paths)))

    def test_library_is_not_asked_for_app_controls(self):
        pkg = {"name": "express", "dependencies": {"debug": "4.0.0"}, "devDependencies": {"express": "4.0.0"}}
        found = self._check({"package.json": json.dumps(pkg), "package-lock.json": "{}"})
        self.assertFalse({"POS003", "POS004", "POS005"} & set(found))
        found = self._check({"pyproject.toml": '[project]\nname = "Flask"\ndependencies = ["werkzeug>=3"]\n'})
        self.assertNotIn("POS011", found)

    def test_app_is_asked(self):
        pkg = {"name": "shop", "private": True, "dependencies": {"express": "4.0.0"}}
        self.assertIn("POS003", self._check({"package.json": json.dumps(pkg), "package-lock.json": "{}"}))
        self.assertIn("POS011", self._check({"pyproject.toml": '[project]\nname = "a"\ndependencies = ["flask>=3"]\n'}))


class SpeedTest(unittest.TestCase):
    def test_line_rules_skip_files_without_hints(self):
        files = [SourceFile(f"f{i}.js", "const a = 1;\n" * 2000) for i in range(50)]
        start = time.time()
        self.assertEqual(code_rules.scan(files), [])
        self.assertLess(time.time() - start, 2.0)


if __name__ == "__main__":
    unittest.main()
