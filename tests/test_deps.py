"""Dependency engine: version ordering, severity, lockfile parsers, gaps, fix targets and update safety.

Every test passes an explicit database path, so nothing reads or writes ~/.hardn.
"""
import io
import json
import os
import sqlite3
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from hardn import deps


def rng(*events, kind="ECOSYSTEM"):
    return {"type": kind, "events": [dict([e]) for e in events]}


def aff(*events, kind="ECOSYSTEM", versions=()):
    return {"ranges": [rng(*events, kind=kind)], "versions": list(versions)}


class Tmp(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def write(self, rel, text):
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def paths(self):
        return sorted(str(p.relative_to(self.tmp)).replace(os.sep, "/") for p in self.tmp.rglob("*") if p.is_file())

    def pkgs(self):
        return deps.collect_packages(str(self.tmp), self.paths())

    def db(self, rows=(), kev=(), ages=None, ecos_age_days=0):
        """A current-schema DB. rows: (eco, name, id, severity, aliases, affected)."""
        path = self.tmp / "db" / "osv.sqlite"
        con = deps._connect(path)
        now = int(time.time() - ecos_age_days * 86400)
        for eco, name, vid, sev, aliases, affected in rows:
            con.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?)",
                        (eco, deps.normalize(eco, name), vid, f"summary of {vid}", sev, json.dumps(aliases),
                         json.dumps(affected)))
            con.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (f"updated:{eco}", str(now)))
        for cve in kev:
            con.execute("INSERT INTO kev VALUES (?)", (cve,))
        con.execute("INSERT OR REPLACE INTO meta VALUES ('updated_at', ?)", (str(now),))
        con.commit()
        con.close()
        return path

    def scan(self, db):
        return deps.scan(str(self.tmp), [p for p in self.paths() if not p.startswith("db/")], db=db)


# ---------------------------------------------------------------- versions

class VersionOrderTest(unittest.TestCase):
    def lt(self, a, b, eco):
        self.assertLess(deps.vkey(a, eco), deps.vkey(b, eco), f"{eco}: {a} < {b}")

    def eq(self, a, b, eco):
        self.assertEqual(deps.vkey(a, eco), deps.vkey(b, eco), f"{eco}: {a} == {b}")

    def test_semver_numeric_prerelease_sorts_below_release(self):
        for eco in ("npm", "Go", "crates.io"):
            self.lt("1.5.8-0", "1.5.8", eco)
            self.lt("1.5.8-0.20250204093451-1f4db20199b8", "1.5.8", eco)
            self.lt("2.0.0-0", "2.0.0-rc.1", eco)
            self.lt("3.3.0-12", "3.3.0-13", eco)
            self.lt("3.3.0-13", "3.3.0", eco)
        self.lt("v1.9.1-0.20230101000000-abcdefabcdef", "v1.9.1", "Go")
        self.lt("8.0.0-20250102081831-64c566a8280b", "8.0.0", "Go")
        self.eq("v20.10.0+incompatible", "20.10.0", "Go")

    def test_npm_patch_suffix_is_a_prerelease(self):
        self.lt("2.2.7-patch.1", "2.2.7", "npm")
        self.lt("1.0.0-alpha.1", "1.0.0-alpha.beta", "npm")  # numeric identifiers sort below alphanumeric

    def test_pep440(self):
        e = "PyPI"
        for a, b in (("1.0.dev0", "1.0a1"), ("1.0a1", "1.0b1"), ("1.0b1", "1.0rc1"), ("1.0rc1", "1.0"),
                     ("1.0", "1.0.post1"), ("1.0.post1", "1.0.1"), ("2.0", "1!0.1"), ("1.0", "1.0+local")):
            self.lt(a, b, e)
        self.eq("1.0", "1.0.0", e)
        self.eq("1.0-1", "1.0.post1", e)
        self.lt("2.9.0-NA", "0.1", e)  # not PEP 440: legacy versions sort below every valid one, as in OSV
        self.assertFalse(deps.is_affected("2.9.0", aff(("introduced", "0"), ("last_affected", "2.9.0-NA")), e))

    def test_packagist_php_version_compare(self):
        e = "Packagist"
        self.lt("2.3.7", "2.3.7-p1", e)      # -p1 is a patch level, after the release
        self.lt("2.3.7-p1", "2.3.8", e)
        self.lt("3.11.0-beta", "3.11.0", e)
        self.lt("1.0.0-RC1", "1.0.0", e)
        self.eq("v4.4.0", "4.4.0", e)

    def test_maven(self):
        e = "Maven"
        for a, b in (("1.0-alpha1", "1.0-beta1"), ("1.0-beta1", "1.0-RC1"), ("1.0-RC1", "1.0-SNAPSHOT"),
                     ("1.0-SNAPSHOT", "1.0"), ("1.0", "1.0-sp1"), ("2.0-beta9", "2.0"), ("9.0.0.M1", "9.0.0")):
            self.lt(a, b, e)
        self.eq("4.1.71.Final", "4.1.71", e)
        self.eq("5.2.20.RELEASE", "5.2.20", e)
        self.lt("31.1-jre", "32.0.0-jre", e)

    def test_rubygems(self):
        e = "RubyGems"
        self.lt("6.0.0.rc1", "6.0.0", e)
        self.lt("4.0.0-beta.2", "4.0.0", e)
        self.eq("1.16.5-x86_64-linux", "1.16.5", e)
        self.eq("9.4.0-java", "9.4.0", e)
        self.lt("2.2.8", "2.2.8.1", e)


class RangeTest(unittest.TestCase):
    def test_go_fix_at_tagged_release_is_not_flagged(self):
        # wasmvm shape: the fix is a pseudo-version just before the v1.5.8 tag
        a = aff(("introduced", "0"), ("fixed", "1.5.8-0.20250204093451-1f4db20199b8"), kind="SEMVER")
        self.assertFalse(deps.is_affected("v1.5.8", a, "Go"))
        self.assertTrue(deps.is_affected("v1.5.7", a, "Go"))

    def test_prerelease_introduced(self):
        a = aff(("introduced", "2.0.0-0"), ("fixed", "2.0.0-rc.2"), kind="SEMVER")
        self.assertTrue(deps.is_affected("2.0.0-rc.1", a, "npm"))
        self.assertFalse(deps.is_affected("2.0.0", a, "npm"))

    def test_last_affected_and_open_ranges(self):
        a = aff(("introduced", "2.0.0"), ("last_affected", "2.3.0"))
        self.assertTrue(deps.is_affected("2.3.0", a, "PyPI"))
        self.assertFalse(deps.is_affected("2.3.1", a, "PyPI"))
        self.assertTrue(deps.is_affected("9.0", aff(("introduced", "1.0")), "PyPI"))

    def test_events_are_sorted_before_evaluation(self):
        # Two intervals written out of order: [1.0, 1.2) and [2.0, 2.1)
        a = {"ranges": [rng(("introduced", "2.0"), ("fixed", "2.1"), ("introduced", "1.0"), ("fixed", "1.2"))]}
        self.assertTrue(deps.is_affected("1.1", a, "PyPI"))
        self.assertFalse(deps.is_affected("1.5", a, "PyPI"))
        self.assertTrue(deps.is_affected("2.0.5", a, "PyPI"))

    def test_explicit_versions_list(self):
        self.assertTrue(deps.is_affected("0.12.2", {"ranges": [], "versions": ["0.12.2"]}, "PyPI"))
        self.assertTrue(deps.is_affected("v1.0.0", {"ranges": [], "versions": ["1.0.0"]}, "Go"))

    def test_unparseable_semver_is_not_matched(self):
        a = aff(("introduced", "0"), kind="SEMVER")
        self.assertFalse(deps.is_affected("github:lodash/lodash#2da024c", a, "npm"))


# ---------------------------------------------------------------- severity

class SeverityTest(unittest.TestCase):
    def test_cvss31_reference_scores(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
        }
        for vector, want in cases.items():
            self.assertEqual(deps.cvss_score(vector), want, vector)

    def test_cvss2_and_v4(self):
        self.assertEqual(deps.cvss_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), 7.5)
        # FIRST's calculator gives 9.3 for this vector; the estimate must not understate it
        v4 = deps.cvss_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertGreaterEqual(v4, 9.0)
        self.assertIsNone(deps.cvss_score("garbage"))

    def test_record_severity(self):
        self.assertEqual(deps.record_severity({"id": "MAL-2024-1677"}), "critical")
        pysec = {"id": "PYSEC-2019-241", "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(deps.record_severity(pysec), "critical")
        ghsa = {"id": "GHSA-x", "database_specific": {"severity": "MODERATE"}, "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
        self.assertEqual(deps.record_severity(ghsa), "high")  # the worse of the two ratings
        info = {"id": "RUSTSEC-2020-0016", "database_specific": {"informational": "unmaintained"}}
        self.assertEqual(deps.record_severity(info), "info")
        self.assertEqual(deps.record_severity({"id": "GO-2023-1"}), "medium")


# ---------------------------------------------------------------- parsers

class ParserTest(Tmp):
    def got(self):
        return {(p.eco, p.name, p.version, p.dev, p.direct, p.source) for p in self.pkgs()}

    def test_npm_aliases_all_formats(self):
        self.write("a/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"my-lodash": "npm:lodash@4.17.15"}},
            "node_modules/my-lodash": {"name": "lodash", "version": "4.17.15"}}}))
        self.write("b/package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
            "my-lodash": {"version": "npm:lodash@4.17.15"}}}))
        self.write("c/yarn.lock", '# yarn lockfile v1\n\n"my-lodash@npm:lodash@4.17.15":\n  version "4.17.15"\n')
        self.write("d/yarn.lock", '__metadata:\n  version: 8\n\n"my-lodash@npm:lodash@4.17.15":\n'
                                  '  version: 4.17.15\n  resolution: "lodash@npm:4.17.15"\n  linkType: hard\n')
        names = {(p.path.split("/")[0], p.name, p.version) for p in self.pkgs()}
        self.assertEqual(names, {(d, "lodash", "4.17.15") for d in "abcd"})

    def test_npm_dev_direct_and_git(self):
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"lodash": "^4"}, "devDependencies": {"jest": "^29"}},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/jest": {"version": "29.0.0", "dev": True},
            "node_modules/minimist": {"version": "0.0.8", "dev": True},
            "node_modules/x": {"version": "github:a/b#abc", "resolved": "git+ssh://git@github.com/a/b.git"}}}))
        got = self.got()
        self.assertIn(("npm", "lodash", "4.17.15", False, True, "registry"), got)
        self.assertIn(("npm", "jest", "29.0.0", True, True, "registry"), got)
        self.assertIn(("npm", "minimist", "0.0.8", True, False, "registry"), got)
        self.assertIn("local", {p.source for p in self.pkgs() if p.name == "x"})

    def test_berry_workspace_is_not_a_registry_package(self):
        self.write("yarn.lock", '__metadata:\n  version: 8\n\n"lodash@workspace:.":\n  version: 0.0.0-use.local\n'
                                '  resolution: "lodash@workspace:."\n  linkType: soft\n')
        self.assertEqual({p.source for p in self.pkgs()}, {"local"})

    def test_pnpm_v9_with_dev_reachability_and_alias(self):
        self.write("pnpm-lock.yaml", """lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: 4.17.15
        version: 4.17.15
      my-lodash:
        specifier: npm:lodash@3.10.1
        version: lodash@3.10.1
    devDependencies:
      mkdirp:
        specifier: 0.5.1
        version: 0.5.1

packages:

  lodash@3.10.1:
    resolution: {integrity: sha512-a}

  lodash@4.17.15:
    resolution: {integrity: sha512-b}

  minimist@0.0.8:
    resolution: {integrity: sha512-c}

  mkdirp@0.5.1:
    resolution: {integrity: sha512-d}
    hasBin: true

snapshots:

  lodash@3.10.1: {}

  lodash@4.17.15: {}

  minimist@0.0.8: {}

  mkdirp@0.5.1:
    dependencies:
      minimist: 0.0.8
""")
        got = self.got()
        self.assertIn(("npm", "lodash", "4.17.15", False, True, "registry"), got)
        self.assertIn(("npm", "lodash", "3.10.1", False, True, "registry"), got)
        self.assertIn(("npm", "mkdirp", "0.5.1", True, True, "registry"), got)
        self.assertIn(("npm", "minimist", "0.0.8", True, False, "registry"), got)

    def test_pnpm_v6_dev_flag(self):
        self.write("pnpm-lock.yaml", """lockfileVersion: 5.4

specifiers:
  lodash: 4.17.15

devDependencies:
  lodash: 4.17.15

packages:

  /lodash/4.17.15:
    resolution: {integrity: sha512-x}
    dev: true
""")
        self.assertIn(("npm", "lodash", "4.17.15", True, True, "registry"), self.got())

    def test_bun_lock_text_format(self):
        self.write("bun.lock", """{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "fx",
      "dependencies": { "lodash": "4.17.15", },
      "devDependencies": { "jest": "29.0.0", },
    },
  },
  "packages": {
    "lodash": ["lodash@4.17.15", "", {}, "sha512-x"],
    "jest": ["jest@29.0.0", "", { "dependencies": { "minimist": "0.0.8" } }, "sha512-y"],
    "minimist": ["minimist@0.0.8", "", {}, "sha512-z"],
  }
}
""")
        got = self.got()
        self.assertIn(("npm", "lodash", "4.17.15", False, True, "registry"), got)
        self.assertIn(("npm", "minimist", "0.0.8", True, False, "registry"), got)

    def test_python_lockfiles(self):
        self.write("pipfile/Pipfile.lock", json.dumps({
            "default": {"flask": {"version": "==0.12.2"}},
            "develop": {"pytest": {"version": "==3.0.0"}, "black": {"version": "*"}}}))
        self.write("pdm/pdm.lock", '[[package]]\nname = "flask"\nversion = "0.12.2"\ngroups = ["default"]\n\n'
                                   '[[package]]\nname = "pytest"\nversion = "3.0.0"\ngroups = ["test"]\n')
        self.write("old/poetry.lock", '[[package]]\ncategory = "dev"\ndescription = "x"\nname = "flask"\n'
                                      'optional = false\nversion = "0.12.2"\n\n[metadata]\ncontent-hash = "a"\n')
        self.write("uv/uv.lock", """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "flask" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[[package]]
name = "flask"
version = "2.2.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
""")
        got = {(p.path.split("/")[0], p.name, p.version, p.dev, p.source) for p in self.pkgs()}
        for row in (("pipfile", "flask", "0.12.2", False, "registry"), ("pipfile", "pytest", "3.0.0", True, "registry"),
                    ("pipfile", "black", "", True, "unpinned"), ("pdm", "flask", "0.12.2", False, "registry"),
                    ("pdm", "pytest", "3.0.0", True, "registry"), ("old", "flask", "0.12.2", True, "registry"),
                    ("uv", "flask", "2.2.2", False, "registry"), ("uv", "pytest", "7.0.0", True, "registry"),
                    ("uv", "app", "0.1.0", False, "local")):
            self.assertIn(row, got)

    def test_requirements_includes_constraints_and_cycles(self):
        self.write("requirements/base.txt", "-r prod.txt\nflask==0.12.2 \\\n    --hash=sha256:abc\nrequests\n")
        self.write("requirements/prod.txt", "-r base.txt\n-c ../constraints.txt\njinja2>=2\n-r ../../outside.txt\n")
        self.write("constraints.txt", "requests==2.19.0\n")
        self.write("dev-requirements.txt", "pytest==3.0.0\n")
        pkgs = self.pkgs()
        got = {(p.name, p.version, p.dev, p.source) for p in pkgs}
        self.assertIn(("flask", "0.12.2", False, "registry"), got)
        self.assertIn(("requests", "2.19.0", False, "registry"), got)  # pinned by the constraints file
        self.assertIn(("jinja2", "", False, "unpinned"), got)
        self.assertIn(("pytest", "3.0.0", True, "registry"), got)
        _, problems, _ = deps._collect(str(self.tmp), self.paths())
        self.assertTrue(any("outside the project" in p for p in problems))

    def test_go_mod_replace_exclude_and_indirect(self):
        self.write("a/go.mod", "module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n"
                               "\tgolang.org/x/text v0.3.0 // indirect\n)\n\n"
                               "replace github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.9.1\n")
        self.write("b/go.mod", "module x\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n\n"
                               "replace (\n\tgithub.com/gin-gonic/gin v1.9.1 => github.com/gin-gonic/gin v1.6.0\n)\n")
        self.write("c/go.mod", "module x\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n\n"
                               "exclude (\n\tgithub.com/gin-gonic/gin v1.6.0\n)\n")
        self.write("d/go.mod", "module x\n\ngo 1.21\n\nrequire example.com/m v1.0.0\n\nreplace example.com/m => ../m\n")
        self.write("e/go.sum", "github.com/gin-gonic/gin v1.6.0 h1:a=\ngithub.com/gin-gonic/gin v1.6.0/go.mod h1:b=\n")
        got = {(p.path.split("/")[0], p.name, p.version, p.direct, p.source) for p in self.pkgs()}
        self.assertIn(("a", "github.com/gin-gonic/gin", "v1.9.1", True, "registry"), got)
        self.assertIn(("a", "golang.org/x/text", "v0.3.0", False, "registry"), got)
        self.assertIn(("b", "github.com/gin-gonic/gin", "v1.6.0", True, "registry"), got)
        self.assertIn(("c", "github.com/gin-gonic/gin", "v1.9.1", True, "registry"), got)
        self.assertNotIn("v1.6.0", {v for d, _, v, _, _ in got if d == "c"})
        self.assertIn(("d", "example.com/m", "v1.0.0", True, "local"), got)
        self.assertIn(("e", "github.com/gin-gonic/gin", "v1.6.0", None, "registry"), got)

    def test_composer_null_dev_and_dev_section(self):
        self.write("a/composer.lock", json.dumps({"packages": [{"name": "guzzlehttp/guzzle", "version": "6.5.0"}],
                                                   "packages-dev": None}))
        self.write("b/composer.lock", json.dumps({"packages": [], "packages-dev": [
            {"name": "phpunit/phpunit", "version": "v5.6.0"}]}))
        got = {(p.name, p.version, p.dev) for p in self.pkgs()}
        self.assertEqual(got, {("guzzlehttp/guzzle", "6.5.0", False), ("phpunit/phpunit", "5.6.0", True)})

    def test_pom_properties_parent_and_management(self):
        self.write("pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>g</groupId><artifactId>parent</artifactId><version>1</version>
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>
      <version>2.9.8</version></dependency>
  </dependencies></dependencyManagement>
</project>""")
        self.write("app/pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version>
      <scope>test</scope></dependency>
    <dependency><groupId>x</groupId><artifactId>y</artifactId><version>${missing}</version></dependency>
  </dependencies>
</project>""")
        got = {(p.name, p.version, p.dev, p.source) for p in self.pkgs() if p.path == "app/pom.xml"}
        self.assertIn(("org.apache.logging.log4j:log4j-core", "2.14.1", False, "registry"), got)
        self.assertIn(("com.fasterxml.jackson.core:jackson-databind", "2.9.8", False, "registry"), got)
        self.assertIn(("junit:junit", "4.12", True, "registry"), got)
        self.assertIn(("x:y", "", False, "unpinned"), got)

    def test_gradle_lockfile(self):
        self.write("gradle.lockfile", "# comment\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,"
                                      "runtimeClasspath\njunit:junit:4.12=testCompileClasspath\nempty=\n")
        got = {(p.name, p.version, p.dev) for p in self.pkgs()}
        self.assertEqual(got, {("org.apache.logging.log4j:log4j-core", "2.14.1", False), ("junit:junit", "4.12", True)})

    def test_malformed_files_become_gaps_not_crashes(self):
        self.write("a/package-lock.json", "{not json")
        self.write("b/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": None}))
        self.write("c/package-lock.json", "[1, 2]")
        self.write("d/composer.lock", json.dumps({"packages": "nope"}))
        self.write("e/pom.xml", "<project><dependencies>")
        findings, note, gaps = self.scan(self.db())
        self.assertEqual(findings, [])
        self.assertEqual(len(gaps), 5, gaps)
        self.assertTrue(all("not checked" in g for g in gaps))


# ---------------------------------------------------------------- scan: honesty about coverage

LODASH = ("npm", "lodash", "GHSA-test", "high", ["CVE-2099-0001"], aff(("introduced", "0"), ("fixed", "4.17.21"),
                                                                       kind="SEMVER"))


class ScanCoverageTest(Tmp):
    def setUp(self):
        super().setUp()
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"lodash": "4"}}, "node_modules/lodash": {"version": "4.17.15"}}}))
        self.write("go.mod", "module x\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n")

    def test_no_db(self):
        findings, note, gaps = self.scan(self.tmp / "db" / "missing.sqlite")
        self.assertNotIn("checked", note)
        self.assertEqual(len(gaps), 1)
        self.assertIn("Go and npm", gaps[0])
        self.assertIn("hardn update", gaps[0])

    def test_empty_db_is_no_data(self):
        findings, note, gaps = self.scan(self.db())
        self.assertNotIn("packages checked", note)
        self.assertTrue(any("no advisory data" in g for g in gaps))

    def test_partial_db_names_the_missing_ecosystem(self):
        findings, note, gaps = self.scan(self.db([LODASH]))
        self.assertEqual(len(findings), 1)
        self.assertNotIn("packages checked", note)
        self.assertIn("1 of 2 packages", note)
        go = [g for g in gaps if "Go" in g]
        self.assertEqual(len(go), 1)
        self.assertIn("no Go data", go[0])
        self.assertIn("--ecosystems Go", go[0])
        self.assertTrue(any("known-exploited list is missing" in g for g in gaps))  # this DB has no KEV rows

    def test_stale_db_is_a_gap(self):
        findings, note, gaps = self.scan(self.db([LODASH], ecos_age_days=45))
        self.assertTrue(any("45 days old" in g for g in gaps), gaps)

    def test_damaged_and_old_schema_db(self):
        bad = self.tmp / "db" / "garbage.sqlite"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_bytes(b"this is not sqlite" * 100)
        _, note, gaps = self.scan(bad)
        self.assertIn("unusable", note)
        self.assertTrue(any("damaged" in g for g in gaps))
        old = self.tmp / "db" / "old.sqlite"
        con = sqlite3.connect(str(old))
        con.executescript("CREATE TABLE vulns (eco TEXT,name TEXT,id TEXT,summary TEXT,severity TEXT);"
                          "CREATE TABLE kev (cve TEXT PRIMARY KEY); CREATE TABLE meta (key TEXT, value TEXT);")
        con.close()
        _, note, gaps = self.scan(old)
        self.assertTrue(any("old format" in g for g in gaps))

    def test_unpinned_requirement_is_a_gap_without_a_guess(self):
        self.write("requirements.txt", "flask>=0.12\n")
        findings, _, gaps = self.scan(self.db([LODASH]))
        self.assertTrue(any("no pinned version (flask)" in g for g in gaps))
        self.assertNotIn("flask", {f.extra["package"] for f in findings})


class ScanFindingTest(Tmp):
    def test_kev_escalation_dev_context_and_transitive(self):
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"devDependencies": {"jest": "29"}},
            "node_modules/jest": {"version": "29.0.0", "dev": True},
            "node_modules/lodash": {"version": "4.17.15", "dev": True}}}))
        findings, note, gaps = self.scan(self.db([LODASH], kev=["CVE-2099-0001"]))
        self.assertEqual(note, "2 packages checked")
        self.assertEqual(gaps, [])
        f = findings[0]
        self.assertEqual(f.severity, "critical")
        self.assertIn("actively exploited", f.title)
        self.assertEqual(f.context, "dev-dependency")
        self.assertEqual(f.extra["dependency"], "transitive")
        self.assertEqual(f.extra["fixed_in"], "4.17.21")

    def test_malicious_package_is_critical(self):
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/evil": {"version": "1.0.0"}}}))
        mal = ("npm", "evil", "MAL-2024-1", deps.record_severity({"id": "MAL-2024-1"}), [],
               {"ranges": [], "versions": ["1.0.0"]})
        findings, _, _ = self.scan(self.db([mal]))
        self.assertEqual(findings[0].severity, "critical")
        self.assertIsNone(findings[0].extra["fixed_in"])

    def test_fix_target_is_verified_against_every_range(self):
        # lodash shape: 4.18.0 clears the current hits but lands inside [4.17.23, 4.18.1); 4.18.1 is clean
        rows = [("npm", "lodash", "A", "high", [], aff(("introduced", "4.0.0"), ("fixed", "4.17.21"), kind="SEMVER")),
                ("npm", "lodash", "B", "high", [], aff(("introduced", "4.0.0"), ("fixed", "4.18.0"), kind="SEMVER")),
                ("npm", "lodash", "C", "high", [], aff(("introduced", "4.17.23"), ("fixed", "4.18.1"), kind="SEMVER"))]
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": "4.17.15"}}}))
        findings, _, _ = self.scan(self.db(rows))
        self.assertEqual(findings[0].extra["ids"], ["A", "B"])
        self.assertEqual(findings[0].extra["fixed_in"], "4.18.1")

    def test_smallest_target_across_branches(self):
        rows = [("PyPI", "django", "A", "high", [], {"ranges": [rng(("introduced", "2.0"), ("fixed", "2.2.11"),
                                                                    ("introduced", "3.0"), ("fixed", "3.0.4"))]}),
                ("PyPI", "django", "B", "high", [], aff(("introduced", "0"), ("fixed", "2.2.13")))]
        self.write("requirements.txt", "django==2.2.10\n")
        findings, _, _ = self.scan(self.db(rows))
        self.assertEqual(findings[0].extra["fixed_in"], "2.2.13")
        self.assertIn("clears A, B", findings[0].fix)

    def test_no_single_release_clears_everything(self):
        rows = [("npm", "x", "A", "high", [], aff(("introduced", "0"), ("fixed", "2.0.0"), kind="SEMVER")),
                ("npm", "x", "B", "high", [], aff(("introduced", "0"), kind="SEMVER"))]
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/x": {"version": "1.0.0"}}}))
        f = self.scan(self.db(rows))[0][0]
        self.assertIsNone(f.extra["fixed_in"])
        self.assertEqual(f.extra["still_open"], ["B"])
        self.assertIn("No single release clears every advisory", f.fix)
        self.assertNotIn("clears A", f.fix)

    def test_aliases_count_once(self):
        rows = [("PyPI", "flask", "GHSA-1", "high", ["CVE-1", "PYSEC-1"], aff(("introduced", "0"), ("fixed", "1.0"))),
                ("PyPI", "flask", "PYSEC-1", "high", ["CVE-1", "GHSA-1"], aff(("introduced", "0"), ("fixed", "1.0")))]
        self.write("requirements.txt", "flask==0.12.2\n")
        f = self.scan(self.db(rows))[0][0]
        self.assertEqual(f.extra["ids"], ["GHSA-1", "PYSEC-1"])
        self.assertIn(": 1 known vulnerability", f.title)

    def test_crates_name_case(self):
        rows = [("crates.io", "SurrealDB", "A", "high", [], aff(("introduced", "0"), ("fixed", "3.0.0"),
                                                                 kind="SEMVER"))]
        self.write("Cargo.lock", 'version = 3\n\n[[package]]\nname = "surrealdb"\nversion = "2.3.0"\n'
                                 'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
        self.assertEqual(len(self.scan(self.db(rows))[0]), 1)


# ---------------------------------------------------------------- update safety

def make_zip(path, members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    Path(path).write_bytes(buf.getvalue())


ADV = {"id": "GHSA-new", "summary": "s", "aliases": ["CVE-2021-44228"], "database_specific": {"severity": "HIGH"},
       "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"}, "ranges": [rng(("introduced", "0"),
                                                                                      ("fixed", "2.0"))]}]}


class UpdateTest(Tmp):
    def setUp(self):
        super().setUp()
        self._urls = deps.OSV_URL, deps.KEV_URL
        self.feeds = self.tmp / "feeds"
        self.feeds.mkdir()
        deps.OSV_URL = self.feeds.as_uri() + "/{eco}.zip"
        deps.KEV_URL = (self.feeds / "kev.json").as_uri()
        (self.feeds / "kev.json").write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}))
        self.dbp = self.db([("PyPI", "old", "OLD-1", "high", [], {"ranges": [], "versions": ["1.0"]})],
                           kev=["CVE-OLD"], ecos_age_days=100)
        self.log = []

    def tearDown(self):
        deps.OSV_URL, deps.KEV_URL = self._urls
        super().tearDown()

    def state(self):
        con = sqlite3.connect(str(self.dbp))
        ids = sorted(r[0] for r in con.execute("SELECT id FROM vulns"))
        kev = sorted(r[0] for r in con.execute("SELECT cve FROM kev"))
        updated = con.execute("SELECT value FROM meta WHERE key='updated_at'").fetchone()[0]
        con.close()
        return ids, kev, int(updated)

    def run_update(self):
        return deps.update(["PyPI"], log=self.log.append, db=self.dbp)

    def test_good_zip_replaces_data(self):
        make_zip(self.feeds / "PyPI.zip", [("GHSA-new.json", json.dumps(ADV)), ("bad.json", "{nope")])
        self.assertEqual(self.run_update(), 0)
        ids, kev, updated = self.state()
        self.assertEqual((ids, kev), (["GHSA-new"], ["CVE-2021-44228"]))
        self.assertGreater(updated, time.time() - 60)
        self.assertTrue(any("1 unreadable records skipped" in m for m in self.log))

    def test_empty_or_useless_zip_keeps_old_data(self):
        for members in ([], [("x.json", "[1,2]")], [("x.json", json.dumps({"id": "X", "affected": None}))]):
            make_zip(self.feeds / "PyPI.zip", members)
            self.assertEqual(self.run_update(), 1)
            ids, _, updated = self.state()
            self.assertEqual(ids, ["OLD-1"])
            self.assertLess(updated, time.time() - 50 * 86400)  # not stamped fresh

    def test_all_sources_failing_keeps_timestamp_and_kev(self):
        (self.feeds / "kev.json").write_text(json.dumps({"vulnerabilities": []}))
        self.assertEqual(self.run_update(), 2)  # missing zip, empty KEV
        ids, kev, updated = self.state()
        self.assertEqual((ids, kev), (["OLD-1"], ["CVE-OLD"]))
        self.assertLess(updated, time.time() - 50 * 86400)

    def test_member_size_limit(self):
        make_zip(self.feeds / "PyPI.zip", [("big.json", " " * 5000)])
        limit = deps.MAX_MEMBER_BYTES
        deps.MAX_MEMBER_BYTES = 1000
        try:
            self.assertEqual(self.run_update(), 1)
        finally:
            deps.MAX_MEMBER_BYTES = limit
        self.assertEqual(self.state()[0], ["OLD-1"])
        self.assertTrue(any("larger than" in m for m in self.log))

    def test_corrupt_db_is_rebuilt(self):
        self.dbp.write_bytes(b"garbage" * 1000)
        make_zip(self.feeds / "PyPI.zip", [("GHSA-new.json", json.dumps(ADV))])
        self.assertEqual(self.run_update(), 0)
        self.assertEqual(self.state()[0], ["GHSA-new"])

    def test_legacy_db_is_stamped_only_after_reload(self):
        con = sqlite3.connect(str(self.dbp))
        con.execute("PRAGMA user_version = 0")
        con.commit()
        con.close()
        self.assertTrue(deps.status(self.dbp)["legacy"])
        self.assertEqual(self.run_update(), 1)  # download missing: legacy data stays, still flagged
        self.assertEqual(self.state()[0], ["OLD-1"])
        self.assertTrue(deps.status(self.dbp)["legacy"])
        make_zip(self.feeds / "PyPI.zip", [("GHSA-new.json", json.dumps(ADV))])
        self.assertEqual(self.run_update(), 0)
        self.assertFalse(deps.status(self.dbp)["legacy"])

    def test_severity_stored_from_cvss(self):
        rec = dict(ADV, id="PYSEC-1", database_specific={}, severity=[
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])
        make_zip(self.feeds / "PyPI.zip", [("PYSEC-1.json", json.dumps(rec))])
        self.run_update()
        con = sqlite3.connect(str(self.dbp))
        self.assertEqual(con.execute("SELECT severity FROM vulns WHERE id='PYSEC-1'").fetchone()[0], "critical")
        con.close()


if __name__ == "__main__":
    unittest.main()


class UvDependencyGroupTest(unittest.TestCase):
    """PEP 735 groups such as pre-commit or gha-update are dev tooling even without a 'dev' word."""

    def test_unnamed_groups_are_dev_and_prod_groups_are_not(self):
        lock = """version = 1

[[package]]
name = "app"
version = "1.0"
source = { editable = "." }
dependencies = [
    { name = "flask" },
]

[package.dev-dependencies]
pre-commit = [
    { name = "pre-commit-uv" },
]
production = [
    { name = "gunicorn" },
]

[[package]]
name = "flask"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pre-commit-uv"
version = "4.3.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "uv" },
]

[[package]]
name = "uv"
version = "0.12.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "gunicorn"
version = "23.0.0"
source = { registry = "https://pypi.org/simple" }
"""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "uv.lock"), "w") as fh:
                fh.write(lock)
            dev = {p[1]: p[4] for p in deps.collect_packages(tmp, ["uv.lock"]) if p[1] != "app"}
        self.assertEqual(dev, {"flask": False, "pre-commit-uv": True, "uv": True, "gunicorn": False})
