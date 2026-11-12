from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import traceback

from . import __version__, baseline, code_rules, deps, engines, fix, gitdiff, output, prompt, scanner, walker
from .models import SEV_RANK, SEVERITIES
from .scoring import LEVELS, TARGETS

COMMANDS = {"scan", "fix", "baseline", "init", "update", "doctor", "rules"}
EPILOG = """examples:
  hardn                               scan the current directory
  hardn ./app --target hardened       prompt for a specific security level
  hardn fix --agent claude            let a coding agent fix it, re-scan, repeat
  hardn scan --diff origin/main       only findings on lines changed since main
  hardn baseline                      accept current findings; fail only on new ones
  hardn init                          add a GitHub Actions workflow to this repo
  hardn scan ./theirs --untrusted     ignore the repo's own .hardnignore, baseline and suppressions

exit codes:
  0  no app-code finding at or above --fail-on
  1  at least one app-code finding at or above --fail-on (findings in tests, docs or examples never fail)
  2  usage or runtime error, including a report that could not be written
  3  only with --strict: the scan had blind spots (checks that could not run). Exit 1 takes precedence.
"""


class UsageError(Exception):
    pass


def _utf8_streams() -> None:
    """Windows consoles/pipes default to cp1252; never crash on → ▰ ✓ in output."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure") and (stream.encoding or "").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv=None) -> int:
    _utf8_streams()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")  # `hardn` / `hardn ./app` == `hardn scan ./app`

    p = argparse.ArgumentParser(prog="hardn", description="Offline security scanner → AI-ready remediation prompt.",
                                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"hardn {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="command")

    def common(sp):
        sp.add_argument("path", nargs="?", default=".")
        sp.add_argument("-t", "--target", choices=list(TARGETS), help="security level to reach (default: next level up)")
        sp.add_argument("--no-external", action="store_true", help="only use built-in engines")
        sp.add_argument("--max-tasks", type=int, default=30, help="cap tasks per prompt (default: 30 for scan, 15 for fix)")

    s = sub.add_parser("scan", help="scan a codebase and write the fix prompt (default command)",
                       epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    common(s)
    s.add_argument("-o", "--out", help="output directory (default: <path>/.hardn)")
    s.add_argument("--fail-on", choices=SEVERITIES[1:],
                   help="exit 1 if an app-code finding is at or above this severity")
    s.add_argument("--diff", nargs="?", const="HEAD", metavar="REF",
                   help="only report findings on lines changed since REF (default HEAD), compared from the merge "
                        "base, plus untracked files")
    s.add_argument("--baseline", metavar="FILE", help=f"baseline file (default: <path>/{baseline.FILENAME} if present)")
    s.add_argument("--no-baseline", action="store_true", help="ignore the baseline file")
    s.add_argument("--sarif", action="store_true", help="also write results.sarif (GitHub code scanning)")
    s.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    s.add_argument("--copy", action="store_true", help="copy the prompt to the clipboard")
    s.add_argument("--print-prompt", action="store_true", help="print the prompt to stdout instead of the summary")
    s.add_argument("-v", "--verbose", action="store_true", help="list every finding and engine detail")
    s.add_argument("-q", "--quiet", action="store_true", help="no summary output (blind spots still go to stderr)")
    s.add_argument("--strict", action="store_true",
                   help="exit 3 when the scan has blind spots (checks that could not run)")
    s.add_argument("--untrusted", action="store_true",
                   help="for repos you do not trust: ignore their .hardnignore, baseline and inline suppressions, "
                        "and count findings in tests, docs and examples too")

    fx = sub.add_parser("fix", help="run a coding agent on the prompt, re-scan, and repeat until the target level")
    common(fx)
    fx.set_defaults(max_tasks=15)
    fx.add_argument("--agent", help=f"{' | '.join(fix.AGENTS)} | a custom command (use {{prompt_file}} or stdin). "
                                    "Default: first one installed")
    fx.add_argument("--rounds", type=int, default=3, help="max scan→fix rounds (default 3)")
    fx.add_argument("--test", metavar="CMD", help="test command to run after each round, e.g. 'npm test'")
    fx.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")
    fx.add_argument("--no-branch", action="store_true", help="work on the current branch")
    fx.add_argument("--allow-dirty", action="store_true", help="allow uncommitted changes")
    fx.add_argument("--timeout", type=int, default=1800, help="seconds per agent round (default 1800)")
    fx.add_argument("--test-timeout", type=int, default=fix.TEST_TIMEOUT,
                    help=f"seconds allowed for the --test command (default {fix.TEST_TIMEOUT})")
    fx.add_argument("--baseline", metavar="FILE", help=f"baseline file (default: <path>/{baseline.FILENAME} if present)")
    fx.add_argument("--no-baseline", action="store_true", help="ignore the baseline file")

    b = sub.add_parser("baseline", help=f"record current findings in {baseline.FILENAME} (commit it)")
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("--no-external", action="store_true")

    i = sub.add_parser("init", help="add a GitHub Actions workflow (and optionally a baseline) to a repo")
    i.add_argument("path", nargs="?", default=".")
    i.add_argument("--fail-on", choices=SEVERITIES[1:], default="high")
    i.add_argument("--baseline", action="store_true", help="also record a baseline so CI starts green")
    i.add_argument("--force", action="store_true", help="overwrite an existing workflow file")

    u = sub.add_parser("update", help="download advisory databases (the only command that uses the network)")
    u.add_argument("--ecosystems", help=f"comma-separated OSV ecosystems (default: {','.join(deps.DEFAULT_ECOSYSTEMS)})")
    u.add_argument("--for", dest="for_path", metavar="PATH", help="only the ecosystems used by the project at PATH")
    u.add_argument("--semgrep-rules", action="store_true", help="also clone/refresh the Semgrep community rules")

    sub.add_parser("doctor", help="show engines, databases, and how to install missing tools")
    r = sub.add_parser("rules", help="list every rule, or explain one: hardn rules PY004")
    r.add_argument("rule", nargs="?")

    a = p.parse_args(argv)
    try:
        if a.cmd == "fix":
            return cmd_fix(a)
        if a.cmd == "baseline":
            return cmd_baseline(a)
        if a.cmd == "init":
            return cmd_init(a)
        if a.cmd == "update":
            return cmd_update(a)
        if a.cmd == "doctor":
            return cmd_doctor()
        if a.cmd == "rules":
            return cmd_rules(a)
        return cmd_scan(a)
    except (fix.FixError, gitdiff.DiffError, baseline.BaselineError, output.OutputError, UsageError) as exc:
        print(f"hardn: {output.clean(exc)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nhardn: interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        try:  # the reader went away (e.g. `| head`): stop quietly
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 0
    except Exception:  # noqa: BLE001 - exit 2, never 1, so CI can tell a crash from findings
        traceback.print_exc()
        print("hardn: unexpected error (exit 2). Please report it with the traceback above.", file=sys.stderr)
        return 2


def _require_dir(path: str) -> None:
    if not os.path.isdir(path):
        raise UsageError(f"not a directory: {path}")


def _inside(path: str, root: str) -> bool:
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _baseline_path(a, root: str):
    """The baseline file to apply, or None."""
    if a.no_baseline:
        return None
    if a.baseline:
        path = os.path.abspath(a.baseline)
        if a.untrusted and _inside(path, root):
            raise UsageError("--untrusted ignores baselines inside the scanned repo; keep yours outside it")
        if not os.path.lexists(path):
            raise UsageError(f"baseline file not found: {a.baseline}")
        return path
    if a.untrusted:
        return None
    path = baseline.path_for(root)
    return path if os.path.lexists(path) else None


def cmd_scan(a) -> int:
    _require_dir(a.path)
    root = os.path.abspath(a.path)
    if a.diff is not None and not a.diff.strip():
        raise UsageError("--diff needs a git ref, for example --diff origin/main (or --diff alone for HEAD)")
    changes = gitdiff.changed_lines(root, a.diff) if a.diff else None  # a bad ref fails before the scan
    bl_path = _baseline_path(a, root)
    known = baseline.load(bl_path) if bl_path else None
    out_dir = os.path.abspath(a.out) if a.out else os.path.join(root, ".hardn")
    stdout_only = a.print_prompt or a.json
    out_error = None
    try:
        output.ensure_out_dir(out_dir)
    except output.OutputError as exc:
        if not stdout_only:
            raise  # nothing would be delivered, so fail before spending time on the scan
        out_error = exc

    show_log = not (a.quiet or stdout_only) and sys.stderr.isatty()
    log = (lambda m: print(output.c(f"  {output.clean(m)}", "2"), file=sys.stderr)) if show_log else (lambda *_: None)
    result = scanner.run(root, external=not a.no_external, log=log, untrusted=a.untrusted)

    scope, meta = [], {}
    if known is not None:
        is_new = (lambda f: gitdiff.touches(f, changes)) if changes is not None else None
        result.findings, old = baseline.split(result.findings, known, is_new=is_new, root=root)
        scope.append(f"baseline {output.rel(bl_path)}")
        meta["baselined"] = len(old)
        meta["baseline"] = {"path": bl_path, "hidden": len(old)}
    if not a.untrusted:
        result.hidden["baselined"] = meta.get("baselined", 0)
    whole = list(result.findings)
    level_findings = None
    if changes is not None:
        result.findings = gitdiff.keep(whole, changes)
        level_findings = whole
        scope.append(f"changed lines since {a.diff}: {len(result.findings)} of {len(whole)} findings")
        meta["diff"] = {"ref": a.diff, "base": changes.base, "total": len(whole), "kept": len(result.findings)}

    target = TARGETS[a.target] if a.target else None
    text, target, n_tasks = prompt.build(result, target=target, max_tasks=a.max_tasks)
    report = output.report_dict(result, meta, level_findings=level_findings)
    prompt_path = os.path.join(out_dir, "FIX_PROMPT.md")
    if out_error is None:
        try:
            output.write_file(out_dir, "FIX_PROMPT.md", text)
            output.write_file(out_dir, "report.json", json.dumps(report, indent=2) + "\n")
            if a.sarif:
                output.write_sarif(result, os.path.join(out_dir, "results.sarif"), prefix=gitdiff.repo_prefix(root))
        except output.OutputError as exc:
            if not stdout_only:
                raise
            out_error = exc

    if a.json:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    elif a.print_prompt:
        print(output.clean(text, multiline=True))
    elif not a.quiet:
        print(output.render(result, output.rel(prompt_path), target, n_tasks, show=10_000 if a.verbose else 15,
                            verbose=a.verbose, scope=" · ".join(scope), level_findings=level_findings))
    if a.quiet or stdout_only:
        for line in output.blind_spot_lines(result):
            print(line, file=sys.stderr)
    if a.copy:
        _copy(text, a.quiet)

    if out_error is not None:
        print(f"hardn: {output.clean(out_error)}", file=sys.stderr)
        return 2
    if a.fail_on and any(f.counts and f.rank >= SEV_RANK[a.fail_on] for f in result.findings):
        return 1
    if a.strict and result.gaps:
        return 3
    return 0


def cmd_fix(a) -> int:
    _require_dir(a.path)
    return fix.run(a.path, agent=a.agent, target=TARGETS[a.target] if a.target else None, max_rounds=a.rounds,
                   test_cmd=a.test, external=not a.no_external, yes=a.yes, branch=not a.no_branch,
                   allow_dirty=a.allow_dirty, max_tasks=a.max_tasks, timeout=a.timeout,
                   test_timeout=a.test_timeout, baseline_file=a.baseline, use_baseline=not a.no_baseline)


def cmd_baseline(a) -> int:
    _require_dir(a.path)
    result = scanner.run(a.path, external=not a.no_external)
    path = baseline.save(result.root, result.findings)
    counts = " · ".join(f"{sum(1 for f in result.findings if f.severity == s)} {s}"
                        for s in reversed(SEVERITIES) if any(f.severity == s for f in result.findings))
    print(f"\n  {output.c('✓', '32')} Baselined {len(result.findings)} finding(s) → {output.clean(output.rel(path))}"
          + (f"  ({counts})" if counts else ""))
    print("    Commit this file. `hardn scan` now reports only new findings; use --no-baseline to see everything.")
    for line in output.blind_spot_lines(result):
        print(f"    {line.strip()}")
    print()
    return 0


# Actions are pinned to full commit SHAs. The comment names the release each SHA belongs to.
WORKFLOW = """\
# Generated by `hardn init`: https://github.com/saideepreddy7781/hardn
name: hardn security scan

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read
  security-events: write   # upload SARIF to the Security tab

jobs:
  hardn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0     # needed for --diff on pull requests
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0  # v7.1.0
        with:
          python-version: "3.12"
      # Installs this exact release from GitHub. The PyPI name "hardn" belongs to an unrelated project.
      - run: pip install "git+https://github.com/saideepreddy7781/hardn@v__VERSION__"
      - id: week
        run: echo "w=$(date +%G-%V)" >> "$GITHUB_OUTPUT"
      - uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9  # v6.1.0, advisory DB refreshed weekly
        with:
          path: ~/.hardn
          key: hardn-db-${{ steps.week.outputs.w }}
          restore-keys: hardn-db-
      - run: hardn update --for . || echo "advisory update failed; scanning with cached data"
      - name: Scan
        env:
          BASE_REF: ${{ github.base_ref }}
        run: |
          if [ -n "$BASE_REF" ]; then
            hardn scan . --sarif --fail-on __FAIL_ON__ --diff "origin/$BASE_REF"
          else
            hardn scan . --sarif --fail-on __FAIL_ON__
          fi
      - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066  # v4.39.3
        if: always()
        continue-on-error: true   # code scanning must be enabled for the repo
        with:
          sarif_file: .hardn/results.sarif
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9  # v7.0.2
        if: always()
        with:
          name: hardn-report
          path: .hardn/
          include-hidden-files: true
"""


def workflow_text(fail_on: str) -> str:
    return WORKFLOW.replace("__FAIL_ON__", fail_on).replace("__VERSION__", __version__)


def cmd_init(a) -> int:
    _require_dir(a.path)
    root = os.path.abspath(a.path)
    wf_dir = os.path.join(root, ".github", "workflows")
    wf = os.path.join(wf_dir, "hardn.yml")
    wrote = False
    if os.path.lexists(wf) and not a.force:
        print(f"  {output.clean(output.rel(wf))} already exists (use --force to overwrite)")
    else:
        try:
            os.makedirs(wf_dir, exist_ok=True)
        except OSError as exc:
            raise output.OutputError(f"cannot create {wf_dir}: {exc.strerror or exc}") from exc
        output.write_file(wf_dir, "hardn.yml", workflow_text(a.fail_on))
        os.chmod(wf, 0o644)  # a workflow is meant to be committed and read by others
        wrote = True
        print(f"  {output.c('✓', '32')} wrote {output.clean(output.rel(wf))} "
              f"(fails PRs on {a.fail_on}+ findings in changed lines)")
    if a.baseline:
        result = scanner.run(root, external=False)
        path = baseline.save(root, result.findings)
        wrote = True
        print(f"  {output.c('✓', '32')} baselined {len(result.findings)} finding(s) → {output.clean(output.rel(path))}")
    if wrote:
        print("\n  Commit the new file(s) and push. Each PR now gets a hardn check.\n")
    return 0


def cmd_rules(a) -> int:
    catalog = output.rule_catalog()
    if a.rule:
        r = output.explain_rule(a.rule, catalog)
        if not r:
            print(f"hardn: unknown rule {output.clean(a.rule)} (see `hardn rules`)", file=sys.stderr)
            return 2
        print(f"\n  {output.c(r['id'], '1')} · {r['severity']} · {r['cwe'] or 'no CWE'} · {r['kind']}\n  {r['title']}\n")
        if r.get("applies"):
            print(f"  Applies to: {r['applies']}")
        print(f"  Fix: {r['fix']}\n")
        if r["kind"] in ("code", "config", "secret"):
            print("  Suppress a verified false positive with a `hardn:ignore` comment on the line.\n")
        elif r["kind"] in ("taint", "posture", "dependency"):
            print("  Accept a verified false positive with `hardn baseline`, or exclude the path in .hardnignore.\n")
        return 0
    for rid, r in catalog.items():
        print(f"{rid:<8} {r['severity']:<9} {r['cwe'] or '-':<10} {r['title']}")
    print("\nAlso: DEP-<ecosystem> for vulnerable dependencies, and gitleaks:*, bandit:*, trivy:* and Semgrep rule "
          "ids from external engines.")
    return 0


def _copy(text: str, quiet: bool) -> None:
    for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"], ["clip"]):
        if shutil.which(cmd[0]):
            subprocess.run(cmd, input=text.encode("utf-8", "replace"), check=False, timeout=30)
            if not quiet:
                print(output.c("  ✓ prompt copied to clipboard", "32"))
            return
    print("hardn: no clipboard tool found (pbcopy / wl-copy / xclip)", file=sys.stderr)


def cmd_update(a) -> int:
    if a.ecosystems:
        ecos = [e.strip() for e in a.ecosystems.split(",") if e.strip()]
    elif a.for_path:
        _require_dir(a.for_path)
        _, all_paths = walker.walk(a.for_path)
        ecos = sorted({p[0] for p in deps.collect_packages(a.for_path, all_paths)})
        if not ecos:
            print(f"No lockfiles found in {output.clean(a.for_path)}; nothing to download.")
            return 0
    else:
        ecos = list(deps.DEFAULT_ECOSYSTEMS)
    print(f"Updating advisory databases in {deps.HOME} (network required for this step only)")
    failures = deps.update(ecos)
    if a.semgrep_rules:
        dest = engines.SEMGREP_RULES
        if not shutil.which("git"):
            print("  ! git not found; cannot fetch semgrep rules")
        elif (dest / ".git").is_dir():
            print(f"  ↻ semgrep-rules → {dest}")
            subprocess.run(["git", "-C", str(dest), "pull", "--ff-only", "-q"], check=False)
        else:
            print(f"  ↓ semgrep-rules → {dest}")
            subprocess.run(["git", "clone", "--depth", "1", "-q", "https://github.com/semgrep/semgrep-rules", str(dest)],
                           check=False)
    if failures:
        print(f"Finished with {failures} failed source(s); scans will use whatever data is present.")
        return 1
    print("Done. Scans are fully offline from here.")
    return 0


def cmd_doctor() -> int:
    ok, dash = output.c("✓", "32"), output.c("–", "33")
    print(f"\nhardn {__version__} · Python {sys.version.split()[0]} · home {deps.HOME}\n")
    print(f"  {ok} built-in engines: {len(code_rules.RULES)} code rules, Python AST + JS taint tracking, secrets, "
          "posture checks")
    st = deps.status()
    if st["present"]:
        age = f"{st['age_days']:.0f} days old" if st.get("age_days") is not None else "age unknown"
        ecos = ", ".join(f"{k} {v:,}" for k, v in sorted(st["ecosystems"].items()))
        print(f"  {ok} OSV advisories ({age}): {ecos}; CISA KEV {st['kev']:,} CVEs")
    else:
        print(f"  {dash} OSV advisory DB missing: run `hardn update` once while online")
    for name, path in engines.available().items():
        if path:
            extra = ""
            if name == "semgrep" and not engines.SEMGREP_RULES.is_dir() and not os.environ.get("HARDN_SEMGREP_CONFIG"):
                extra = output.c("  (no offline rules: `hardn update --semgrep-rules`)", "33")
            print(f"  {ok} {name:<9} {path}{extra}")
        else:
            print(f"  {dash} {name:<9} optional: {engines.INSTALL_HINTS[name]}")
    agents = [n for n in fix.AGENTS if shutil.which(n)]
    print(f"  {ok if agents else dash} agents for `hardn fix`: {', '.join(agents) or 'none (install Claude Code, aider, or Codex)'}")
    print("\nLevels: " + " → ".join(f"L{i} {n}" for i, n in enumerate(LEVELS)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
