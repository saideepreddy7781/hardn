from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

from . import __version__, baseline, deps, engines, fix, gitdiff, output, prompt, scanner, walker
from .code_rules import RULES
from .models import SEV_RANK, SEVERITIES
from .scoring import LEVELS, TARGETS

COMMANDS = {"scan", "fix", "baseline", "init", "update", "doctor", "rules"}
EPILOG = """examples:
  hardn                               scan the current directory
  hardn ./app --target hardened       prompt for a specific security level
  hardn fix --agent claude            let a coding agent fix it, re-scan, repeat
  hardn scan --diff origin/main       only findings on lines changed vs main
  hardn baseline                      accept current findings; fail only on new ones
  hardn init                          add a GitHub Actions workflow to this repo
"""


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
        sp.add_argument("--max-tasks", type=int, default=30, help="cap tasks per prompt (default 30)")

    s = sub.add_parser("scan", help="scan a codebase and write the fix prompt (default command)")
    common(s)
    s.add_argument("-o", "--out", help="output directory (default: <path>/.hardn)")
    s.add_argument("--fail-on", choices=SEVERITIES[1:], help="exit 1 if any finding is at or above this severity")
    s.add_argument("--diff", nargs="?", const="HEAD", metavar="REF",
                   help="only report findings on lines changed vs REF (default HEAD) plus untracked files")
    s.add_argument("--baseline", metavar="FILE", help=f"baseline file (default: <path>/{baseline.FILENAME} if present)")
    s.add_argument("--no-baseline", action="store_true", help="ignore the baseline file")
    s.add_argument("--sarif", action="store_true", help="also write results.sarif (GitHub code scanning)")
    s.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    s.add_argument("--copy", action="store_true", help="copy the prompt to the clipboard")
    s.add_argument("--print-prompt", action="store_true", help="print the prompt to stdout instead of the summary")
    s.add_argument("-v", "--verbose", action="store_true", help="list every finding and engine detail")
    s.add_argument("-q", "--quiet", action="store_true", help="no summary output")

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
    r = sub.add_parser("rules", help="list built-in rules, or explain one: hardn rules PY004")
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
    except (fix.FixError, gitdiff.DiffError) as exc:
        print(f"hardn: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nhardn: interrupted", file=sys.stderr)
        return 130


def _require_dir(path: str) -> None:
    if not os.path.isdir(path):
        raise fix.FixError(f"not a directory: {path}")


def cmd_scan(a) -> int:
    _require_dir(a.path)
    log = (lambda m: print(output.c(f"  {m}", "2"), file=sys.stderr)) if not a.quiet and sys.stderr.isatty() else (lambda *_: None)
    result = scanner.run(a.path, external=not a.no_external, log=log)

    scope, meta = [], {}
    if a.diff:
        total = len(result.findings)
        result.findings = gitdiff.keep(result.findings, gitdiff.changed_lines(result.root, a.diff))
        scope.append(f"changed lines vs {a.diff}: {len(result.findings)} of {total} findings")
        meta["diff"] = {"ref": a.diff, "total": total}
    bl_path = a.baseline or baseline.path_for(result.root)
    if not a.no_baseline and os.path.isfile(bl_path):
        result.findings, old = baseline.split(result.findings, baseline.load(bl_path))
        scope.append(f"{len(old)} baselined finding(s) hidden ({output.rel(bl_path)})")
        meta["baselined"] = len(old)
    elif a.baseline:
        raise fix.FixError(f"baseline file not found: {a.baseline}")

    out_dir = a.out or os.path.join(result.root, ".hardn")
    output.ensure_out_dir(out_dir)
    target = TARGETS[a.target] if a.target else None
    text, target, n_tasks = prompt.build(result, target=target, max_tasks=a.max_tasks)
    prompt_path = os.path.join(out_dir, "FIX_PROMPT.md")
    with open(prompt_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    report_path = os.path.join(out_dir, "report.json")
    output.write_json(result, report_path, meta)
    if a.sarif:
        output.write_sarif(result, os.path.join(out_dir, "results.sarif"))

    if a.json:
        with open(report_path, encoding="utf-8") as fh:
            sys.stdout.write(fh.read() + "\n")
    elif a.print_prompt:
        print(text)
    elif not a.quiet:
        print(output.render(result, output.rel(prompt_path), target, n_tasks, show=10_000 if a.verbose else 15,
                            verbose=a.verbose, scope=" · ".join(scope)))
    if a.copy:
        _copy(text, a.quiet)

    if a.fail_on and any(f.rank >= SEV_RANK[a.fail_on] for f in result.findings):
        return 1
    return 0


def cmd_fix(a) -> int:
    _require_dir(a.path)
    return fix.run(a.path, agent=a.agent, target=TARGETS[a.target] if a.target else None, max_rounds=a.rounds,
                   test_cmd=a.test, external=not a.no_external, yes=a.yes, branch=not a.no_branch,
                   allow_dirty=a.allow_dirty, max_tasks=a.max_tasks, timeout=a.timeout)


def cmd_baseline(a) -> int:
    _require_dir(a.path)
    result = scanner.run(a.path, external=not a.no_external)
    path = baseline.save(result.root, result.findings)
    counts = " · ".join(f"{sum(1 for f in result.findings if f.severity == s)} {s}"
                        for s in reversed(SEVERITIES) if any(f.severity == s for f in result.findings))
    print(f"\n  {output.c('✓', '32')} Baselined {len(result.findings)} finding(s) → {output.rel(path)}"
          + (f"  ({counts})" if counts else ""))
    print("    Commit this file. `hardn scan` now reports only new findings; use --no-baseline to see everything.\n")
    return 0


WORKFLOW = """\
# Generated by `hardn init` — https://pypi.org/project/hardn/
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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # needed for --diff on pull requests
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install hardn
      - id: week
        run: echo "w=$(date +%G-%V)" >> "$GITHUB_OUTPUT"
      - uses: actions/cache@v4      # advisory DB, refreshed weekly
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
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        continue-on-error: true   # code scanning must be enabled for the repo
        with:
          sarif_file: .hardn/results.sarif
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: hardn-report
          path: .hardn/
          include-hidden-files: true
"""


def cmd_init(a) -> int:
    _require_dir(a.path)
    root = os.path.abspath(a.path)
    wf = os.path.join(root, ".github", "workflows", "hardn.yml")
    if os.path.exists(wf) and not a.force:
        print(f"  {output.rel(wf)} already exists (use --force to overwrite)")
    else:
        os.makedirs(os.path.dirname(wf), exist_ok=True)
        with open(wf, "w", encoding="utf-8") as fh:
            fh.write(WORKFLOW.replace("__FAIL_ON__", a.fail_on))
        print(f"  {output.c('✓', '32')} wrote {output.rel(wf)} (fails PRs on {a.fail_on}+ findings in changed lines)")
    if a.baseline:
        result = scanner.run(root, external=False)
        print(f"  {output.c('✓', '32')} baselined {len(result.findings)} finding(s) → "
              f"{output.rel(baseline.save(root, result.findings))}")
    print("\n  Commit the new file(s) and push. Each PR now gets a hardn check.\n")
    return 0


def cmd_rules(a) -> int:
    if a.rule:
        r = next((r for r in RULES if r.id.lower() == a.rule.lower()), None)
        if not r:
            print(f"hardn: unknown rule {a.rule} (see `hardn rules`)", file=sys.stderr)
            return 2
        print(f"\n  {output.c(r.id, '1')} · {r.severity} · {r.cwe}\n  {r.title}\n")
        print(f"  Applies to: {', '.join(r.targets)}")
        print(f"  Fix: {r.fix}\n")
        print("  Suppress a verified false positive with a `hardn:ignore` comment on the line.\n")
        return 0
    for r in RULES:
        print(f"{r.id:<8} {r.severity:<9} {r.cwe:<10} {r.title}")
    print("\nAlso: secrets (SEC*), taint flows (PYT*/JST*), posture (POS*), dependencies (DEP-*).")
    return 0


def _copy(text: str, quiet: bool) -> None:
    for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"], ["clip"]):
        if shutil.which(cmd[0]):
            subprocess.run(cmd, input=text.encode(), check=False)
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
            print(f"No lockfiles found in {a.for_path}; nothing to download.")
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
    print(f"  {ok} built-in engines: {len(RULES)} code rules, Python AST + JS taint tracking, secrets, posture checks")
    st = deps.status()
    if st["present"]:
        age = f"{st['age_days']:.0f} days old" if st.get("age_days") is not None else "age unknown"
        ecos = ", ".join(f"{k} {v:,}" for k, v in sorted(st["ecosystems"].items()))
        print(f"  {ok} OSV advisories ({age}): {ecos}; CISA KEV {st['kev']:,} CVEs")
    else:
        print(f"  {dash} OSV advisory DB missing — run `hardn update` once while online")
    for name, path in engines.available().items():
        if path:
            extra = ""
            if name == "semgrep" and not engines.SEMGREP_RULES.is_dir() and not os.environ.get("HARDN_SEMGREP_CONFIG"):
                extra = output.c("  (no offline rules: `hardn update --semgrep-rules`)", "33")
            print(f"  {ok} {name:<9} {path}{extra}")
        else:
            print(f"  {dash} {name:<9} optional — {engines.INSTALL_HINTS[name]}")
    agents = [n for n in fix.AGENTS if shutil.which(n)]
    print(f"  {ok if agents else dash} agents for `hardn fix`: {', '.join(agents) or 'none (install Claude Code, aider, or Codex)'}")
    print("\nLevels: " + " → ".join(f"L{i} {n}" for i, n in enumerate(LEVELS)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
