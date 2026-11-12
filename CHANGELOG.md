# Changelog

## 0.2.0: first release as agentharden

The project was called `hardn` until this release. The PyPI name `hardn` and the `hardn` command belong to an
unrelated company, so the tool is now `agentharden`. Every name moved with it: the command, the Python package,
`.agentharden/` for output, `.agentharden-ignore`, `.agentharden-baseline.json`, the `agentharden:ignore` comment,
`~/.agentharden` for advisory data and `AGENTHARDEN_*` environment variables.

Safety of the fix loop
- Everything taken from the scanned repo reaches the prompt inside fenced, labelled data blocks that cannot be
  broken out of, with control and invisible characters removed. The agent is told those blocks are untrusted.
- `agentharden fix` checks each round for cheating: added suppression comments, edits to ignore, baseline and
  scanner config files, deleted or emptied source and tests, commented-out code, and changes to the test command.
  A round that cheats gets no credit, and the run fails if the cheat stays.
- Agents and tests run with an allowlisted environment, in their own process group, with timeouts.
- Repo config for Claude Code (hooks, permissions, MCP servers) is not loaded. Codex uses
  `--sandbox workspace-write` because `--full-auto` was removed in Codex 0.144.
- New `benchmarks/attacks`: 10 injection cases, 20 cheating agents and 6 legitimate controls. All 36 pass. Version
  0.1.0 stopped none of the 30 attacks.

Security of the scanner itself
- Scanning no longer runs programs named in the scanned repo's `.git/config` (`core.fsmonitor`, filters, hooks).
- Only regular files are read, never through a symlink out of the scanned folder, with bounded reads. Output files
  refuse symlinks and are written with mode 0600. Terminal output strips control sequences.
- Optional engines run with agentharden's own configuration, so a repo's `.gitleaks.toml` or `.bandit` cannot
  switch them off.
- `scan --untrusted` ignores the repo's own ignore file, baseline and suppression comments.

Honest results
- Checks that could not run are listed as blind spots on every scan and cap the level at L2. `--strict` exits 3.
  With no advisory data, 0.1.0 reported "L3 Hardened 95/100".
- Findings in tests, docs, examples, vendored code and dev dependencies are listed separately and do not set the
  level or fail CI. Secrets count everywhere, except generic sample values in docs and examples.
- The summary always shows how many findings were suppressed inline, excluded by `.agentharden-ignore` or baselined.

Detection, measured on a frozen holdout of 188 labelled cases (seed 20261110)
- Python taint recall 65.3% → 93.9%, JavaScript taint 60.5% → 81.6%, code rules 82.1% → 97.4%,
  secrets 70.8% → 87.5% with precision 58.6% → 87.5%.
- Reflected XSS, FastAPI `Annotated` parameters, import aliases, `.format` and concatenated SQL, same-file helpers.
- A committed `.env` with a provider key is found; private-key bodies are fully redacted.

Dependencies
- New lockfile support: pnpm, bun.lock, Pipfile.lock, pdm.lock, pom.xml, gradle.lockfile, go.sum, nested
  requirements files. Dev and transitive packages are marked. Severity comes from CVSS vectors.
- The suggested upgrade is the smallest version that clears every advisory.
- Exact advisory agreement with the live OSV API on 1,716 sampled packages: 92.5% → 94.2%, or 97.6% → 99.4% when
  advisories published after the local database was downloaded are left out (measured 2026-11-11).

CI and packaging
- `--diff` compares from the merge base and handles quoted and unprefixed paths. Baselines survive file moves.
- SARIF validates against the 2.1.0 schema and carries `security-severity`. The Action uploads it.
- Actions are pinned by commit SHA. Releases run only on `vX.Y.Z` tags. Dependabot is removed.
- Large repos scan about three times faster (next.js: 156 s → 48 s).

## 0.1.0: first public release as hardn (2026-10-27)

- Secrets, about 50 code rules, posture checks, offline dependency audit (OSV.dev + CISA KEV).
- Taint analysis for Python (AST) and JavaScript/TypeScript (line based).
- `FIX_PROMPT.md` scoped to the next security level; `fix` drives Claude Code, aider or Codex.
- Baselines, `--diff`, `init`, the GitHub Action, optional Semgrep, Gitleaks, Bandit and Trivy.
