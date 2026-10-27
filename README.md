# hardn

**Find security holes offline. Get a prompt your AI agent can actually fix them with.**

[![ci](https://github.com/saideepreddy7781/hardn/actions/workflows/ci.yml/badge.svg)](https://github.com/saideepreddy7781/hardn/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/hardn)](https://pypi.org/project/hardn/)
![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)

```
$ hardn ./my-app

  hardn 0.1.0 · my-app
  Engines   ✓ built-in  ✓ osv  – semgrep  – gitleaks  – bandit  – trivy
  Stack     JavaScript, Python, Express, Flask
  Scanned   214 files in 0.81s

  CRITICAL  SEC001    AWS access key ID                                    config.js:2
  CRITICAL  PYT002    Command injection: request data reaches a shell      app.py:61
  CRITICAL  DEP-PyPI  pyyaml@5.3: 4 known vulnerabilities                  requirements.txt
  HIGH      JST001    SQL injection: request data reaches a SQL query      server.js:58
  ...
  Level     ▰▱▱▱▱  L0 Exposed   score 0/100 (F)

  → Next: L2 Baseline — 22 tasks written to .hardn/FIX_PROMPT.md
    claude "$(cat .hardn/FIX_PROMPT.md)"
```

## Why hardn

- **Your code never leaves your machine.** Zero dependencies, no telemetry, no account. Scans are fully
  offline; `hardn update` is the only command that touches the network (to download public advisories).
- **Finds real flows, not just patterns.** Follows request data across lines to the dangerous call —
  `request.args → customer → query → execute()` — using Python's own AST, plus taint tracking for JS/TS.
- **Writes the fix prompt for you.** Grouped tasks with `file:line`, the data flow, CWE, a stack-specific
  fix, a "done when" check, guardrails, and a re-scan step. Secrets are always redacted.
- **Levels up one step at a time.** L0 Exposed → L1 Basic → L2 Baseline → L3 Hardened → L4 Fortified.
  Each prompt targets the next level, so every change is a reviewable diff, not a rewrite.
- **Can do the fixing too.** `hardn fix` runs Claude Code / aider / Codex on the prompt, re-scans, and
  repeats until the level is reached — on a new git branch, never committing for you.
- **Fits CI without the noise.** Baselines and `--diff` mean PRs fail only on *new* problems.

## Install

```bash
pipx install hardn          # recommended (or: pip install hardn)
hardn update                # once, while online: OSV advisories + CISA known-exploited list
```

No Python? Grab a standalone binary from [Releases](https://github.com/saideepreddy7781/hardn/releases)
(Linux, macOS, Windows), or the single-file `hardn.pyz` (needs only `python3`).

## Use it

```bash
hardn                                   # scan the current directory → .hardn/FIX_PROMPT.md
hardn ./app --target hardened           # aim for a specific level
hardn scan --print-prompt | claude -p   # pipe the prompt straight into an agent
hardn fix                               # let an agent fix it: scan → fix → re-scan, up to 3 rounds
hardn fix --agent aider --test "npm test"   # any agent; feed test failures back in
hardn scan --diff origin/main           # only findings on lines you changed
hardn baseline                          # accept current findings; only new ones count from now on
hardn init                              # add a GitHub Actions check (SARIF → Security tab)
hardn rules PY004                       # explain a rule
hardn doctor                            # what's installed, what's optional
```

Suppress a verified false positive with a `hardn:ignore` comment on the line (`nosec`, `nosemgrep`
and `gitleaks:allow` are honored too). Skip paths with a `.hardnignore` file.

### In CI

`hardn init` writes a ready workflow, or use the action directly:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: saideepreddy7781/hardn@v0
  with:
    fail-on: high      # PRs fail only on new high/critical findings in changed lines
```

Or as a [pre-commit](https://pre-commit.com) hook:

```yaml
- repo: https://github.com/saideepreddy7781/hardn
  rev: v0.1.0
  hooks: [{ id: hardn }]
```

## What it checks

| Engine | What |
|---|---|
| **Secrets** | Cloud/API keys (AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, Google…), private keys, credentialed connection strings, high-entropy credentials, `.env` files committed or not git-ignored |
| **Taint flows** | Request data → SQL, shell, eval, SSRF, file paths, redirects, deserialization, template injection, XSS, NoSQL, prototype pollution. Python (Flask, Django, FastAPI, Starlette) via AST; JS/TS (Express, Koa, browser) via line tracking |
| **Code rules** | ~50 rules across Python, JS/TS, Go, Java/Kotlin, PHP, Ruby, Dockerfiles, GitHub Actions, Kubernetes, Terraform |
| **Posture** | Missing defenses: security headers/CSP, rate limiting, input validation, Django deploy settings, lockfiles, version pinning, non-root containers, Dependabot, CI scanning |
| **Dependencies** | npm, PyPI, Go, Maven, RubyGems, crates.io, Packagist lockfiles vs. [OSV.dev](https://osv.dev) (GitHub advisories, PyPA, RustSec, Go vulndb, malicious packages). Anything on CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list is escalated to critical |
| **Optional** | [Semgrep](https://semgrep.dev), [Gitleaks](https://github.com/gitleaks/gitleaks), [Bandit](https://github.com/PyCQA/bandit), [Trivy](https://trivy.dev) — used automatically when installed, results merged and de-duplicated |

## Security levels

| Level | Name | Meaning | Prompt fixes |
|---|---|---|---|
| L0 | Exposed | critical issues open | — |
| L1 | Basic | no criticals | critical |
| L2 | Baseline | no criticals or highs | + high |
| L3 | Hardened | nothing above low | + medium |
| L4 | Fortified | only informational items | + low |

## FAQ

**Does any of my code get uploaded?** No. hardn never sends code anywhere. If you then paste the prompt
into a cloud AI, that's your choice — use a local model (e.g. aider + Ollama) to stay fully offline.

**How accurate is it?** Taint analysis is intra-file and heuristic for JS; expect some false positives
and misses. Every finding has a rule ID — report noise with the "False positive" issue template.
Install Semgrep for deeper cross-language analysis.

**Is `hardn fix` safe?** It only runs in a git repo with a clean tree, works on a new branch, asks before
starting, and never commits or pushes. Review `git diff` like any PR. Credential rotation is always left
to you.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).
Apache-2.0 licensed.
