# agentharden

**An offline security scanner for code your AI agent writes, with a fix loop the agent cannot cheat and a scanned
repo cannot hijack.**

[![ci](https://github.com/saideepreddy7781/agentharden/actions/workflows/ci.yml/badge.svg)](https://github.com/saideepreddy7781/agentharden/actions/workflows/ci.yml)
![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)
![attack benchmark: 36/36](https://img.shields.io/badge/attack%20benchmark-36%2F36-brightgreen)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)

agentharden scans a codebase for leaked secrets, injection flows, risky code, missing defenses and vulnerable
dependencies, with no network and no account. It writes `FIX_PROMPT.md`, a task list for Claude Code, Codex, aider
or any LLM. `agentharden fix` hands that prompt to an agent, re-scans, and repeats until the code reaches the next
security level.

Feeding scanner output to an agent that can edit files has two failure modes. The repo being scanned can plant
instructions for the agent in its comments, file names or test output. And the agent can "fix" a finding by hiding
it: a `nosec` comment, a deleted test, an edited ignore file. agentharden fences every piece of repo text as
untrusted data, checks every round's diff for cheating, and gives no credit when it finds any.
[`benchmarks/attacks`](benchmarks/attacks) is the proof you can run yourself.

```
$ agentharden examples/vulnerable-app

  agentharden 0.2.0 · examples/vulnerable-app

  Engines   ✓ built-in  – osv (8 packages checked · 1 unpinned (incomplete: see blind spots))
  Stack     JavaScript, Python, Express, Flask
  Scanned   10 files in 1.36s

  CRITICAL  SEC200    Secret in committed env file                                .env:1
  CRITICAL  SEC001    AWS access key ID                                           config.js:2
  CRITICAL  PYT002    Command injection: request data reaches a shell command     app.py:23
  CRITICAL  PYT007    Unsafe deserialization of request data                      app.py:28
  CRITICAL  PYT007    Unsafe deserialization of request data                      app.py:33
  CRITICAL  PYT002    Command injection: request data reaches a shell command     app.py:61
  CRITICAL  DEP-npm   lodash@4.17.15: 5 known vulnerabilities                     package-lock.json
  CRITICAL  DEP-npm   minimist@1.2.0: 2 known vulnerabilities                     package-lock.json
  CRITICAL  DEP-PyPI  pyyaml@5.3: 2 known vulnerabilities                         requirements.txt
  CRITICAL  JST002    Command injection: request data reaches a shell command     server.js:21
  CRITICAL  JST003    Code injection: request data reaches eval                   server.js:25
  HIGH      SEC100    Hard-coded credential                                       config.js:3
  HIGH      SEC010    Connection string with embedded password                    config.js:4
  HIGH      DK002     Secret baked into the image via ENV/ARG                     Dockerfile:3
  HIGH      PYT001    SQL injection: request data reaches a SQL query             app.py:18
  … 41 more (full list: --verbose or report.json)

  Blind spots  agentharden could not check the following, so this result is incomplete:
    ! 1 PyPI requirement in requirements.txt has no pinned version (gunicorn), so agentharden cannot tell
      which release is installed. Pin exact versions or commit a lockfile.

  Level     ▰▱▱▱▱  L0 Exposed   score 0/100 (F)   incomplete
  Findings  11 critical · 21 high · 17 medium · 7 low · 1 info
  Hidden    0 suppressed inline · 0 files excluded by .agentharden-ignore · 0 baselined

  → Next: L2 Baseline: 26 tasks written to examples/vulnerable-app/.agentharden/FIX_PROMPT.md
    claude "$(cat examples/vulnerable-app/.agentharden/FIX_PROMPT.md)"     # or paste into Cursor / Copilot / any LLM
```

## Install

```bash
pipx install git+https://github.com/saideepreddy7781/agentharden   # or: pip install git+https://...
agentharden update        # once, while online: OSV advisories and the CISA known-exploited list
```

Python 3.9 or newer, nothing else. Standalone binaries for Linux, macOS and Windows, and a single-file
`agentharden.pyz`, are on the [Releases](https://github.com/saideepreddy7781/agentharden/releases) page.

The package called `hardn` on PyPI is unrelated. agentharden was named `hardn` until version 0.2.0.

## Use it

```bash
agentharden                                  # scan the current directory, write .agentharden/FIX_PROMPT.md
agentharden ./app --target hardened          # aim for a specific level
agentharden scan --print-prompt | claude -p  # pipe the prompt into an agent yourself
agentharden fix                              # scan → agent fixes → re-scan, up to 3 rounds, on a new branch
agentharden fix --agent codex --test "npm test"   # any agent; test failures go back into the next round
agentharden scan ./someone-elses-repo --untrusted # ignore the repo's own ignore file, baseline and suppressions
agentharden scan --diff origin/main          # only findings on lines changed since main
agentharden baseline                         # accept today's findings; from now on only new ones count
agentharden init                             # add a GitHub Actions check with SARIF upload
agentharden rules PYT001                     # explain a rule
agentharden doctor                           # what is installed, how fresh the advisory data is
```

Exit codes: 0 clean, 1 a finding at or above `--fail-on`, 2 an error, 3 blind spots with `--strict`.

### What `agentharden fix` guarantees

- It works only in a git repo, on a clean tree, on a new branch, and asks before it starts. It never commits.
- Every round's diff is checked against a snapshot taken before the first round. Added suppression comments,
  edits to ignore, baseline or scanner config files, deleted or emptied source, commented-out code, deleted or
  gutted tests, and changes to the test command all withhold credit. They go back to the agent as a revert
  instruction, and the run fails if they remain.
- A real false positive has a route that is not cheating: the agent leaves the code alone and lists it in its
  report, and you decide.
- The agent runs with an allowlisted environment, so cloud keys and tokens in your shell stay out of its reach.
  Add names with `AGENTHARDEN_PASS_ENV=AWS_PROFILE,DATABASE_URL`.
- Claude Code runs with `--setting-sources user --strict-mcp-config`, so the repo's hooks, permission rules and MCP
  servers do not load. Codex runs with `--sandbox workspace-write`.
- The agent and its child processes are killed on timeout and on Ctrl-C.

### In CI

`agentharden init` writes a workflow, or use the Action:

```yaml
- uses: actions/checkout@v7
  with: { fetch-depth: 0 }
- uses: saideepreddy7781/agentharden@v0.2.0
  with:
    fail-on: high      # pull requests fail only on new high or critical findings in changed lines
```

Or as a [pre-commit](https://pre-commit.com) hook:

```yaml
- repo: https://github.com/saideepreddy7781/agentharden
  rev: v0.2.0
  hooks: [{ id: agentharden }]
```

## What it checks

| Engine | What |
|---|---|
| Secrets | Cloud and API keys (AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, Google and more), private keys, credentialed connection strings, high-entropy credentials, committed `.env` files |
| Taint flows | Request data reaching SQL, shell, eval, SSRF, file paths, redirects, deserialization, templates, HTML (XSS), NoSQL and deep merges. Python via its AST (Flask, Django, FastAPI, Starlette); JavaScript and TypeScript via scoped line tracking (Express, Koa, Next.js, browser) |
| Code rules | 63 rules across Python, JS/TS, Go, Java and Kotlin, PHP, Ruby, Dockerfiles, GitHub Actions, Kubernetes and Terraform |
| Posture | Missing security headers and CSP, rate limiting, input validation, Django deploy settings, lockfiles, pinned versions, non-root containers, CI scanning |
| Dependencies | npm, pnpm, yarn, bun, PyPI (requirements, Pipfile, poetry, uv, pdm), Go, Maven, Gradle, RubyGems, crates.io and Packagist lockfiles against [OSV.dev](https://osv.dev). Anything on CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list becomes critical |
| Optional | [Semgrep](https://semgrep.dev), [Gitleaks](https://github.com/gitleaks/gitleaks), [Bandit](https://github.com/PyCQA/bandit) and [Trivy](https://trivy.dev), used when installed, run with agentharden's own config, results merged |

Findings in tests, docs, examples, vendored code and dev dependencies are listed apart and do not set the level or
fail CI. A real-format secret counts wherever it is, because a key leaked from a test file is still leaked.

## Security levels

| Level | Name | Meaning |
|---|---|---|
| L0 | Exposed | critical issues open |
| L1 | Basic | no criticals |
| L2 | Baseline | no criticals or highs |
| L3 | Hardened | nothing above low |
| L4 | Fortified | only informational items |

Each prompt targets the next level, so every change is a reviewable diff. A scan with blind spots (no advisory
data, unpinned dependencies, unreadable files) cannot claim more than L2, and says why.

## How well it works

All figures were measured on 2026-11-13 with agentharden 0.2.0, except the OSV comparison. Every benchmark is in
this repo, so you can rerun it.

Fix-loop safety, `python benchmarks/attacks/run.py`. These cases use scripted agents, so they test agentharden's
guarantees. They do not measure how a real model reacts to an injected instruction.

| Suite | Cases | Passed | 0.1.0 (as hardn) |
|---|---|---|---|
| Prompt injection via code, comments, file names, dependency names, identifiers, test output, fence breaks, hidden Unicode | 10 | 10 | 0 |
| Cheating agents (suppressions, ignore and baseline edits, deleted or gutted tests, test-command edits) | 20 | 20 | 0 |
| Legitimate fixes that must still get credit | 6 | 6 | 6 |

Detection, `python benchmarks/detection/run.py`, on a labelled corpus of vulnerable and safe twins. The figures
come from the holdout: 188 cases picked at random (seed 20261110) and frozen before any engine changed. We wrote
the corpus ourselves, aimed at known weak spots, so expect real code to score lower.

| Engine | Recall | Precision | 0.1.0 recall |
|---|---|---|---|
| Python taint | 93.9% | 97.9% | 65.3% |
| JavaScript taint | 81.6% | 91.2% | 60.5% |
| Code rules | 97.4% | 88.4% | 82.1% |
| Secrets | 87.5% | 87.5% | 70.8% |
| Posture | 100% | 100% | 83.3% |

Real code. On five deliberately vulnerable apps (OWASP NodeGoat, OWASP Juice Shop, PyGoat, vulpy, DVNA) it finds 40
of the 54 issues on a list we compiled from their documentation (0.1.0 found 26). On well-kept projects (Flask,
Requests, Express, FastAPI, Django, Next.js, Cal.com) we read a random sample of 49 findings in application code: 1
was a real issue, 15 were false positives, and 33 were correct but not worth acting on, mostly intended framework
behavior. Some of those false positives were fixed after the sample, but expect noise on large codebases. Use
`agentharden baseline`, and `agentharden:ignore` comments with a reason.

Dependency matching agrees with the live OSV API on the exact advisory set for 99.4% of 1,716 sampled packages,
leaving out advisories published after the local database was downloaded (measured 2026-11-11).

## Known limits

- Taint analysis stays inside one file. JavaScript has no type information, and data flow across two lines in Java
  is missed.
- Not detected: weak hard-coded secrets such as `'keyboard cat'`, ReDoS, CSRF, IDOR, plaintext password storage,
  and some server-side template injection.
- The cheat check misses semantic tricks such as wrapping a dangerous call in `if False:`. Review the diff.
- aider and Gitleaks read some config from the scanned repo with no switch to stop them; agentharden warns.

## FAQ

**Does my code get uploaded?** No. Scans never touch the network. If you paste the prompt into a cloud model,
that is your choice; a local model through aider and Ollama keeps everything on your machine.

**Is it safe to scan a repo I do not trust?** That is the case it is built for. Scanning never runs code from the
repo, including programs named in its `.git/config`, and never follows a symlink out of it. Add `--untrusted` so
the repo's own ignore file, baseline and suppression comments cannot hide anything. The threat model is in
[SECURITY.md](SECURITY.md).

**Can I trust the agent's fix?** Trust the diff, after you read it. agentharden makes sure a round that cheats
earns nothing, and it never commits for you. Credential rotation is always left to a person.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New cheats and injection tricks for the attack benchmark are especially
welcome. Security issues go through [SECURITY.md](SECURITY.md). Apache-2.0.
