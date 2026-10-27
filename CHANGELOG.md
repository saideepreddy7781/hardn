# Changelog

## 0.1.0 — first public release

- `hardn scan`: secrets, ~50 code rules, posture checks, offline dependency audit (OSV.dev + CISA KEV)
- Taint analysis: Python via the stdlib `ast` module (Flask, Django, FastAPI, Starlette), and line-based
  multi-line tracking for JavaScript/TypeScript
- AI-ready `FIX_PROMPT.md` scoped to the next security level (L0 Exposed → L4 Fortified)
- `hardn fix`: drives Claude Code, aider, Codex, or any command; re-scans until the target level is reached
- `hardn baseline` and `scan --diff REF`: fail CI only on new findings / changed lines
- `hardn init`: GitHub Actions workflow with SARIF upload; reusable `action.yml`
- Optional engines when installed: Semgrep, Gitleaks, Bandit, Trivy
- Distribution: PyPI, single-file `hardn.pyz`, standalone binaries for Linux, macOS, and Windows
