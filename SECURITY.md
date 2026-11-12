# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private reporting: **Security → Report a vulnerability** on this
repository. You will get a reply within a few days.

## Threat model

agentharden reads code it does not trust and hands what it finds to a coding agent that can edit files. These are
the guarantees, and a break in any of them is in scope:

- Scanning never runs code from the scanned repo, including programs named in its `.git/config`.
- Scans never use the network. Only `agentharden update` downloads data (OSV.dev, CISA KEV, optional Semgrep rules).
- Secret values never reach the terminal, `FIX_PROMPT.md`, `report.json`, SARIF or the baseline.
- Files are read only inside the scanned folder, and output is never written through a symlink.
- Text from the scanned repo reaches the agent only inside labelled data blocks it cannot break out of.
- In `agentharden fix`, a round that cheats (suppression comments, ignore or baseline edits, deleted tests, an
  edited test command) gets no level credit.
- The agent does not inherit cloud keys or tokens from your shell, beyond those its own login needs.

`benchmarks/attacks/` tests the injection and cheating guarantees with scripted agents. It does not measure how a
real model behaves when it reads an injected instruction.

## Known limits

- A repo's `.gitleaksignore` is still read by Gitleaks; agentharden warns when one exists.
- aider reads `.aider.conf.yml` and `.env` from the repo with no switch to stop it; agentharden warns.
- The cheat check does not catch every semantic trick, for example wrapping a dangerous call in `if False:`.
  Review the diff before you commit.

## Supported versions

Only the latest release gets fixes.
