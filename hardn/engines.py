"""Optional adapters for best-in-class open-source scanners, used when installed.

Every adapter runs with network/telemetry disabled. Missing tools are reported, never fatal.

A scanned repository can ship configuration that tells these tools to skip files or findings: a
`.gitleaks.toml` with an allowlist of `.*`, a `.bandit` that skips B602, a `.trivyignore` of `*`, a
`.semgrepignore`. Left alone, that silently blinds the engine while it still reports "ok". So every
adapter is started with configuration that hardn controls and runs from a neutral directory. Where a tool
offers no switch to stop reading a repo file, the engine status says so and hardn prints a warning.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

from .deps import HOME
from .models import SEV_RANK, Finding

SEMGREP_RULES = HOME / "semgrep-rules"
SEMGREP_LANG_DIRS = {
    "Python": "python", "JavaScript": "javascript", "TypeScript": "typescript", "Go": "go",
    "Java": "java", "Kotlin": "kotlin", "Ruby": "ruby", "PHP": "php", "C#": "csharp", "Rust": "rust",
    "Terraform": "terraform",
}
INSTALL_HINTS = {
    "semgrep": "brew install semgrep   (or: pipx install semgrep) — then `hardn update --semgrep-rules`",
    "gitleaks": "brew install gitleaks",
    "bandit": "pipx install bandit",
    "trivy": "brew install trivy — then run `trivy fs --download-db-only` once while online",
}
TIMEOUT = 900

# Files a repository can ship to change what an engine reports. hardn replaces each one with its own
# configuration on the command line; the ones in UNBLOCKABLE have no such switch and only get a warning.
REPO_CONFIGS = {
    "gitleaks": (".gitleaks.toml", ".gitleaksignore"),
    "bandit": (".bandit",),
    "semgrep": (".semgrepignore",),
    "trivy": (".trivyignore", ".trivyignore.yaml", "trivy.yaml"),
}
UNBLOCKABLE = {"gitleaks": (".gitleaksignore",)}
_GITLEAKS_CONFIG = 'title = "hardn default"\n\n[extend]\nuseDefault = true\n'
_SKIP = {".git", "node_modules", ".venv", "venv", ".hardn", "__pycache__"}


def available() -> dict:
    return {name: shutil.which(name) for name in INSTALL_HINTS}


def _run(cmd: list, cwd: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    return subprocess.run(cmd, capture_output=True, check=False, text=True, encoding="utf-8", errors="replace",
                          timeout=TIMEOUT, cwd=cwd, env=env, stdin=subprocess.DEVNULL)


def _rel(root: str, path: str) -> str:
    path = os.path.relpath(os.path.join(root, path), root) if not os.path.isabs(path) else os.path.relpath(path, root)
    return path.replace(os.sep, "/")


def repo_configs(root: str) -> dict:
    """Engine name -> relative paths of suppression files this repository ships (any depth)."""
    names = {n: eng for eng, files in REPO_CONFIGS.items() for n in files}
    found = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP]
        for name in filenames:
            if name in names:
                rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
                found.setdefault(names[name], []).append(rel)
    return found


def run_all(root: str, stack: dict, log=lambda *_: None) -> tuple:
    findings, statuses = [], {}
    tools = available()
    shipped = repo_configs(root)
    with tempfile.TemporaryDirectory(prefix="hardn-engines-") as work:
        for name, fn in (("semgrep", _semgrep), ("gitleaks", _gitleaks), ("bandit", _bandit), ("trivy", _trivy)):
            if not tools[name]:
                statuses[name] = "not installed"
                continue
            if name == "bandit" and "Python" not in stack.get("languages", []):
                statuses[name] = "skipped (no Python)"
                continue
            log(f"running {name}…")
            try:
                got, note, still_read = fn(root, stack, work)
                findings += got
                statuses[name] = note or f"ok ({len(got)})"
            except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as exc:
                statuses[name] = f"error: {str(exc)[:80]}"
                continue
            honoured = [p for p in shipped.get(name, []) if p.rsplit("/", 1)[-1] in still_read]
            if honoured:
                statuses[name] += "; may be filtered by the repo's " + ", ".join(sorted(honoured)[:3])
                print(f"hardn: warning: {name} reads {', '.join(sorted(honoured)[:3])} from the scanned repository "
                      "and hardn cannot switch that off, so some of its results may be hidden.", file=sys.stderr)
            elif shipped.get(name):
                statuses[name] += "; repo config ignored"
    return findings, statuses


def _unknown_option(proc: subprocess.CompletedProcess, flag: str) -> bool:
    err = (proc.stderr or "").lower()
    return proc.returncode != 0 and flag in err and ("unknown" in err or "unrecognized" in err or "no such" in err)


def _semgrep(root: str, stack: dict, work: str):
    custom = os.environ.get("HARDN_SEMGREP_CONFIG")
    configs = [custom] if custom else [
        str(SEMGREP_RULES / d) for lang, d in SEMGREP_LANG_DIRS.items()
        if lang in stack.get("languages", []) and (SEMGREP_RULES / d).is_dir()
    ]
    if not configs:
        return [], "no offline rules — run `hardn update --semgrep-rules`", ()
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check", "--no-git-ignore"]
    for c in configs:
        cmd += ["--config", c]
    still_read = ()
    proc = _run(cmd + ["--x-ignore-semgrepignore-files", root], cwd=work)
    if _unknown_option(proc, "--x-ignore-semgrepignore-files"):  # older semgrep: the flag is experimental
        proc = _run(cmd + [root], cwd=work)
        still_read = (".semgrepignore",)
    data = json.loads(proc.stdout or "{}")
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    out = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwe = meta.get("cwe", "")
        cwe = (cwe[0] if isinstance(cwe, list) and cwe else cwe) or ""
        out.append(Finding(
            rule_id=r["check_id"].rsplit(".", 1)[-1], title=r["extra"].get("message", "").split("\n")[0][:120],
            severity=sev.get(r["extra"].get("severity", "WARNING"), "medium"), category="code",
            file=_rel(root, r["path"]), line=r["start"]["line"], snippet=r["extra"].get("lines", "").strip()[:240],
            cwe=str(cwe).split(":")[0], fix=r["extra"].get("fix") or next(iter(meta.get("references") or []), ""),
            sources=["semgrep"],
        ))
    return out, None, still_read


def _gitleaks(root: str, stack: dict, work: str):
    config = os.environ.get("GITLEAKS_CONFIG")  # the user's own choice, set outside the repository
    if not config:
        config = os.path.join(work, "gitleaks.toml")
        with open(config, "w", encoding="utf-8") as fh:
            fh.write(_GITLEAKS_CONFIG)
    ignore_dir = os.path.join(work, "gitleaks-ignore")
    os.makedirs(ignore_dir, exist_ok=True)
    report = os.path.join(work, "gl.json")
    _run(["gitleaks", "detect", "--no-git", "--no-banner", "--redact", "--exit-code", "0",
          "--config", config, "--gitleaks-ignore-path", ignore_dir,
          "--source", root, "--report-format", "json", "--report-path", report], cwd=work)
    with open(report, encoding="utf-8") as fh:
        data = json.load(fh) or []
    os.remove(report)
    return [Finding(
        rule_id=f"gitleaks:{d.get('RuleID')}", title=d.get("Description", "Secret"), severity="high", category="secret",
        file=_rel(root, d.get("File", "")), line=d.get("StartLine", 0), snippet=(d.get("Match") or "")[:200],
        cwe="CWE-798", sources=["gitleaks"],
        fix="Move the value to an environment variable or secret manager and rotate the credential.",
    ) for d in data], None, UNBLOCKABLE["gitleaks"]


def _bandit(root: str, stack: dict, work: str):
    ini = os.path.join(work, "bandit.ini")  # an explicit --ini stops bandit reading .bandit from the targets
    with open(ini, "w", encoding="utf-8") as fh:
        fh.write("[bandit]\n")
    proc = _run(["bandit", "-r", root, "-f", "json", "-q", "--ini", ini, "-x",
                 ",".join(os.path.join(root, d) for d in ("node_modules", ".venv", "venv", "tests", "test"))], cwd=work)
    data = json.loads(proc.stdout or "{}")
    sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    return [Finding(
        rule_id=f"bandit:{r['test_id']}", title=r["issue_text"][:120], severity=sev.get(r["issue_severity"], "low"),
        category="code", file=_rel(root, r["filename"]), line=r["line_number"], snippet=r.get("code", "").strip()[:240],
        cwe=f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else "", fix=r.get("more_info", ""), sources=["bandit"],
    ) for r in data.get("results", [])], None, ()


def _trivy(root: str, stack: dict, work: str):
    empty = os.path.join(work, "trivyignore")
    with open(empty, "w", encoding="utf-8"):
        pass
    proc = _run(["trivy", "fs", "--quiet", "--format", "json", "--scanners", "misconfig",
                 "--skip-db-update", "--skip-check-update", "--offline-scan",
                 "--ignorefile", empty, "--config", "", root], cwd=work)  # "" = load no trivy.yaml
    data = json.loads(proc.stdout or "{}")
    out = []
    for res in data.get("Results", []) or []:
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                continue
            out.append(Finding(
                rule_id=f"trivy:{m.get('ID')}", title=m.get("Title", "")[:120],
                severity=m.get("Severity", "").lower() if m.get("Severity", "").lower() in SEV_RANK else "medium",
                category="config", file=_rel(root, res.get("Target", "")),
                line=(m.get("CauseMetadata") or {}).get("StartLine", 0), snippet=m.get("Message", "")[:240],
                fix=m.get("Resolution", ""), sources=["trivy"],
            ))
    return out, None, ()
