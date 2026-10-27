"""Optional adapters for best-in-class open-source scanners, used when installed.

Every adapter runs with network/telemetry disabled. Missing tools are reported, never fatal.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
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


def available() -> dict:
    return {name: shutil.which(name) for name in INSTALL_HINTS}


def _run(cmd: list, cwd: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=TIMEOUT, cwd=cwd, env=env)


def _rel(root: str, path: str) -> str:
    path = os.path.relpath(os.path.join(root, path), root) if not os.path.isabs(path) else os.path.relpath(path, root)
    return path.replace(os.sep, "/")


def run_all(root: str, stack: dict, log=lambda *_: None) -> tuple:
    findings, statuses = [], {}
    tools = available()
    for name, fn in (("semgrep", _semgrep), ("gitleaks", _gitleaks), ("bandit", _bandit), ("trivy", _trivy)):
        if not tools[name]:
            statuses[name] = "not installed"
            continue
        if name == "bandit" and "Python" not in stack.get("languages", []):
            statuses[name] = "skipped (no Python)"
            continue
        log(f"running {name}…")
        try:
            got, note = fn(root, stack)
            findings += got
            statuses[name] = note or f"ok ({len(got)})"
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as exc:
            statuses[name] = f"error: {str(exc)[:80]}"
    return findings, statuses


def _semgrep(root: str, stack: dict):
    custom = os.environ.get("HARDN_SEMGREP_CONFIG")
    configs = [custom] if custom else [
        str(SEMGREP_RULES / d) for lang, d in SEMGREP_LANG_DIRS.items()
        if lang in stack.get("languages", []) and (SEMGREP_RULES / d).is_dir()
    ]
    if not configs:
        return [], "no offline rules — run `hardn update --semgrep-rules`"
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check", "--no-git-ignore"]
    for c in configs:
        cmd += ["--config", c]
    proc = _run(cmd + [root])
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
    return out, None


def _gitleaks(root: str, stack: dict):
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "gl.json")
        _run(["gitleaks", "detect", "--no-git", "--no-banner", "--redact", "--exit-code", "0",
              "--source", root, "--report-format", "json", "--report-path", report])
        with open(report) as fh:
            data = json.load(fh) or []
    return [Finding(
        rule_id=f"gitleaks:{d.get('RuleID')}", title=d.get("Description", "Secret"), severity="high", category="secret",
        file=_rel(root, d.get("File", "")), line=d.get("StartLine", 0), snippet=(d.get("Match") or "")[:200],
        cwe="CWE-798", sources=["gitleaks"],
        fix="Move the value to an environment variable or secret manager and rotate the credential.",
    ) for d in data], None


def _bandit(root: str, stack: dict):
    proc = _run(["bandit", "-r", root, "-f", "json", "-q", "-x",
                 ",".join(os.path.join(root, d) for d in ("node_modules", ".venv", "venv", "tests", "test"))])
    data = json.loads(proc.stdout or "{}")
    sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    return [Finding(
        rule_id=f"bandit:{r['test_id']}", title=r["issue_text"][:120], severity=sev.get(r["issue_severity"], "low"),
        category="code", file=_rel(root, r["filename"]), line=r["line_number"], snippet=r.get("code", "").strip()[:240],
        cwe=f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else "", fix=r.get("more_info", ""), sources=["bandit"],
    ) for r in data.get("results", [])], None


def _trivy(root: str, stack: dict):
    proc = _run(["trivy", "fs", "--quiet", "--format", "json", "--scanners", "misconfig",
                 "--skip-db-update", "--skip-check-update", "--offline-scan", root])
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
    return out, None
