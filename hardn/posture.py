"""Missing-control checks: the hardening layer that moves an app from 'no obvious bugs' to 'defended'."""
from __future__ import annotations

import os
import re

from .models import Finding
from .stack import _read, node_deps, node_manifests

LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json")

# framework dependency -> (security-header packages, rate-limit packages, suggested header pkg, suggested limiter pkg)
NODE_CONTROLS = {
    "express": (("helmet",), ("express-rate-limit", "rate-limiter-flexible", "express-slow-down", "@upstash/ratelimit"),
                "helmet", "express-rate-limit"),
    "fastify": (("@fastify/helmet", "fastify-helmet"), ("@fastify/rate-limit", "fastify-rate-limit"),
                "@fastify/helmet", "@fastify/rate-limit"),
    "koa": (("koa-helmet",), ("koa-ratelimit", "rate-limiter-flexible"), "koa-helmet", "koa-ratelimit"),
    "@nestjs/core": (("helmet",), ("@nestjs/throttler",), "helmet", "@nestjs/throttler"),
    "hono": ((), ("hono-rate-limiter", "@upstash/ratelimit"), "hono/secure-headers (built in)", "hono-rate-limiter"),
}
VALIDATORS = ("zod", "joi", "yup", "express-validator", "class-validator", "valibot", "ajv", "@sinclair/typebox", "superstruct", "celebrate")

DJANGO_SETTINGS = {
    "SECURE_HSTS_SECONDS": "SECURE_HSTS_SECONDS = 31536000",
    "SESSION_COOKIE_SECURE": "SESSION_COOKIE_SECURE = True",
    "CSRF_COOKIE_SECURE": "CSRF_COOKIE_SECURE = True",
    "SECURE_SSL_REDIRECT": "SECURE_SSL_REDIRECT = True",
}


def _f(rid, title, sev, fix, file="", snippet="", cwe="CWE-693") -> Finding:
    return Finding(rule_id=rid, title=title, severity=sev, category="posture", file=file,
                   snippet=snippet, cwe=cwe, fix=fix)


def check(root: str, files: list, all_paths: list, stack: dict) -> list:
    out = []
    out += _node(root, all_paths)
    out += _python(root, files, all_paths, stack)
    out += _docker(files)
    out += _repo(root, files, all_paths)
    return out


def _node(root: str, all_paths: list) -> list:
    out = []
    paths = set(all_paths)
    for manifest in node_manifests(root, all_paths):
        d = os.path.dirname(manifest)
        prefix = d + "/" if d else ""
        deps = node_deps(root, manifest)
        if not deps:
            continue
        if not any(prefix + lf in paths or lf in paths for lf in LOCKFILES):
            out.append(_f("POS001", "No dependency lockfile", "medium",
                          "Commit a lockfile (package-lock.json / pnpm-lock.yaml / yarn.lock) and install with `npm ci` "
                          "in CI so builds are reproducible and vulnerabilities can be audited.", manifest, cwe="CWE-1104"))
        loose = [n for n, v in deps.items() if isinstance(v, str) and v.strip() in ("*", "latest", "x", "") or str(v).startswith(">")]
        if loose:
            out.append(_f("POS002", "Unbounded dependency versions", "medium",
                          f"Pin these to a semver range or exact version: {', '.join(sorted(loose)[:15])}.",
                          manifest, snippet=", ".join(f"{n}: {deps[n]}" for n in sorted(loose)[:5]), cwe="CWE-1104"))
        for fw, (hdr, rl, hdr_pkg, rl_pkg) in NODE_CONTROLS.items():
            if fw not in deps:
                continue
            if hdr and not any(h in deps for h in hdr):
                out.append(_f("POS003", f"No security headers middleware for {fw}", "medium",
                              f"Install `{hdr_pkg}` and register it before routes (e.g. `app.use(helmet())`). Configure a "
                              "Content-Security-Policy that matches your asset origins, HSTS, frame-ancestors 'none', and "
                              "remove X-Powered-By.", manifest))
            if not any(r in deps for r in rl):
                out.append(_f("POS004", "No rate limiting", "medium",
                              f"Add `{rl_pkg}`: a strict limiter on auth routes (login, signup, password reset, OTP — e.g. "
                              "5 req/min per IP+account) and a looser global limiter. Configure `trust proxy` correctly "
                              "if behind a load balancer.", manifest, cwe="CWE-307"))
            if not any(v in deps for v in VALIDATORS):
                out.append(_f("POS005", "No request schema validation library", "low",
                              "Validate every request body/query/params at the boundary with a schema (zod is a good "
                              "default) and reject unknown fields.", manifest, cwe="CWE-20"))
            break
        if "next" in deps:
            cfg = next((p for p in all_paths if re.fullmatch(re.escape(prefix) + r"next\.config\.(js|mjs|ts|cjs)", p)), "")
            mw = next((p for p in all_paths if re.fullmatch(re.escape(prefix) + r"(src/)?(middleware|proxy)\.(js|ts)", p)), "")
            text = _read(root, cfg) + _read(root, mw) if (cfg or mw) else ""
            if "Content-Security-Policy" not in text:
                out.append(_f("POS006", "No Content-Security-Policy for Next.js", "medium",
                              "Add security headers via `headers()` in next.config (or middleware with a per-request nonce): "
                              "Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, "
                              "Referrer-Policy: strict-origin-when-cross-origin, and frame-ancestors 'none'.",
                              cfg or manifest))
    return out


def _python(root: str, files: list, all_paths: list, stack: dict) -> list:
    out = []
    pdeps = set(stack.get("python_deps", []))
    manifest = next((p for p in all_paths if re.match(r"(.*/)?(requirements.*\.txt|pyproject\.toml|Pipfile)$", p)), "")
    for rel in all_paths:
        base = rel.rsplit("/", 1)[-1]
        if re.match(r"requirements.*\.txt$", base) and rel.count("/") <= 2:
            loose = [ln.strip() for ln in _read(root, rel).splitlines()
                     if ln.strip() and not ln.strip().startswith(("#", "-")) and "==" not in ln and "@" not in ln]
            if loose:
                out.append(_f("POS010", "Unpinned Python dependencies", "low",
                              "Pin exact versions (pip-compile / uv pip compile) and install with hashes "
                              "(`--require-hashes`) for reproducible, auditable builds.", rel,
                              snippet=", ".join(loose[:5]), cwe="CWE-1104"))
    if "flask" in pdeps:
        if "flask-talisman" not in pdeps:
            out.append(_f("POS011", "No security headers for Flask", "medium",
                          "Add flask-talisman (`Talisman(app, content_security_policy=...)`) for HSTS, CSP and secure "
                          "cookie defaults, and set SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE.", manifest))
        if "flask-limiter" not in pdeps:
            out.append(_f("POS004", "No rate limiting", "medium",
                          "Add flask-limiter with strict limits on authentication endpoints and a global default.",
                          manifest, cwe="CWE-307"))
    if "fastapi" in pdeps and not pdeps & {"slowapi", "fastapi-limiter"}:
        out.append(_f("POS004", "No rate limiting", "medium",
                      "Add slowapi (or fastapi-limiter) with strict limits on authentication endpoints.", manifest,
                      cwe="CWE-307"))
    if "django" in pdeps:
        for f in files:
            if f.path.endswith("settings.py") or "/settings/" in f.path and f.path.endswith(("prod.py", "production.py", "base.py")):
                missing = [k for k in DJANGO_SETTINGS if k not in f.text]
                if missing:
                    out.append(_f("POS012", "Django production security settings missing", "medium",
                                  "Set these (from env in production): " + "; ".join(DJANGO_SETTINGS[k] for k in missing)
                                  + ". Then run `python manage.py check --deploy` and resolve its warnings.", f.path,
                                  snippet=", ".join(missing)))
    return out


def _docker(files: list) -> list:
    out = []
    for f in files:
        if not f.path.rsplit("/", 1)[-1].lower().startswith("dockerfile"):
            continue
        users = re.findall(r"(?im)^\s*USER\s+(\S+)", f.text)
        if not users or users[-1] in ("root", "0", "0:0"):
            out.append(_f("POS020", "Container runs as root", "medium",
                          "Create an unprivileged user and switch to it before CMD, e.g. "
                          "`RUN addgroup -S app && adduser -S app -G app` then `USER app` (or `USER node` on node images).",
                          f.path, cwe="CWE-250"))
    return out


def _repo(root: str, files: list, all_paths: list) -> list:
    out = []
    paths = set(all_paths)
    if ".gitignore" not in paths:
        out.append(_f("POS030", "No .gitignore", "low",
                      "Add a .gitignore that excludes .env*, build output, dependency directories and local keys.",
                      cwe="CWE-538"))
    if not any(p.lower() in ("security.md", ".github/security.md", "docs/security.md") for p in paths):
        out.append(_f("POS031", "No security policy (SECURITY.md)", "info",
                      "Add SECURITY.md describing how to report vulnerabilities and supported versions."))
    if not any(p in paths for p in (".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json",
                                    ".github/renovate.json", ".renovaterc", ".renovaterc.json")):
        out.append(_f("POS032", "No automated dependency updates", "low",
                      "Add .github/dependabot.yml (or Renovate) covering each package ecosystem and GitHub Actions.",
                      cwe="CWE-1104"))
    workflows = [f for f in files if f.path.startswith((".github/workflows/", ".gitlab-ci", ".circleci/"))]
    if not any(re.search(r"(?i)codeql|semgrep|gitleaks|trivy|osv-scanner|snyk|hardn|bandit|npm audit|pip-audit", f.text)
               for f in workflows):
        out.append(_f("POS033", "No security scanning in CI", "low",
                      "Add a CI job that runs `hardn scan . --fail-on high` (plus gitleaks/semgrep if available) on "
                      "every pull request so regressions are caught before merge."))
    return out
