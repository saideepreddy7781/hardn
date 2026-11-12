"""Missing-control checks: the hardening layer that moves an app from 'no obvious bugs' to 'defended'.

App-level controls (security headers, rate limiting, request validation, production settings) are only asked of
applications. A package that is the framework itself, or a library that lists the framework only for development
or as a peer, is not told to add a Content-Security-Policy.
"""
from __future__ import annotations

import os
import re

from .code_rules import _is_dockerfile, views
from .models import Finding
from .stack import _read, node_manifest, node_manifests, python_project

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
VALIDATORS = ("zod", "joi", "yup", "express-validator", "class-validator", "valibot", "ajv", "@sinclair/typebox",
              "superstruct", "celebrate", "@hapi/joi", "fastest-validator", "io-ts", "runtypes", "arktype")
PY_FRAMEWORKS = ("flask", "fastapi", "django", "starlette", "quart")
MANUAL_HEADERS = re.compile(r"(?i)content-security-policy|strict-transport-security|x-frame-options")
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
NEXT_CONFIGS = ("next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs")
NEXT_MIDDLEWARE = tuple(f"{d}{n}.{e}" for d in ("", "src/") for n in ("middleware", "proxy") for e in ("js", "ts"))

DJANGO_SETTINGS = {
    "SECURE_HSTS_SECONDS": "SECURE_HSTS_SECONDS = 31536000",
    "SESSION_COOKIE_SECURE": "SESSION_COOKIE_SECURE = True",
    "CSRF_COOKIE_SECURE": "CSRF_COOKIE_SECURE = True",
    "SECURE_SSL_REDIRECT": "SECURE_SSL_REDIRECT = True",
}
NONROOT_IMAGE = re.compile(r"(?i)distroless.*:(?:[\w.-]*-)?nonroot|[:-]nonroot\b|^cgr\.dev/|chainguard")


def _f(rid, title, sev, fix, file="", snippet="", cwe="CWE-693") -> Finding:
    return Finding(rule_id=rid, title=title, severity=sev, category="posture", file=file,
                   snippet=snippet, cwe=cwe, fix=fix)


def check(root: str, files: list, all_paths: list, stack: dict) -> list:
    out = []
    out += _node(root, files, all_paths)
    out += _python(root, files, all_paths, stack)
    out += _docker(files)
    out += _repo(root, files, all_paths)
    return out


def _code(f) -> str:
    """File text with comments removed, so a commented-out `app.use(helmet())` does not count."""
    if f.path.lower().endswith(JS_SUFFIXES):
        return views(f.text, "c")[0]
    if f.path.endswith(".py"):
        return views(f.text, "py")[0]
    return f.text


def _is_node_library(pkg: dict, framework: str) -> bool:
    name = str(pkg.get("name", ""))
    if name == framework or name.startswith(framework + "-") or name.startswith(("@" + framework.strip("@") + "/",)):
        return True
    deps = pkg.get("dependencies") if isinstance(pkg.get("dependencies"), dict) else {}
    if framework not in deps:
        return True  # only a devDependency or peer: a test server or a plugin, not the app itself
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    published = not pkg.get("private") and any(k in pkg for k in ("main", "exports", "module", "types"))
    return published and not any(k in scripts for k in ("start", "dev", "serve"))


def _node(root: str, files: list, all_paths: list) -> list:
    out = []
    paths = set(all_paths)
    by_dir = {}
    for f in files:
        if f.path.lower().endswith(JS_SUFFIXES):
            by_dir.setdefault(os.path.dirname(f.path), []).append(f)
    for manifest in node_manifests(root, all_paths):
        d = os.path.dirname(manifest)
        prefix = d + "/" if d else ""
        pkg = node_manifest(root, manifest)
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(pkg.get(key), dict):
                deps.update(pkg[key])
        if not deps:
            continue
        runtime = pkg.get("dependencies") if isinstance(pkg.get("dependencies"), dict) else {}
        if not any(prefix + lf in paths or lf in paths for lf in LOCKFILES):
            out.append(_f("POS001", "No dependency lockfile", "medium",
                          "Commit a lockfile (package-lock.json / pnpm-lock.yaml / yarn.lock) and install with `npm ci` "
                          "in CI so builds are reproducible and vulnerabilities can be audited.", manifest, cwe="CWE-1104"))
        loose = sorted(n for n, v in deps.items() if isinstance(v, str) and _unbounded(v))
        if loose:
            out.append(_f("POS002", "Unbounded dependency versions", "medium",
                          f"Pin these to a semver range or exact version: {', '.join(loose[:15])}.",
                          manifest, snippet=", ".join(f"{n}: {deps[n]}" for n in loose[:5]), cwe="CWE-1104"))
        local = [f for dd, fs in by_dir.items() if dd == d or dd.startswith(prefix) for f in fs] if prefix else \
            [f for fs in by_dir.values() for f in fs]
        for fw, (hdr, rl, hdr_pkg, rl_pkg) in NODE_CONTROLS.items():
            if fw not in runtime:
                continue
            if _is_node_library(pkg, fw):
                break
            code = [_code(f) for f in local]
            if hdr:
                installed = [h for h in hdr if h in deps]
                used = any(re.search(r"\b(?:require\(\s*['\"]" + re.escape(h) + r"['\"]|from\s+['\"]" + re.escape(h)
                                     + r"['\"])", c) for c in code for h in installed)
                manual = any(MANUAL_HEADERS.search(c) for c in code)
                if not manual and (not installed or (local and not used)):
                    title = (f"No security headers middleware for {fw}" if not installed
                             else f"{installed[0]} is installed but never registered")
                    out.append(_f("POS003", title, "medium",
                                  f"Install `{hdr_pkg}` and register it before routes (e.g. `app.use(helmet())`). "
                                  "Configure a Content-Security-Policy that matches your asset origins, HSTS, "
                                  "frame-ancestors 'none', and remove X-Powered-By.", manifest))
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
        if "next" in runtime and not _is_node_library(pkg, "next"):
            cfg = next((prefix + c for c in NEXT_CONFIGS if prefix + c in paths), "")
            mw = next((prefix + c for c in NEXT_MIDDLEWARE if prefix + c in paths), "")
            texts = [_strip_js(_read(root, p)) for p in (cfg, mw) if p]
            for p in (cfg, mw):  # follow local imports one level: `require('./lib/headers')`
                if not p:
                    continue
                for imp in re.findall(r"(?:require\(|from\s+)['\"](\.{1,2}/[^'\"]+)['\"]", _read(root, p)):
                    target = os.path.normpath(os.path.join(os.path.dirname(p), imp)).replace(os.sep, "/")
                    for cand in (target, *(target + e for e in (".js", ".ts", ".mjs", ".cjs", "/index.js", "/index.ts"))):
                        if cand in paths:
                            texts.append(_strip_js(_read(root, cand)))
                            break
            if not any(re.search(r"(?i)content-security-policy", t) for t in texts):
                out.append(_f("POS006", "No Content-Security-Policy for Next.js", "medium",
                              "Add security headers via `headers()` in next.config (or middleware with a per-request nonce): "
                              "Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, "
                              "Referrer-Policy: strict-origin-when-cross-origin, and frame-ancestors 'none'.",
                              cfg or manifest))
    return out


def _strip_js(text: str) -> str:
    return views(text, "c")[0] if text else ""


def _unbounded(v: str) -> bool:
    v = v.strip()
    if v in ("*", "latest", "x", "", "X"):
        return True
    return v.startswith(">") and "<" not in v and "||" not in v


def _python(root: str, files: list, all_paths: list, stack: dict) -> list:
    out = []
    manifest = next((p for p in all_paths if re.match(r"(.*/)?(requirements.*\.txt|pyproject\.toml|Pipfile|setup\.py)$", p)),
                    "")
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
    project = python_project(root, all_paths)
    pdeps = project["runtime"] or set(stack.get("python_deps", []))
    names = project["names"]
    if any(n == fw or n.startswith((fw + "-", "django-", "flask-", "fastapi-")) for n in names for fw in PY_FRAMEWORKS):
        return out  # the framework itself, or an extension library: app-level controls are its users' job
    py_code = None

    def manual_headers() -> bool:
        nonlocal py_code
        if py_code is None:
            py_code = [_code(f) for f in files if f.path.endswith(".py")]
        return any(MANUAL_HEADERS.search(c) for c in py_code)

    if "flask" in pdeps:
        if "flask-talisman" not in pdeps and "secure" not in pdeps and not manual_headers():
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
    if "django" in pdeps or "django" in stack.get("python_deps", []):
        for f in files:
            if not _is_prod_settings(f.path):
                continue
            text = _code(f)
            missing = [k for k in DJANGO_SETTINGS if not _setting_on(text, k)]
            if missing:
                out.append(_f("POS012", "Django production security settings missing", "medium",
                              "Set these (from env in production): " + "; ".join(DJANGO_SETTINGS[k] for k in missing)
                              + ". Then run `python manage.py check --deploy` and resolve its warnings.", f.path,
                              snippet=", ".join(missing)))
    return out


def _is_prod_settings(path: str) -> bool:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if re.search(r"(^|/)(tests?|docs?|examples?)/", low) or re.search(r"(test|dev|local|ci)", base.replace(".py", "")) \
            and base != "settings.py":
        return False
    if base == "settings.py":
        return True
    return bool(re.search(r"(^|/)settings/", low)) and base in ("prod.py", "production.py", "base.py", "__init__.py",
                                                                 "common.py", "settings.py")


def _setting_on(text: str, key: str) -> bool:
    """A setting counts when it is assigned something other than False/0/None outside a comment."""
    for m in re.finditer(r"(?m)^\s*" + key + r"\s*=\s*(.+)$", text):
        value = m.group(1).strip()
        if not re.fullmatch(r"(False|0|None|''|\"\")", value):
            return True
    return False


def _docker(files: list) -> list:
    out = []
    for f in files:
        if not _is_dockerfile(f.path.rsplit("/", 1)[-1].lower()):
            continue
        stages = re.split(r"(?im)^\s*FROM\s+", f.text)
        if len(stages) < 2:
            continue
        names, final_user = {}, None
        for stage in stages[1:]:
            head = stage.split("\n", 1)[0]
            m = re.match(r"(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", head, re.IGNORECASE)
            image = m.group(1) if m else ""
            users = re.findall(r"(?im)^\s*USER\s+(\S+)", stage)
            user = users[-1] if users else names.get(image.lower())
            if user is None and NONROOT_IMAGE.search(image):
                user = "nonroot"
            if m and m.group(2):
                names[m.group(2).lower()] = user
            final_user = user
        if final_user is None or final_user in ("root", "0", "0:0", "root:root"):
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
    if not any(p.lower() in ("security.md", ".github/security.md", "docs/security.md", "security.rst") for p in paths):
        out.append(_f("POS031", "No security policy (SECURITY.md)", "info",
                      "Add SECURITY.md describing how to report vulnerabilities and supported versions.", cwe=""))
    renovate = {f"{d}{n}" for d in ("", ".github/", ".gitlab/") for n in ("renovate.json", "renovate.json5",
                                                                           ".renovaterc", ".renovaterc.json",
                                                                           ".renovaterc.json5")}
    if not (paths & ({".github/dependabot.yml", ".github/dependabot.yaml"} | renovate)):
        out.append(_f("POS032", "No automated dependency updates", "low",
                      "Add .github/dependabot.yml (or Renovate) covering each package ecosystem and GitHub Actions.",
                      cwe="CWE-1104"))
    workflows = [f for f in files if f.path.startswith((".github/workflows/", ".gitlab-ci", ".circleci/"))]
    if not any(re.search(r"(?i)codeql|semgrep|gitleaks|trivy|osv-scanner|snyk|hardn|bandit|npm audit|pip-audit|"
                         r"zizmor|grype|dependency-review", views(f.text, "hash")[0]) for f in workflows):
        out.append(_f("POS033", "No security scanning in CI", "low",
                      "Add a CI job that runs `hardn scan . --fail-on high` (plus gitleaks/semgrep if available) on "
                      "every pull request so regressions are caught before merge."))
    return out
