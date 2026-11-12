"""Detect languages and frameworks so checks and prompts can be stack-specific."""
from __future__ import annotations

import json
import os
import re
from collections import Counter

from . import walker

LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".java": "Java", ".kt": "Kotlin", ".rb": "Ruby", ".php": "PHP", ".rs": "Rust",
    ".cs": "C#", ".swift": "Swift", ".vue": "Vue", ".svelte": "Svelte", ".tf": "Terraform",
}

NODE_FRAMEWORKS = {
    "express": "Express", "next": "Next.js", "react": "React", "fastify": "Fastify",
    "@nestjs/core": "NestJS", "koa": "Koa", "hono": "Hono", "vue": "Vue", "nuxt": "Nuxt",
    "@angular/core": "Angular", "@sveltejs/kit": "SvelteKit", "electron": "Electron",
}
PY_FRAMEWORKS = {"django": "Django", "flask": "Flask", "fastapi": "FastAPI", "starlette": "Starlette"}
OTHER_MARKERS = [
    ("go.mod", r"github\.com/gin-gonic/gin", "Gin"),
    ("go.mod", r"github\.com/labstack/echo", "Echo"),
    ("go.mod", r"github\.com/gofiber/fiber", "Fiber"),
    ("Gemfile", r"['\"]rails['\"]", "Rails"),
    ("composer.json", r"laravel/framework", "Laravel"),
    ("pom.xml", r"spring-boot", "Spring Boot"),
    ("build.gradle", r"spring-boot", "Spring Boot"),
]


def _read(root: str, rel: str) -> str:
    try:
        return walker.read_regular(os.path.join(root, rel)).decode("utf-8", errors="replace")
    except OSError:  # includes walker.NotReadable: FIFOs, devices, symlinks, oversize files
        return ""


def node_manifests(root: str, all_paths: list) -> list:
    """package.json files up to two directories deep (covers most monorepos)."""
    return [p for p in all_paths if p.endswith("package.json") and p.count("/") <= 2]


def node_deps(root: str, rel: str) -> dict:
    try:
        pkg = json.loads(_read(root, rel) or "{}")
    except json.JSONDecodeError:
        return {}
    deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        if isinstance(pkg.get(key), dict):
            deps.update(pkg[key])
    return deps


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def _quoted_requirements(text: str) -> set:
    """Package names from quoted requirement strings: `["flask>=3", "gunicorn"]`, inline or spread over lines."""
    return {_norm(m.group(1)) for m in re.finditer(r"[\"']([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*"
                                                    r"(?:[=<>!~;@ ][^\"']*)?[\"']", text)}


def _list_after(text: str, key: str) -> str:
    """The bracketed list assigned to `key` (`dependencies = [...]`, `install_requires=[...]`)."""
    m = re.search(r"(?m)^\s*" + key + r"\s*=\s*\[", text) or re.search(r"\b" + key + r"\s*=\s*\[", text)
    if not m:
        return ""
    depth, i = 1, m.end()
    while i < len(text) and depth:
        depth += {"[": 1, "]": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i]


def _toml_section(text: str, name: str) -> str:
    m = re.search(r"(?m)^\[" + re.escape(name) + r"\]\s*$", text)
    if not m:
        return ""
    end = re.search(r"(?m)^\[", text[m.end():])
    return text[m.end(): m.end() + end.start()] if end else text[m.end():]


def python_deps(root: str, all_paths: list) -> set:
    """Every Python dependency named anywhere in the manifests, dev and optional groups included."""
    names = set()
    for rel in all_paths:
        base = rel.rsplit("/", 1)[-1]
        if not (re.match(r"requirements.*\.txt$", base) or base in ("pyproject.toml", "Pipfile", "setup.py", "setup.cfg")):
            continue
        text = _read(root, rel)
        for m in re.finditer(r"(?im)^[\s\"']*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~;\"',]|$)", text):
            names.add(_norm(m.group(1)))
        if base in ("pyproject.toml", "setup.py", "setup.cfg"):
            names |= _quoted_requirements(_list_after(text, "dependencies") + _list_after(text, "install_requires"))
    return names


def python_project(root: str, all_paths: list) -> dict:
    """{'names': project names, 'runtime': dependencies the installed project needs, without dev/test/docs groups}."""
    names, runtime = set(), set()
    for rel in all_paths:
        if rel.count("/") > 2 or re.search(r"(^|/)(tests?|docs?|examples?|samples?)/", rel):
            continue
        base = rel.rsplit("/", 1)[-1]
        if re.match(r"requirements.*\.txt$", base):
            if re.search(r"(?i)dev|test|doc|lint|ci|typing|build|bench|example|tox", base):
                continue
            text = _read(root, rel)
            runtime |= {_norm(m.group(1)) for m in re.finditer(
                r"(?m)^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~;]|$)", text)}
        elif base == "pyproject.toml":
            text = _read(root, rel)
            project = _toml_section(text, "project")
            m = re.search(r"(?m)^\s*name\s*=\s*[\"']([^\"']+)", project or _toml_section(text, "tool.poetry"))
            if m:
                names.add(_norm(m.group(1)))
            runtime |= _quoted_requirements(_list_after(project, "dependencies"))
            poetry = _toml_section(text, "tool.poetry.dependencies")
            runtime |= {_norm(m.group(1)) for m in re.finditer(r"(?m)^\s*([A-Za-z0-9][\w.\-]*)\s*=", poetry)} - {"python"}
        elif base == "setup.py":
            text = _read(root, rel)
            m = re.search(r"\bname\s*=\s*[\"']([^\"']+)", text)
            if m:
                names.add(_norm(m.group(1)))
            runtime |= _quoted_requirements(_list_after(text, "install_requires"))
        elif base == "Pipfile":
            runtime |= {_norm(m.group(1)) for m in re.finditer(r"(?m)^\s*([A-Za-z0-9][\w.\-]*)\s*=",
                                                                 _toml_section(_read(root, rel), "packages"))}
    return {"names": names, "runtime": runtime}


def node_manifest(root: str, rel: str) -> dict:
    try:
        pkg = json.loads(_read(root, rel) or "{}")
    except json.JSONDecodeError:
        return {}
    return pkg if isinstance(pkg, dict) else {}


def detect(root: str, files: list, all_paths: list) -> dict:
    langs = Counter()
    for rel in all_paths:
        ext = os.path.splitext(rel)[1].lower()
        if ext in LANG_BY_EXT:
            langs[LANG_BY_EXT[ext]] += 1
    frameworks = []
    ndeps = {}
    for manifest in node_manifests(root, all_paths):
        ndeps.update(node_deps(root, manifest))
    for dep, name in NODE_FRAMEWORKS.items():
        if dep in ndeps and name not in frameworks:
            frameworks.append(name)
    pdeps = python_deps(root, all_paths)
    for dep, name in PY_FRAMEWORKS.items():
        if dep in pdeps:
            frameworks.append(name)
    for marker, pattern, name in OTHER_MARKERS:
        for rel in all_paths:
            if rel.rsplit("/", 1)[-1] == marker and re.search(pattern, _read(root, rel)):
                if name not in frameworks:
                    frameworks.append(name)
                break
    return {
        "languages": [lang for lang, _ in langs.most_common()],
        "frameworks": frameworks,
        "node_deps": sorted(ndeps),
        "python_deps": sorted(pdeps),
        "docker": any(p.rsplit("/", 1)[-1].lower().startswith("dockerfile") for p in all_paths),
    }
