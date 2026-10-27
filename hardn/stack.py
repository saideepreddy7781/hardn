"""Detect languages and frameworks so checks and prompts can be stack-specific."""
from __future__ import annotations

import json
import os
import re
from collections import Counter

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
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
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


def python_deps(root: str, all_paths: list) -> set:
    names = set()
    for rel in all_paths:
        base = rel.rsplit("/", 1)[-1]
        if not (re.match(r"requirements.*\.txt$", base) or base in ("pyproject.toml", "Pipfile", "setup.py", "setup.cfg")):
            continue
        for m in re.finditer(r"(?im)^[\s\"']*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~;\"',]|$)", _read(root, rel)):
            names.add(re.sub(r"[-_.]+", "-", m.group(1).lower()))
    return names


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
