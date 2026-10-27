"""Offline dependency vulnerability matching against a local OSV.dev mirror (SQLite).

`hardn update` is the only networked command: it downloads OSV's free per-ecosystem
dumps (which aggregate GitHub Security Advisories, PyPA, RustSec, Go vulndb, ...) plus
CISA's Known Exploited Vulnerabilities catalog. Every scan afterwards is fully offline.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import ssl
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .models import SEV_RANK, Finding

HOME = Path(os.environ.get("HARDN_HOME", Path.home() / ".hardn"))
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_ECOSYSTEMS = ("npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "Packagist")
SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def db_path() -> Path:
    return HOME / "osv.sqlite"


def _connect(path: Path | None = None) -> sqlite3.Connection:
    path = path or db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS vulns (eco TEXT, name TEXT, id TEXT, summary TEXT, severity TEXT,
                                          aliases TEXT, affected TEXT);
        CREATE INDEX IF NOT EXISTS vulns_pkg ON vulns (eco, name);
        CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    return con


def normalize(eco: str, name: str) -> str:
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name.lower())
    return name


# ---------------------------------------------------------------- update (network)

CA_BUNDLES = ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt")


def _ssl_context() -> ssl.SSLContext:
    """Verified TLS that also works on python.org macOS builds that never ran 'Install Certificates'."""
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca"):
        return ctx
    try:
        import certifi  # optional
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    for path in CA_BUNDLES:
        if os.path.isfile(path):
            return ssl.create_default_context(cafile=path)
    return ctx


def update(ecosystems=DEFAULT_ECOSYSTEMS, log=print, db: Path | None = None) -> int:
    """Download advisories. Returns the number of sources that failed."""
    con = _connect(db)
    ctx = _ssl_context()
    failures = 0
    for eco in ecosystems:
        url = OSV_URL.format(eco=urllib.parse.quote(eco))
        log(f"  ↓ {eco:<10} {url}")
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            try:
                with urllib.request.urlopen(url, timeout=120, context=ctx) as resp:
                    while chunk := resp.read(1 << 20):
                        tmp.write(chunk)
            except OSError as exc:
                log(f"    ! failed: {exc}")
                failures += 1
                os.unlink(tmp.name)
                continue
        try:
            n = _load_zip(con, eco, tmp.name)
            log(f"    ✓ {n:,} advisories")
        except zipfile.BadZipFile:
            log("    ! failed: download was not a valid zip")
            failures += 1
        finally:
            os.unlink(tmp.name)
    log(f"  ↓ CISA KEV  {KEV_URL}")
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "hardn"})
        with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
            kev = json.load(resp)
        cves = [(v["cveID"],) for v in kev.get("vulnerabilities", [])]
        with con:
            con.execute("DELETE FROM kev")
            con.executemany("INSERT OR IGNORE INTO kev VALUES (?)", cves)
        log(f"    ✓ {len(cves):,} known-exploited CVEs")
    except (OSError, ValueError) as exc:
        log(f"    ! failed: {exc}")
        failures += 1
    if failures < len(ecosystems) + 1:
        with con:
            con.execute("INSERT OR REPLACE INTO meta VALUES ('updated_at', ?)", (str(int(time.time())),))
    con.close()
    return failures


def _load_zip(con: sqlite3.Connection, eco: str, zip_path: str) -> int:
    rows = []
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                v = json.loads(zf.read(name))
            except ValueError:
                continue
            if v.get("withdrawn"):
                continue
            sev = SEV_MAP.get(str((v.get("database_specific") or {}).get("severity", "")).upper(), "medium")
            for aff in v.get("affected", []):
                pkg = aff.get("package", {})
                if pkg.get("ecosystem") != eco:
                    continue
                rows.append((
                    eco, normalize(eco, pkg.get("name", "")), v["id"], (v.get("summary") or v.get("details", ""))[:300],
                    sev, json.dumps(v.get("aliases", [])),
                    json.dumps({"ranges": aff.get("ranges", []), "versions": aff.get("versions", [])}),
                ))
    with con:
        con.execute("DELETE FROM vulns WHERE eco = ?", (eco,))
        con.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?)", rows)
    return len({r[2] for r in rows})


def status(db: Path | None = None) -> dict:
    path = db or db_path()
    if not path.exists():
        return {"present": False}
    con = _connect(path)
    counts = dict(con.execute("SELECT eco, COUNT(DISTINCT id) FROM vulns GROUP BY eco").fetchall())
    kev = con.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
    row = con.execute("SELECT value FROM meta WHERE key='updated_at'").fetchone()
    con.close()
    age = (time.time() - int(row[0])) / 86400 if row else None
    return {"present": bool(counts), "ecosystems": counts, "kev": kev, "age_days": age}


# ---------------------------------------------------------------- version matching

_PRE = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "c": 3, "rc": 3, "pre": 3, "preview": 3}


def vkey(version: str) -> tuple:
    """Lenient, cross-ecosystem version sort key (semver, PEP 440-ish, Go, Maven)."""
    v = version.strip().lstrip("vV").split("+", 1)[0]
    tokens = re.findall(r"\d+|[A-Za-z]+", v)
    lead = []
    while tokens and tokens[0].isdigit():
        lead.append(int(tokens.pop(0)))
    while len(lead) > 1 and lead[-1] == 0:
        lead.pop()
    key = [(2, n) for n in lead]
    for t in tokens:
        if t.isdigit():
            key.append((2, int(t)))
        elif t.lower() in ("post", "patch", "sp", "final", "ga", "release"):
            key.append((1, 5))
        else:
            key.append((0, _PRE.get(t.lower(), 1)))
    key.append((1, 0))
    return tuple(key)


def is_affected(version: str, affected: dict) -> bool:
    if version in affected.get("versions", []):
        return True
    vk = vkey(version)
    for rng in affected.get("ranges", []):
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        intro = None
        for ev in rng.get("events", []):
            if "introduced" in ev:
                intro = ev["introduced"]
            elif "fixed" in ev and intro is not None:
                if (intro == "0" or vkey(intro) <= vk) and vk < vkey(ev["fixed"]):
                    return True
                intro = None
            elif "last_affected" in ev and intro is not None:
                if (intro == "0" or vkey(intro) <= vk) and vk <= vkey(ev["last_affected"]):
                    return True
                intro = None
        if intro is not None and (intro == "0" or vkey(intro) <= vk):
            return True
    return False


def fixed_versions(affected: dict) -> list:
    return [ev["fixed"] for r in affected.get("ranges", []) if r.get("type") in ("SEMVER", "ECOSYSTEM")
            for ev in r.get("events", []) if "fixed" in ev]


# ---------------------------------------------------------------- manifest parsing

def collect_packages(root: str, all_paths: list) -> list:
    """Return [(ecosystem, name, version, manifest_path)] from lockfiles / pinned manifests."""
    pkgs = []
    for rel in all_paths:
        base = rel.rsplit("/", 1)[-1]
        full = os.path.join(root, rel)
        try:
            if base in ("package-lock.json", "npm-shrinkwrap.json"):
                pkgs += [("npm", n, v, rel) for n, v in _npm_lock(full)]
            elif base == "yarn.lock":
                pkgs += [("npm", n, v, rel) for n, v in _yarn_lock(full)]
            elif re.match(r"requirements.*\.txt$", base):
                pkgs += [("PyPI", n, v, rel) for n, v in _requirements(full)]
            elif base in ("poetry.lock", "uv.lock", "Cargo.lock"):
                eco = "crates.io" if base == "Cargo.lock" else "PyPI"
                pkgs += [(eco, n, v, rel) for n, v in _toml_lock(full)]
            elif base == "go.mod":
                pkgs += [("Go", n, v, rel) for n, v in _gomod(full)]
            elif base == "Gemfile.lock":
                pkgs += [("RubyGems", n, v, rel) for n, v in _gemfile_lock(full)]
            elif base == "composer.lock":
                data = json.loads(Path(full).read_text(encoding="utf-8", errors="replace"))
                pkgs += [("Packagist", p["name"], p["version"].lstrip("v"), rel)
                         for p in data.get("packages", []) + data.get("packages-dev", [])]
        except (OSError, ValueError, KeyError):
            continue
    seen, out = set(), []
    for p in pkgs:
        if p[:3] not in seen:
            seen.add(p[:3])
            out.append(p)
    return out


def _npm_lock(path):
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    if "packages" in data:
        for key, meta in data["packages"].items():
            if key and "node_modules/" in key and meta.get("version") and not meta.get("link"):
                yield key.rsplit("node_modules/", 1)[-1], meta["version"]
    else:
        stack = [data.get("dependencies", {})]
        while stack:
            for name, meta in stack.pop().items():
                if meta.get("version"):
                    yield name, meta["version"]
                stack.append(meta.get("dependencies", {}))


def _yarn_lock(path):
    name = None
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if line and not line.startswith((" ", "#")):
            first = line.split(",")[0].strip().strip('"').rstrip(":")
            name = first.rsplit("@", 1)[0] if first.count("@") > (1 if first.startswith("@") else 0) else first
        m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
        if m and name:
            yield name, m.group(1)
            name = None


def _requirements(path):
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)(\[[^\]]*\])?\s*==\s*([^\s;#]+)", line)
        if m:
            yield m.group(1), m.group(3)


def _toml_lock(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
        yield m.group(1), m.group(2)


def _gomod(path):
    for m in re.finditer(r"(?m)^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", Path(path).read_text(encoding="utf-8", errors="replace")):
        yield m.group(1), m.group(2)


def _gemfile_lock(path):
    for m in re.finditer(r"(?m)^    ([A-Za-z0-9_.\-]+) \(([\w.\-]+)\)$", Path(path).read_text(encoding="utf-8", errors="replace")):
        yield m.group(1), m.group(2)


# ---------------------------------------------------------------- scan (offline)

def scan(root: str, all_paths: list, db: Path | None = None):
    pkgs = collect_packages(root, all_paths)
    st = status(db)
    if not pkgs:
        return [], "no lockfiles found"
    if not st["present"]:
        return [], f"{len(pkgs)} packages found, no advisory DB — run `hardn update`"
    con = _connect(db)
    kev = {r[0] for r in con.execute("SELECT cve FROM kev")}
    findings = []
    for eco, name, version, manifest in pkgs:
        rows = con.execute("SELECT id, summary, severity, aliases, affected FROM vulns WHERE eco=? AND name=?",
                           (eco, normalize(eco, name))).fetchall()
        hits = {}
        for vid, summary, sev, aliases, affected in rows:
            aff = json.loads(affected)
            if vid in hits or not is_affected(version, aff):
                continue
            exploited = bool(kev & set(json.loads(aliases) + [vid]))
            hits[vid] = (summary, "critical" if exploited else sev, fixed_versions(aff), exploited)
        if not hits:
            continue
        sev = max((h[1] for h in hits.values()), key=SEV_RANK.get)
        fixes = [f for h in hits.values() for f in h[2] if vkey(f) > vkey(version)]
        target = max(fixes, key=vkey) if fixes else None
        exploited = [vid for vid, h in hits.items() if h[3]]
        ids = sorted(hits)
        fix = (f"Upgrade `{name}` from {version} to >= {target} (clears {', '.join(ids[:6])}"
               f"{'…' if len(ids) > 6 else ''}). If it's a transitive dependency, upgrade the parent package or "
               f"add an override/resolution. Read the changelog for breaking changes and run the test suite."
               if target else f"No fixed release published for `{name}` {version}. Assess reachability; replace the "
               "package or mitigate around the vulnerable API.")
        findings.append(Finding(
            rule_id=f"DEP-{eco}", title=f"{name}@{version}: {len(ids)} known vulnerabilit{'y' if len(ids) == 1 else 'ies'}"
            + (" (actively exploited)" if exploited else ""), severity=sev, category="dependency", file=manifest,
            snippet="; ".join(f"{vid}: {hits[vid][0][:90]}" for vid in ids[:4]), cwe="CWE-1395", fix=fix,
            sources=["osv"], extra={"package": name, "version": version, "ecosystem": eco, "ids": ids,
                                    "fixed_in": target, "kev": exploited},
        ))
    con.close()
    age = st.get("age_days")
    note = f"{len(pkgs)} packages checked"
    if age is not None and age > 7:
        note += f" · advisories {age:.0f}d old — run `hardn update`"
    return findings, note
