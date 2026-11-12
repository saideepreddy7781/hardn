"""Offline dependency vulnerability matching against a local OSV.dev mirror (SQLite).

`hardn update` is the only networked command: it downloads OSV's free per-ecosystem
dumps (which aggregate GitHub Security Advisories, PyPA, RustSec, Go vulndb, ...) plus
CISA's Known Exploited Vulnerabilities catalog. Every scan afterwards is fully offline.

`scan()` returns `(findings, note, gaps)`. A gap is a plain sentence about a check that could
not run and that could change the grade: no advisory data for an ecosystem the project uses,
stale data, a lockfile that could not be read, or a requirement with no pinned version.
"""
from __future__ import annotations

import functools
import http.client
import json
import math
import os
import re
import sqlite3
import ssl
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path
from typing import NamedTuple
from xml.etree import ElementTree

from . import walker
from .models import SEV_RANK, Finding

HOME = Path(os.environ.get("HARDN_HOME", Path.home() / ".hardn"))
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_ECOSYSTEMS = ("npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "Packagist")
SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}

SCHEMA_VERSION = 1           # PRAGMA user_version of a database this module writes
STALE_DAYS = 30              # older advisory data is a gap
WARN_DAYS = 7                # older advisory data gets a note
MAX_DOWNLOAD_BYTES = 2 << 30          # one OSV zip (npm is about 220 MB in 2026)
MAX_MEMBER_BYTES = 64 << 20           # one advisory JSON inside the zip
MAX_UNCOMPRESSED_BYTES = 6 << 30      # all members of one zip together (npm is about 400 MB)
MAX_KEV_BYTES = 64 << 20
MAX_MANIFEST_BYTES = 64 << 20
MAX_REQUIREMENT_FILES = 64            # -r / -c includes followed per top-level requirements file
MAX_INCLUDE_DEPTH = 8


class AdvisoryDbError(Exception):
    """The advisory database exists but cannot be used. The message is a plain sentence."""


class LockfileError(Exception):
    """A dependency file exists but could not be read."""


class Package(NamedTuple):
    eco: str
    name: str            # "" for a placeholder: an ecosystem is in use but nothing could be read
    version: str         # "" when the file does not pin a version
    path: str
    dev: bool = False    # only in dev, test or docs dependency groups
    direct: bool | None = None  # None when the file does not say
    source: str = "registry"     # registry | unpinned | unreadable | local


def db_path() -> Path:
    return HOME / "osv.sqlite"


# ---------------------------------------------------------------- database

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vulns (eco TEXT, name TEXT, id TEXT, summary TEXT, severity TEXT,
                                  aliases TEXT, affected TEXT);
CREATE INDEX IF NOT EXISTS vulns_pkg ON vulns (eco, name);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""
_VULN_COLUMNS = ("eco", "name", "id", "summary", "severity", "aliases", "affected")


def _schema_state(con: sqlite3.Connection) -> str:
    """'current', 'empty', 'legacy' (written before versioning, same columns), 'newer' or 'old'."""
    version = con.execute("PRAGMA user_version").fetchone()[0]
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if version > SCHEMA_VERSION:
        return "newer"
    if not tables:
        return "empty"
    cols = tuple(r[1] for r in con.execute("PRAGMA table_info(vulns)"))
    if cols != _VULN_COLUMNS or not {"kev", "meta"} <= tables:
        return "old"
    return "current" if version == SCHEMA_VERSION else "legacy"


def _db_problem(path: Path, exc: Exception) -> str:
    if "locked" in str(exc) or "busy" in str(exc):
        return (f"The advisory database at {path} stayed locked by another process for 30 seconds "
                "(probably a running `hardn update`). Scan again when it finishes.")
    return f"The advisory database at {path} is damaged ({exc}). Run `hardn update`."


def _connect(path: Path | None = None, create: bool = True) -> sqlite3.Connection:
    """Open the advisory database, creating the schema in a new file. Raises AdvisoryDbError."""
    path = path or db_path()
    try:
        if create:
            path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(str(path), timeout=30)
    except (OSError, sqlite3.Error) as exc:
        raise AdvisoryDbError(f"The advisory database at {path} could not be opened ({exc}).") from exc
    try:
        state = _schema_state(con)
        if state == "empty" and create:
            con.executescript(_SCHEMA)
            con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            con.commit()
        elif state == "newer":
            raise AdvisoryDbError(f"The advisory database at {path} was written by a newer hardn. "
                                  "Upgrade hardn or run `hardn update`.")
        elif state == "old":
            raise AdvisoryDbError(f"The advisory database at {path} uses an old format. Run `hardn update`.")
        return con
    except sqlite3.Error as exc:
        con.close()
        raise AdvisoryDbError(_db_problem(path, exc)) from exc
    except AdvisoryDbError:
        con.close()
        raise


def _open_for_update(path: Path) -> sqlite3.Connection:
    """Open for writing. A damaged or outdated cache is deleted and rebuilt, since it holds only downloads."""
    try:
        return _connect(path)
    except (AdvisoryDbError, sqlite3.Error) as exc:
        if "newer hardn" in str(exc):
            raise
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                os.unlink(str(path) + suffix)
            except FileNotFoundError:
                pass
        return _connect(path)


def normalize(eco: str, name: str) -> str:
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name.lower())
    if eco in ("crates.io", "Packagist"):  # both registries treat names case-insensitively
        return name.lower()
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


class UpdateError(Exception):
    """One source failed. The message is shown to the user."""


_NET_ERRORS = (OSError, http.client.HTTPException, ValueError)


def _download(url: str, ctx, dest, limit: int) -> int:
    total = 0
    req = urllib.request.Request(url, headers={"User-Agent": "hardn"})
    with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise UpdateError(f"download is larger than {limit >> 20} MB, refusing it")
            dest.write(chunk)
    return total


def update(ecosystems=DEFAULT_ECOSYSTEMS, log=print, db: Path | None = None) -> int:
    """Download advisories. Returns the number of sources that failed. Existing data survives every failure."""
    ecosystems = list(ecosystems)
    path = db or db_path()
    try:
        con = _open_for_update(path)
    except (AdvisoryDbError, OSError, sqlite3.Error) as exc:
        log(f"    ! failed: {exc}")
        return len(ecosystems) + 1
    try:
        # A database from before schema versioning keeps working; it is stamped current only once every
        # ecosystem in it has been reloaded, since its stored severities came from older code.
        legacy = _schema_state(con) == "legacy"
        stored = {r[0] for r in con.execute("SELECT DISTINCT eco FROM vulns")} if legacy else set()
    except sqlite3.Error as exc:
        con.close()
        log(f"    ! failed: {exc}")
        return len(ecosystems) + 1
    ctx = _ssl_context()
    failures, loaded, done = 0, 0, set()
    try:
        for eco in ecosystems:
            url = OSV_URL.format(eco=urllib.parse.quote(eco))
            log(f"  ↓ {eco:<10} {url}")
            tmp_name = None
            try:
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    tmp_name = tmp.name
                    _download(url, ctx, tmp, MAX_DOWNLOAD_BYTES)
                n, skipped = _load_zip(con, eco, tmp_name)
                loaded += 1
                done.add(eco)
                log(f"    ✓ {n:,} advisories" + (f" ({skipped:,} unreadable records skipped)" if skipped else ""))
            except UpdateError as exc:
                log(f"    ! failed: {exc}; kept the existing {eco} data")
                failures += 1
            except (zipfile.BadZipFile, zlib.error, EOFError):
                log(f"    ! failed: download was not a valid zip; kept the existing {eco} data")
                failures += 1
            except sqlite3.Error as exc:
                log(f"    ! failed: database error ({exc}); kept the existing {eco} data")
                failures += 1
            except _NET_ERRORS as exc:
                log(f"    ! failed: {exc}; kept the existing {eco} data")
                failures += 1
            finally:
                if tmp_name:
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
        log(f"  ↓ CISA KEV  {KEV_URL}")
        try:
            n = _load_kev(con, ctx)
            log(f"    ✓ {n:,} known-exploited CVEs")
        except (UpdateError, sqlite3.Error, *_NET_ERRORS) as exc:
            log(f"    ! failed: {exc}; kept the existing KEV data")
            failures += 1
        if loaded:
            try:
                with con:
                    con.execute("INSERT OR REPLACE INTO meta VALUES ('updated_at', ?)", (str(int(time.time())),))
                if legacy and stored <= done:
                    con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    con.commit()
            except sqlite3.Error as exc:
                log(f"    ! could not record the update time: {exc}")
    finally:
        con.close()
    return failures


def _load_kev(con: sqlite3.Connection, ctx) -> int:
    with tempfile.TemporaryFile() as tmp:
        _download(KEV_URL, ctx, tmp, MAX_KEV_BYTES)
        tmp.seek(0)
        try:
            data = json.loads(tmp.read().decode("utf-8", errors="replace"))
        except ValueError as exc:
            raise UpdateError("KEV feed was not JSON") from exc
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise UpdateError("KEV feed had no vulnerability list")
    cves = sorted({v["cveID"] for v in items if isinstance(v, dict) and isinstance(v.get("cveID"), str)})
    if not cves:
        raise UpdateError("KEV feed listed no CVEs")
    with con:
        con.execute("DELETE FROM kev")
        con.executemany("INSERT OR IGNORE INTO kev VALUES (?)", [(c,) for c in cves])
        con.execute("INSERT OR REPLACE INTO meta VALUES ('kev_updated_at', ?)", (str(int(time.time())),))
    return len(cves)


def _records(zf: zipfile.ZipFile):
    """Yield parsed advisory dicts (None for an unreadable record), within the size limits."""
    total = 0
    for info in zf.infolist():
        if not info.filename.endswith(".json") or info.is_dir():
            continue
        if info.file_size > MAX_MEMBER_BYTES:
            raise UpdateError(f"zip member {info.filename[:60]} is larger than {MAX_MEMBER_BYTES >> 20} MB")
        with zf.open(info) as fh:
            raw = fh.read(MAX_MEMBER_BYTES + 1)
        if len(raw) > MAX_MEMBER_BYTES:
            raise UpdateError(f"zip member {info.filename[:60]} is larger than {MAX_MEMBER_BYTES >> 20} MB")
        total += len(raw)
        if total > MAX_UNCOMPRESSED_BYTES:
            raise UpdateError(f"zip expands past {MAX_UNCOMPRESSED_BYTES >> 30} GB")
        try:
            v = json.loads(raw)
        except ValueError:
            yield None
            continue
        yield v if isinstance(v, dict) else None


def _rows(eco: str, v: dict):
    vid = v.get("id")
    if not isinstance(vid, str) or not vid:
        return None
    if v.get("withdrawn"):
        return []
    affected = v.get("affected")
    if not isinstance(affected, list):
        return None
    aliases = [a for a in v.get("aliases") or [] if isinstance(a, str)] if isinstance(v.get("aliases"), list) else []
    summary = v.get("summary") or v.get("details") or ""
    summary = summary[:300] if isinstance(summary, str) else ""
    out = []
    for aff in affected:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package")
        if not isinstance(pkg, dict) or pkg.get("ecosystem") != eco or not isinstance(pkg.get("name"), str):
            continue
        ranges = [r for r in aff.get("ranges") or [] if isinstance(r, dict) and r.get("type") in ("SEMVER", "ECOSYSTEM")
                  and isinstance(r.get("events"), list)]
        versions = [x for x in aff.get("versions") or [] if isinstance(x, str)]
        if not ranges and not versions:
            continue
        stored = {"ranges": ranges, "versions": versions}
        info = (v.get("database_specific") or {}).get("informational") if isinstance(v.get("database_specific"), dict) else None
        if info:
            stored["informational"] = str(info)
        out.append((normalize(eco, pkg["name"]), vid, summary, record_severity(v, aff), json.dumps(aliases),
                    json.dumps(stored)))
    return out


def _load_zip(con: sqlite3.Connection, eco: str, zip_path: str) -> tuple:
    """Replace one ecosystem's advisories atomically. Returns (advisories, unreadable records).

    Nothing is deleted unless the new data parsed, holds at least one advisory and is not a sudden
    collapse of what was there before (a truncated or tampered dump).
    """
    skipped = 0
    con.execute("DROP TABLE IF EXISTS temp.staged")
    con.execute("CREATE TEMP TABLE staged (name TEXT, id TEXT, summary TEXT, severity TEXT, aliases TEXT, affected TEXT)")
    try:
        with zipfile.ZipFile(zip_path) as zf:
            batch = []
            for v in _records(zf):
                rows = _rows(eco, v) if v is not None else None
                if rows is None:
                    skipped += 1
                    continue
                batch += rows
                if len(batch) >= 5000:
                    con.executemany("INSERT INTO temp.staged VALUES (?,?,?,?,?,?)", batch)
                    batch = []
            con.executemany("INSERT INTO temp.staged VALUES (?,?,?,?,?,?)", batch)
        new = con.execute("SELECT COUNT(DISTINCT id) FROM temp.staged").fetchone()[0]
        old = con.execute("SELECT COUNT(DISTINCT id) FROM vulns WHERE eco=?", (eco,)).fetchone()[0]
        if not new:
            raise UpdateError("the download held no usable advisories")
        if old >= 200 and new < old // 10:
            raise UpdateError(f"the download held {new:,} advisories where {old:,} were stored before")
        con.execute("DELETE FROM vulns WHERE eco = ?", (eco,))
        con.execute("INSERT INTO vulns SELECT ?, name, id, summary, severity, aliases, affected FROM temp.staged", (eco,))
        con.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (f"updated:{eco}", str(int(time.time()))))
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        try:
            con.execute("DROP TABLE IF EXISTS temp.staged")
        except sqlite3.Error:
            pass
    return new, skipped


def status(db: Path | None = None) -> dict:
    """State of the advisory DB. `error` holds a sentence when the file exists but cannot be used."""
    path = db or db_path()
    base = {"present": False, "ecosystems": {}, "kev": 0, "age_days": None, "eco_age_days": {}, "error": None,
            "legacy": False}
    try:
        if not path.exists() or path.stat().st_size == 0:
            return base
    except OSError:
        return base
    try:
        con = _connect(path, create=False)
    except AdvisoryDbError as exc:
        return {**base, "error": str(exc)}
    try:
        legacy = _schema_state(con) == "legacy"
        counts = dict(con.execute("SELECT eco, COUNT(DISTINCT id) FROM vulns GROUP BY eco").fetchall())
        kev = con.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
        meta = dict(con.execute("SELECT key, value FROM meta").fetchall())
    except sqlite3.Error as exc:
        return {**base, "error": _db_problem(path, exc)}
    finally:
        con.close()
    now = time.time()

    def age(key):
        try:
            return max(0.0, (now - int(meta[key])) / 86400)
        except (KeyError, ValueError, TypeError):
            return None

    overall = age("updated_at")
    eco_age = {}
    for eco in counts:
        a = age(f"updated:{eco}")
        eco_age[eco] = a if a is not None else overall
    known = [a for a in eco_age.values() if a is not None]
    return {**base, "present": bool(counts), "ecosystems": counts, "kev": kev, "legacy": legacy,
            "age_days": max(known) if known else overall, "eco_age_days": eco_age}


# ---------------------------------------------------------------- severity

def _roundup(x: float) -> float:
    """CVSS v3.1 Roundup: smallest number with one decimal that is >= x, robust to float noise."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def _metrics(vector: str) -> dict:
    return dict(p.split(":", 1) for p in vector.strip().split("/") if ":" in p)


_V3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
       "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _v3_score(av, ac, pr, ui, changed, c, i, a) -> float:
    """CVSS v3.1 base score equations (FIRST specification, section 7.1)."""
    pr_w = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[pr]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploit = 8.22 * av * ac * pr_w * ui
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploit), 10)) if changed else _roundup(min(impact + exploit, 10))


def cvss_score(vector: str) -> float | None:
    """Base score from a CVSS v2, v3.0, v3.1 or v4.0 vector string. None when it cannot be read."""
    try:
        m = _metrics(vector)
        if vector.startswith("CVSS:3"):
            return _v3_score(_V3["AV"][m["AV"]], _V3["AC"][m["AC"]], m["PR"], _V3["UI"][m["UI"]], m["S"] == "C",
                             _V3["CIA"][m["C"]], _V3["CIA"][m["I"]], _V3["CIA"][m["A"]])
        if vector.startswith("CVSS:4"):
            # The real 4.0 score comes from FIRST's lookup table of 270 macro-vectors, which is not shipped here.
            # This is an upper estimate through the 3.1 equations: attack requirements (AT) are ignored, any
            # passive or active user interaction counts as 3.1 "Required", each impact takes the worse of the
            # vulnerable and subsequent system, and any subsequent-system impact counts as a scope change.
            # Every one of these choices can only raise the score, so the estimate never understates severity.
            cia = {k: _V3["CIA"][max(m[f"V{k}"], m[f"S{k}"], key=lambda x: _V3["CIA"][x])] for k in "CIA"}
            changed = any(m[f"S{k}"] != "N" for k in "CIA")
            return _v3_score(_V3["AV"][m["AV"]], _V3["AC"][m["AC"]], m["PR"], 0.85 if m["UI"] == "N" else 0.62,
                             changed, cia["C"], cia["I"], cia["A"])
        if "Au" in m:  # CVSS v2 base equation
            cia = {"N": 0.0, "P": 0.275, "C": 0.660}
            impact = 10.41 * (1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]]))
            exploit = 20 * {"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]] * {"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]] \
                * {"M": 0.45, "S": 0.56, "N": 0.704}[m["Au"]]
            return round(((0.6 * impact) + (0.4 * exploit) - 1.5) * (0 if impact == 0 else 1.176), 1)
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
    return None


def score_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def record_severity(v: dict, aff: dict | None = None) -> str:
    """Severity of one advisory for one affected package: malicious > worst of CVSS and GHSA rating."""
    ids = [v.get("id", "")] + [a for a in (v.get("aliases") or []) if isinstance(a, str)]
    if any(str(i).startswith("MAL-") for i in ids):
        return "critical"  # malicious package: installing it is the compromise
    found = []
    for source in (v, aff or {}):
        for s in source.get("severity") or []:
            if isinstance(s, dict) and isinstance(s.get("score"), str):
                score = cvss_score(s["score"])
                if score is not None:
                    found.append(score_severity(score))
        for key in ("database_specific", "ecosystem_specific"):
            word = (source.get(key) or {}).get("severity") if isinstance(source.get(key), dict) else None
            if isinstance(word, str) and word.upper() in SEV_MAP:
                found.append(SEV_MAP[word.upper()])
    if found:
        return max(found, key=SEV_RANK.get)
    ds = v.get("database_specific") if isinstance(v.get("database_specific"), dict) else {}
    if ds.get("informational"):
        return "info"  # e.g. RUSTSEC "unmaintained" notices
    return "medium"


# ---------------------------------------------------------------- version ordering

SEMVER_ECOSYSTEMS = ("npm", "Go", "crates.io")
_SEMVER = re.compile(r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?([0-9A-Za-z.\-]*)$")


def _semver_key(version: str):
    """SemVer 2.0 precedence, coerced the way OSV does it (missing minor/patch read as 0, build ignored)."""
    m = _SEMVER.match(version.strip().split("+", 1)[0])
    if not m:
        return None
    core = [int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)]
    rest = m.group(4)
    while rest.startswith(".") and re.match(r"\.\d+", rest):  # 1.2.3.4: keep extra numeric parts
        n = re.match(r"\.(\d+)", rest)
        core.append(int(n.group(1)))
        rest = rest[n.end():]
    if not rest:
        return (tuple(core), 1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in rest.lstrip("-.").split("."))
    return (tuple(core), 0, ids)


_PEP440 = re.compile(
    r"^\s*v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$", re.IGNORECASE)
_PRE_NORM = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "c": "rc", "pre": "rc", "preview": "rc", "rc": "rc"}


def _legacy_key(version: str):
    """packaging's LegacyVersion: what OSV uses for strings that are not PEP 440. It sorts below them all."""
    parts = []
    for part in re.split(r"(\d+|[a-z]+|\.|-)", version.lower()):
        part = {"pre": "c", "preview": "c", "-": "final-", "rc": "c", "dev": "@"}.get(part, part)
        if not part or part == ".":
            continue
        part = part.zfill(8) if part[:1].isdigit() else "*" + part
        if part.startswith("*"):
            if part < "*final":
                while parts and parts[-1] == "*final-":
                    parts.pop()
            while parts and parts[-1] == "00000000":
                parts.pop()
        parts.append(part)
    parts.append("*final")
    return (-1, tuple(parts))


def _pep440_key(version: str):
    m = _PEP440.match(version)
    if not m:
        return _legacy_key(version)
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = (_PRE_NORM[m.group("pre_l").lower()], int(m.group("pre_n") or 0)) if m.group("pre_l") else None
    post_n = m.group("post_n1") or m.group("post_n2")
    post = int(post_n or 0) if (m.group("post_n1") or m.group("post_l")) else None
    dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None
    if pre is None and post is None and dev is not None:
        pre_k = (-1,)
    elif pre is None:
        pre_k = (2,)
    else:
        pre_k = (1,) + pre
    post_k = (-1,) if post is None else (0, post)
    dev_k = (1,) if dev is None else (0, dev)
    local = m.group("local")
    local_k = (0,) if not local else (1,) + tuple((1, int(p), "") if p.isdigit() else (0, 0, p.lower())
                                                  for p in re.split(r"[-_.]", local))
    return (0, int(m.group("epoch") or 0), tuple(release), pre_k, post_k, dev_k, local_k)


def _cmp(a, b) -> int:
    return (a > b) - (a < b)


# Packagist: PHP version_compare(), which is what OSV implements for this ecosystem. Note "2.2" < "2.2.0".
_PHP_SPECIAL = (("dev", 0), ("alpha", 1), ("a", 1), ("beta", 2), ("b", 2), ("rc", 3), ("#", 4), ("pl", 5), ("p", 5))


def _php_parts(version: str) -> list:
    v = version.strip()
    if v[:1] in ("v", "V") and v[1:2].isdigit():
        v = v[1:]
    v = re.sub(r"[-_+]", ".", v)
    v = re.sub(r"([^\d.])(\d)", r"\1.\2", v)
    v = re.sub(r"(\d)([^\d.])", r"\1.\2", v)
    return [p for p in v.split(".") if p]


def _php_special(s: str) -> int:
    s = s.lower()
    return next((rank for name, rank in _PHP_SPECIAL if s.startswith(name)), -1)


def _php_cmp_parts(a: list, b: list) -> int:
    for x, y in zip(a, b):
        if x.isdigit() and y.isdigit():
            c = _cmp(int(x), int(y))
        elif not x.isdigit() and not y.isdigit():
            c = _cmp(_php_special(x), _php_special(y))
        else:
            c = _cmp(_php_special("#"), _php_special(y)) if x.isdigit() else _cmp(_php_special(x), _php_special("#"))
        if c:
            return c
    if len(a) > len(b):
        return 1 if a[len(b)].isdigit() else _php_cmp_parts(a[len(b):], ["#"])
    if len(b) > len(a):
        return -1 if b[len(a)].isdigit() else _php_cmp_parts(["#"], b[len(a):])
    return 0


# Maven: ComparableVersion ordering from the Maven POM reference.
_MVN_ORDER = {"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4, "": 5, "sp": 6}


def _maven_tokens(version: str) -> list:
    tokens, prefix, prev = [], ".", None
    for part in re.findall(r"\d+|[^\d.\-]+|[.\-]", version.strip().lower()):
        if part in ".-":
            prefix, prev = part, None
            continue
        kind = "n" if part.isdigit() else "s"
        if prev is not None and prev != kind:
            prefix = "-"  # a switch between digits and letters acts as a hyphen
        tokens.append([prefix, int(part) if kind == "n" else part])
        prefix, prev = ".", kind
    for i, t in enumerate(tokens):
        if isinstance(t[1], str):
            nxt = tokens[i + 1][1] if i + 1 < len(tokens) else None
            if t[1] in ("a", "b", "m") and isinstance(nxt, int):
                t[1] = {"a": "alpha", "b": "beta", "m": "milestone"}[t[1]]
            t[1] = {"ga": "", "final": "", "release": "", "cr": "rc"}.get(t[1], t[1])
    end = len(tokens)
    while end > 0:  # trim trailing nulls, then repeat before each hyphen, from the end
        while end > 0 and tokens[end - 1][1] in (0, ""):
            del tokens[end - 1]
            end -= 1
        end -= 1
        while end > 0 and tokens[end][0] != "-":
            end -= 1
    return [tuple(t) for t in tokens]


def _mvn_tok_cmp(x, y) -> int:
    def rank(t):
        return 0 if isinstance(t[1], str) else (1 if t[0] == "-" else 2)

    rx, ry = rank(x), rank(y)
    if rx != ry:
        return _cmp(rx, ry)
    if rx:
        return _cmp(x[1], y[1])

    def qual(s):
        return (0, _MVN_ORDER[s], "") if s in _MVN_ORDER else (1, 0, s)

    return _cmp(qual(x[1]), qual(y[1]))


def _maven_cmp(a: list, b: list) -> int:
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else None
        y = b[i] if i < len(b) else None
        if x is None:
            x = (y[0], 0 if y[0] == "." else "")
        if y is None:
            y = (x[0], 0 if x[0] == "." else "")
        c = _mvn_tok_cmp(x, y)
        if c:
            return c
    return 0


_GEM_PLATFORM = re.compile(r"-(?:x86_64|x86|x64|i[3-6]86|arm64|aarch64|arm|universal|java|jruby|mswin\w*|mingw\w*|"
                           r"darwin|linux|ppc64le|s390x|wasm32)(?:-.*)?$", re.IGNORECASE)


def _gem_segments(version: str) -> list:
    # Gemfile.lock adds a platform: 1.16.5-x86_64-linux. Any other hyphen is a prerelease, as in Gem::Version.
    v = _GEM_PLATFORM.sub("", version.strip()).replace("-", ".pre.")
    segs = [int(s) if s.isdigit() else s for s in re.findall(r"\d+|[a-zA-Z]+", v)]
    cut = next((i for i, s in enumerate(segs) if isinstance(s, str)), len(segs))
    num, rest = segs[:cut], segs[cut:]
    while num and num[-1] == 0:
        num.pop()
    while rest and rest[-1] == 0:
        rest.pop()
    return num + rest


def _gem_cmp(a: list, b: list) -> int:
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        if x == y:
            continue
        if isinstance(x, str) and not isinstance(y, str):
            return -1
        if not isinstance(x, str) and isinstance(y, str):
            return 1
        return _cmp(x, y)
    return 0


class _CmpKey:
    __slots__ = ("v", "f")

    def __init__(self, v, f):
        self.v, self.f = v, f

    def __lt__(self, o):
        return self.f(self.v, o.v) < 0

    def __le__(self, o):
        return self.f(self.v, o.v) <= 0

    def __gt__(self, o):
        return self.f(self.v, o.v) > 0

    def __ge__(self, o):
        return self.f(self.v, o.v) >= 0

    def __eq__(self, o):
        return isinstance(o, _CmpKey) and self.f(self.v, o.v) == 0

    __hash__ = None


def _generic_key(version: str):
    """Lenient key for an unknown ecosystem. Anything after a hyphen is a prerelease, as in SemVer."""
    v = version.strip().lstrip("vV").split("+", 1)[0]
    m = re.match(r"\d+(?:\.\d+)*", v)
    if not m:
        return ((), ((0, 0, v.lower()),))
    nums = [int(x) for x in m.group(0).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    rest = v[m.end():]
    tail = []
    hyphen = rest.startswith("-")
    for t in re.findall(r"\d+|[A-Za-z]+", rest):
        low = t.lower()
        if t.isdigit():
            tail.append((1 if tail and tail[-1][0] == 2 else 0, int(t), ""))
        elif low in ("post", "rev", "sp", "final", "ga", "release", "pl") or (low == "patch" and not hyphen):
            tail.append((2, 0, low))
        else:
            tail.append((0, -1, {"dev": "0", "a": "1", "alpha": "1", "b": "2", "beta": "2", "c": "3", "rc": "3",
                                 "pre": "3", "preview": "3"}.get(low, "1" + low)))
    tail.append((1, 0, ""))
    return (tuple(nums), tuple(tail))


@functools.lru_cache(maxsize=200_000)
def vkey(version: str, eco: str | None = None):
    """Sort key for `version` under `eco`'s ordering rules. None when the string is not a version there."""
    if eco in SEMVER_ECOSYSTEMS:
        return _semver_key(version)
    if eco == "PyPI":
        return _pep440_key(version)
    if eco == "Packagist":
        return _CmpKey(_php_parts(version), _php_cmp_parts)
    if eco == "Maven":
        return _CmpKey(_maven_tokens(version), _maven_cmp)
    if eco == "RubyGems":
        return _CmpKey(_gem_segments(version), _gem_cmp)
    return _generic_key(version)


def is_prerelease(version: str, eco: str | None = None) -> bool:
    if eco in SEMVER_ECOSYSTEMS or eco is None:
        return "-" in version.split("+", 1)[0]
    if eco == "PyPI":
        m = _PEP440.match(version)
        return bool(m and (m.group("pre_l") or m.group("dev_l")))
    if eco == "RubyGems":
        return any(isinstance(s, str) for s in _gem_segments(version))
    return bool(re.search(r"(?i)(alpha|beta|milestone|snapshot|preview|dev|rc|cr|\bea|(?<![a-z])[abm])\d*\b",
                          version.split("+", 1)[0].lstrip("vV")))


def _range_affected(vk, events: list, eco) -> bool:
    """OSV schema evaluation: sort the events by version, then sweep."""
    zero, keyed = [], []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected"):
            val = ev.get(kind)
            if not isinstance(val, str):
                continue
            if kind == "introduced" and val == "0":
                zero.append(kind)
            else:
                k = vkey(val, eco)
                if k is not None:
                    keyed.append((k, kind))
    keyed.sort(key=lambda e: e[0])
    hit = bool(zero)
    for k, kind in keyed:
        if kind == "introduced" and vk >= k:
            hit = True
        elif kind == "fixed" and vk >= k:
            hit = False
        elif kind == "last_affected" and vk > k:
            hit = False
    return hit


def is_affected(version: str, affected: dict, eco: str | None = None) -> bool:
    listed = affected.get("versions") or []
    if version in listed or (version[:1] in ("v", "V") and version[1:] in listed):
        return True
    vk = vkey(version, eco)
    if vk is None:
        return False
    return any(_range_affected(vk, r.get("events") or [], eco) for r in affected.get("ranges") or []
               if isinstance(r, dict) and r.get("type") in ("SEMVER", "ECOSYSTEM"))


def fixed_versions(affected: dict) -> list:
    return [ev["fixed"] for r in affected.get("ranges", []) if r.get("type") in ("SEMVER", "ECOSYSTEM")
            for ev in r.get("events", []) if isinstance(ev, dict) and isinstance(ev.get("fixed"), str)]


def upgrade_target(eco: str, version: str, hits: dict, others: dict) -> tuple:
    """Pick the smallest published fix that clears every advisory in `hits`, checked against the ranges.

    hits / others: {advisory id: affected dict}. Returns (target or None, cleared ids, still-open ids at target,
    other advisories that affect the target). Stable releases win over prereleases; a target that is free of every
    known advisory for the package wins over one that only clears the current hits.
    """
    cur = vkey(version, eco)
    # Fix versions of the other advisories are candidates too: they are where a fix lands clear of everything.
    cands = {f for aff in list(hits.values()) + list(others.values()) for f in fixed_versions(aff)}
    cands = [c for c in cands if vkey(c, eco) is not None and (cur is None or vkey(c, eco) > cur)]
    cands.sort(key=lambda c: (is_prerelease(c, eco), vkey(c, eco)))
    best = None
    for c in cands:
        still = [vid for vid, aff in hits.items() if is_affected(c, aff, eco)]
        if still:
            if best is None or len(still) < len(best[2]):
                best = (c, sorted(set(hits) - set(still)), sorted(still), [])
            continue
        landed = sorted(vid for vid, aff in others.items() if is_affected(c, aff, eco))
        if not landed:
            return c, sorted(hits), [], []
        if best is None or best[2]:
            best = (c, sorted(hits), [], landed)
    if best and not best[2]:
        return best
    return (None, best[1], best[2], []) if best else (None, [], sorted(hits), [])


# ---------------------------------------------------------------- manifest parsing helpers

DEV_GROUP_WORDS = {"dev", "develop", "development", "test", "tests", "testing", "doc", "docs", "lint", "linting",
                   "typing", "types", "ci", "bench", "benchmark", "benchmarks", "coverage", "style", "format"}


PROD_GROUP_WORDS = {"prod", "production", "runtime", "server", "deploy", "main", "default"}


def _is_prod_group(name: str) -> bool:
    """PEP 735 dependency groups are never installed for a package's users, so only an explicit name makes one prod."""
    return bool(set(re.split(r"[-_.\s]+", name.lower())) & PROD_GROUP_WORDS)


def _is_dev_group(name: str) -> bool:
    words = set(re.split(r"[-_.\s]+", name.lower()))
    return bool(words & DEV_GROUP_WORDS) and "default" not in words and "main" not in words


def _read(full: str) -> str:
    try:
        raw = walker.read_regular(full, MAX_MANIFEST_BYTES)
    except walker.NotReadable as exc:
        raise LockfileError(f"could not be read safely ({exc})") from exc
    except OSError as exc:
        raise LockfileError(f"could not be read ({exc.strerror or exc})") from exc
    return raw.decode("utf-8", errors="replace").lstrip("﻿")


def _json(text: str):
    try:
        return json.loads(text)
    except ValueError as exc:
        raise LockfileError("is not valid JSON") from exc


def _sibling(root: str, rel: str, name: str) -> str | None:
    d = os.path.dirname(os.path.join(root, rel))
    p = os.path.join(d, name)
    try:
        return _read(p) if os.path.isfile(p) else None
    except LockfileError:
        return None


def _dict(x) -> dict:
    return x if isinstance(x, dict) else {}


def _pkgjson_direct(text: str | None):
    """(prod names, dev names) from a package.json, or None when unknown (missing, or a workspace root)."""
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("workspaces"):
        return None
    prod = set(_dict(data.get("dependencies"))) | set(_dict(data.get("optionalDependencies"))) \
        | set(_dict(data.get("peerDependencies")))
    return prod, set(_dict(data.get("devDependencies")))


def _direct_dev(name: str, direct_sets):
    """(direct, dev-only) for a name given (prod, dev) direct sets or None."""
    if direct_sets is None:
        return None, False
    prod, dev = direct_sets
    return (name in prod or name in dev), (name in dev and name not in prod)


def _reach(roots, graph: dict) -> set:
    seen, stack = set(), list(roots)
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(graph.get(n, ()))
    return seen


_NPM_VERSION = re.compile(r"^v?\d+(\.\d+)*([-+.][0-9A-Za-z.\-+]*)?$")


def _npm_alias(spec: str):
    """'npm:lodash@4.17.15' -> ('lodash', '4.17.15')."""
    m = re.match(r"^npm:((?:@[^/@]+/)?[^@]+)@(.+)$", spec)
    return (m.group(1), m.group(2)) if m else None


# ---------------------------------------------------------------- npm family

def _npm_lock(text: str, root: str, rel: str):
    data = _json(text)
    if not isinstance(data, dict):
        raise LockfileError("is not a lockfile object")
    pkgs = data.get("packages")
    if isinstance(pkgs, dict) and pkgs:
        declared_prod, declared_dev = set(), set()
        for key, meta in pkgs.items():
            if "node_modules/" not in key and isinstance(meta, dict):
                declared_prod |= set(_dict(meta.get("dependencies"))) | set(_dict(meta.get("optionalDependencies"))) \
                    | set(_dict(meta.get("peerDependencies")))
                declared_dev |= set(_dict(meta.get("devDependencies")))
        for key, meta in pkgs.items():
            if not key or "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
                continue
            installed_as = key.rsplit("node_modules/", 1)[-1]
            name = meta.get("name") if isinstance(meta.get("name"), str) else installed_as
            version = meta.get("version")
            if not isinstance(version, str):
                continue
            resolved = str(meta.get("resolved") or "")
            if resolved.startswith(("git", "file:", "github:")) or not _NPM_VERSION.match(version):
                yield name, version, False, None, "local"
                continue
            direct = key.count("node_modules/") == 1 and installed_as in (declared_prod | declared_dev)
            yield name, version, bool(meta.get("dev")), direct, "registry"
        return
    deps = data.get("dependencies")
    if "packages" in data and not isinstance(pkgs, dict):
        raise LockfileError("has a malformed packages section")
    if deps is None:
        return
    if not isinstance(deps, dict):
        raise LockfileError("has a malformed dependencies section")
    sets = _pkgjson_direct(_sibling(root, rel, "package.json"))
    stack = [(deps, True)]
    while stack:
        level, top = stack.pop()
        for name, meta in level.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                real = name
                alias = _npm_alias(version)
                if alias:
                    real, version = alias
                if not _NPM_VERSION.match(version):
                    yield real, version, False, None, "local"
                else:
                    direct = (name in sets[0] or name in sets[1]) if (sets is not None and top) else \
                        (False if sets is not None else None)
                    yield real, version, bool(meta.get("dev")), direct, "registry"
            if isinstance(meta.get("dependencies"), dict):
                stack.append((meta["dependencies"], False))


def _yarn_lock(text: str, root: str, rel: str):
    sets = _pkgjson_direct(_sibling(root, rel, "package.json"))
    entries, cur = [], None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            cur = {"head": line.rstrip().rstrip(":"), "fields": {}}
            entries.append(cur)
            continue
        if cur is None or line.startswith("    "):
            continue
        m = re.match(r'^  ("?)([\w.@\-]+)\1:?\s+"?([^"]*)"?\s*$', line)
        if m:
            cur["fields"][m.group(2)] = m.group(3)
    seen_any = bool(entries)
    for e in entries:
        f = e["fields"]
        version = f.get("version")
        head = e["head"]
        if head.startswith("__metadata") or not version:
            continue
        descriptors = [d.strip().strip('"') for d in head.split(",")]
        first = descriptors[0]
        alias_name = re.match(r"^((?:@[^/@]+/)?[^@]+)@", first)
        installed_as = alias_name.group(1) if alias_name else first
        real = installed_as
        m = re.search(r"@npm:((?:@[^/@]+/)?[^@]+)@", first)
        if m:
            real = m.group(1)
        resolution = f.get("resolution", "")
        rm = re.match(r"^((?:@[^/@]+/)?[^@]+)@(.+)$", resolution)
        if rm:
            real = rm.group(1)
            if not rm.group(2).startswith(("npm:", "patch:")):
                yield real, version, False, None, "local"  # workspace:, link:, portal:, git, url
                continue
        if f.get("linkType") == "soft" or str(f.get("resolved", "")).startswith(("git", "file:")) \
                or "codeload.github.com" in str(f.get("resolved", "")):
            yield real, version, False, None, "local"
            continue
        if not _NPM_VERSION.match(version):
            yield real, version, False, None, "local"
            continue
        direct, dev = _direct_dev(installed_as, sets)
        if sets is not None and not direct:
            direct = False
        yield real, version, dev, direct, "registry"
    if not seen_any and text.strip() and not text.lstrip().startswith("#"):
        raise LockfileError("has no package entries")


def _mini_yaml(text: str) -> dict:
    """Block-mapping subset of YAML, enough for pnpm lockfiles. Lines it does not understand are skipped."""
    root: dict = {}
    stack = [(-1, root)]
    key_re = re.compile(r"""^(\s*)(?:'((?:[^']|'')*)'|"((?:[^"\\]|\\.)*)"|([^\s'"#][^#]*?)):(?:\s+(.*?))?\s*$""")
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith(("#", "- ", "---")):
            continue
        m = key_re.match(raw)
        if not m:
            continue
        indent = len(m.group(1).replace("\t", "  "))
        key = m.group(2).replace("''", "'") if m.group(2) is not None else (
            m.group(3) if m.group(3) is not None else m.group(4).strip())
        val = m.group(5)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            stack = [(-1, root)]
        parent = stack[-1][1]
        if val is None or val == "":
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                val = val[1:-1]
            parent[key] = val
    return root


_PNPM_V5 = re.compile(r"^/?((?:@[^/]+/)?[^@/]+)/(\d[^_(/]*)")
_PNPM_AT = re.compile(r"^/?((?:@[^/@]+/)?[^@/]+)@([^(]+)")


def _pnpm_key(key: str):
    m = _PNPM_AT.match(key) or _PNPM_V5.match(key)
    if not m:
        return None
    return m.group(1), m.group(2).strip()


def _pnpm_ref(name: str, ref) -> str | None:
    """Node id 'name@version' for an importer or snapshot dependency value."""
    if isinstance(ref, dict):
        ref = ref.get("version")
    if not isinstance(ref, str) or ref.startswith(("link:", "file:", "workspace:")):
        return None
    ref = ref.split("(", 1)[0].lstrip("/")
    if ref[:1].isdigit():
        return f"{name}@{ref.split('_', 1)[0]}"
    parsed = _pnpm_key(ref)
    return f"{parsed[0]}@{parsed[1]}" if parsed else None


def _pnpm(text: str, root: str, rel: str):
    doc = _mini_yaml(text)
    if not doc or "lockfileVersion" not in doc:
        raise LockfileError("has no lockfileVersion")
    importers = _dict(doc.get("importers")) or {".": doc}
    prod_roots, dev_roots = set(), set()
    for imp in importers.values():
        imp = _dict(imp)
        for section, bucket in (("dependencies", prod_roots), ("optionalDependencies", prod_roots),
                                ("devDependencies", dev_roots)):
            for name, ref in _dict(imp.get(section)).items():
                node = _pnpm_ref(name, ref)
                if node:
                    bucket.add(node)
    packages = _dict(doc.get("packages"))
    graph_src = _dict(doc.get("snapshots")) or packages
    graph: dict = {}
    for key, meta in graph_src.items():
        parsed = _pnpm_key(key)
        if not parsed:
            continue
        node = f"{parsed[0]}@{parsed[1].split('_', 1)[0]}"
        meta = _dict(meta)
        for section in ("dependencies", "optionalDependencies"):
            for n, ref in _dict(meta.get(section)).items():
                child = _pnpm_ref(n, ref)
                if child:
                    graph.setdefault(node, set()).add(child)
    prod = _reach(prod_roots, graph)
    every = _reach(prod_roots | dev_roots, graph)
    seen = set()
    for key, meta in packages.items():
        parsed = _pnpm_key(key)
        if not parsed:
            yield key.split("@", 1)[0].lstrip("/") or key, "", False, None, "local"
            continue
        name, version = parsed[0], parsed[1].split("_", 1)[0]
        node = f"{name}@{version}"
        if node in seen:
            continue
        seen.add(node)
        meta = _dict(meta)
        resolution = str(meta.get("resolution", ""))
        if not _NPM_VERSION.match(version) or "tarball:" in resolution or "repo:" in resolution:
            yield name, version, False, None, "local"
            continue
        if "dev" in meta:
            dev = str(meta.get("dev")).lower() == "true"
        else:
            dev = node in every and node not in prod
        yield name, version, dev, node in prod_roots or node in dev_roots, "registry"


def _jsonc(text: str):
    """JSON with comments and trailing commas (bun.lock)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return _json(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))


def _bun(text: str, root: str, rel: str):
    data = _jsonc(text)
    if not isinstance(data, dict) or not isinstance(data.get("packages", {}), dict):
        raise LockfileError("is not a bun lockfile object")
    packages = data.get("packages") or {}
    prod_roots, dev_roots = set(), set()
    for ws in _dict(data.get("workspaces")).values():
        ws = _dict(ws)
        prod_roots |= set(_dict(ws.get("dependencies"))) | set(_dict(ws.get("optionalDependencies"))) \
            | set(_dict(ws.get("peerDependencies")))
        dev_roots |= set(_dict(ws.get("devDependencies")))
    graph = {}
    for key, val in packages.items():
        if isinstance(val, list) and len(val) > 2 and isinstance(val[2], dict):
            graph[key] = set(_dict(val[2].get("dependencies"))) | set(_dict(val[2].get("optionalDependencies")))
    prod = _reach(prod_roots, graph)
    every = _reach(prod_roots | dev_roots, graph)
    for key, val in packages.items():
        if not isinstance(val, list) or not val or not isinstance(val[0], str):
            continue
        m = re.match(r"^((?:@[^/@]+/)?[^@]+)@(.+)$", val[0])
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        if not _NPM_VERSION.match(version):
            yield name, version, False, None, "local"
            continue
        nested = key.count("/") > (1 if key.startswith("@") else 0)  # "parent/child" is a nested copy
        dev = key in every and key not in prod
        yield name, version, dev, (not nested and (key in prod_roots or key in dev_roots)), "registry"


# ---------------------------------------------------------------- Python

def _pyproject_direct(text: str | None):
    """(prod names, dev names) from a sibling pyproject.toml or Pipfile, normalised. None when absent."""
    if text is None:
        return None
    prod, dev = set(), set()
    section = ""
    for line in text.splitlines():
        s = line.strip()
        h = re.match(r"^\[\[?([^\]]+)\]\]?$", s)
        if h:
            section = h.group(1).strip().replace('"', "")
            continue
        if not s or s.startswith("#"):
            continue
        key = re.match(r"^([A-Za-z0-9_.\-]+)\s*=", s)
        if section in ("tool.poetry.dependencies", "packages") and key and key.group(1) != "python":
            prod.add(key.group(1))
        elif (section in ("tool.poetry.dev-dependencies", "dev-packages")
              or re.match(r"^tool\.poetry\.group\.(.+)\.dependencies$", section)) and key:
            grp = re.match(r"^tool\.poetry\.group\.(.+)\.dependencies$", section)
            (dev if not grp or _is_dev_group(grp.group(1)) else prod).add(key.group(1))
    for m in re.finditer(r"(?ms)^dependencies\s*=\s*\[(.*?)\]", text):
        prod |= {re.match(r"[A-Za-z0-9_.\-]+", x).group(0) for x in re.findall(r"[\"']([A-Za-z0-9][^\"']*)[\"']",
                                                                             m.group(1))}
    for m in re.finditer(r"(?ms)^\[dependency-groups\](.*?)(?=^\[|\Z)", text):
        for g in re.finditer(r"(?ms)^([A-Za-z0-9_.\-]+)\s*=\s*\[(.*?)\]", m.group(1)):
            names = {re.match(r"[A-Za-z0-9_.\-]+", x).group(0) for x in
                     re.findall(r"[\"']([A-Za-z0-9][^\"']*)[\"']", g.group(2))}
            (dev if _is_dev_group(g.group(1)) else prod).update(names)
    norm = functools.partial(normalize, "PyPI")
    return {norm(n) for n in prod}, {norm(n) for n in dev}


def _toml_value(raw: str):
    raw = raw.strip()
    if raw[:1] in "\"'":
        q = raw[0]
        end = raw.find(q, 1)
        return raw[1:end] if end > 0 else raw[1:]
    if raw.startswith("["):
        return re.findall(r"[\"']([^\"']*)[\"']", raw)
    return raw.split("#", 1)[0].strip()


def _toml_packages(text: str) -> list:
    """[[package]] blocks of poetry.lock, pdm.lock, uv.lock and Cargo.lock as dicts of raw fields."""
    out = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        fields, sections, current = {}, {}, None
        lines = block.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            h = re.match(r"^\s*\[\[?([^\]]+)\]\]?\s*$", line)
            if h:
                current = h.group(1).strip()
                if not current.startswith("package."):
                    break  # [metadata] and friends end the package
                sections.setdefault(current, [])
                i += 1
                continue
            m = re.match(r"^\s*([A-Za-z0-9_\-\"'.]+)\s*=\s*(.*)$", line)
            if m:
                key, raw = m.group(1).strip("\"'"), m.group(2)
                depth = raw.count("[") - raw.count("]") + raw.count("{") - raw.count("}")
                while depth > 0 and i + 1 < len(lines):
                    i += 1
                    raw += "\n" + lines[i]
                    depth += lines[i].count("[") - lines[i].count("]") + lines[i].count("{") - lines[i].count("}")
                if current is None:
                    fields[key] = raw
                else:
                    sections[current].append((key, raw))
            i += 1
        fields["_sections"] = sections
        out.append(fields)
    return out


def _names_in(raw: str) -> set:
    """Package names in a uv dependency list such as [{ name = "click", marker = "..." }]."""
    return set(re.findall(r"name\s*=\s*\"([^\"]+)\"", raw))


def _python_lock(text: str, root: str, rel: str):
    base = rel.rsplit("/", 1)[-1]
    blocks = _toml_packages(text)
    if not blocks and "[[package]]" not in text and text.strip() and "[metadata]" not in text and "version" not in text:
        raise LockfileError("has no [[package]] entries")
    sets = _pyproject_direct(_sibling(root, rel, "pyproject.toml")) if base != "uv.lock" else None
    norm = functools.partial(normalize, "PyPI")
    graph, prod_roots, dev_roots = {}, set(), set()
    if base == "uv.lock":
        for b in blocks:
            src = str(b.get("source", ""))
            name = norm(str(_toml_value(b.get("name", '""'))))
            deps = set()
            for key in ("dependencies", "optional-dependencies"):
                if key in b:
                    deps |= {norm(n) for n in _names_in(b[key])}
            for sec, items in b["_sections"].items():
                if sec == "package.dependencies":  # older uv: [[package.dependencies]] name = "x"
                    deps |= {norm(str(_toml_value(raw))) for key, raw in items if key == "name"}
                elif sec == "package.optional-dependencies":
                    deps |= {norm(n) for _, raw in items for n in _names_in(raw)}
            graph[name] = deps
            if "virtual" in src or "editable" in src:
                prod_roots |= deps
                for sec, items in b["_sections"].items():
                    if sec in ("package.dev-dependencies", "package.dependency-groups"):
                        for grp, raw in items:
                            names = {norm(n) for n in re.findall(r"name\s*=\s*\"([^\"]+)\"", raw)}
                            (prod_roots if _is_prod_group(grp) else dev_roots).update(names)
                    elif sec == "package.optional-dependencies":
                        prod_roots |= {norm(n) for _, raw in items for n in re.findall(r"name\s*=\s*\"([^\"]+)\"",
                                                                                         raw)}
        prod = _reach(prod_roots, graph)
        every = _reach(prod_roots | dev_roots, graph)
    for b in blocks:
        name, version = _toml_value(b.get("name", '""')), _toml_value(b.get("version", '""'))
        if not isinstance(name, str) or not name:
            continue
        src = str(b.get("source", "")) + " " + " ".join(sec for sec in b["_sections"])
        if base == "uv.lock":
            if "virtual" in src or "editable" in src or re.search(r"\b(git|path|directory|url)\s*=", src):
                yield name, version or "", False, None, "local"
                continue
            n = norm(name)
            dev = bool(prod_roots | dev_roots) and n in every and n not in prod
            yield name, version, dev, (n in prod_roots or n in dev_roots) if (prod_roots or dev_roots) else None, \
                "registry"
            continue
        if "package.source" in b["_sections"] and any(k == "type" and _toml_value(v) in ("git", "directory", "file",
                                                                                         "url")
                                                      for k, v in b["_sections"]["package.source"]):
            yield name, version, False, None, "local"
            continue
        if any(k in b for k in ("git", "path", "url", "revision")):
            yield name, version, False, None, "local"
            continue
        groups = _toml_value(b["groups"]) if "groups" in b else None
        category = _toml_value(b["category"]) if "category" in b else None
        if isinstance(groups, list) and groups:
            dev = all(_is_dev_group(g) for g in groups)
        elif isinstance(category, str):
            dev = category != "main"
        else:
            dev = False
        direct = None
        if sets is not None:
            direct = norm(name) in sets[0] or norm(name) in sets[1]
        yield name, version, dev, direct, "registry"


def _pipfile_lock(text: str, root: str, rel: str):
    data = _json(text)
    if not isinstance(data, dict):
        raise LockfileError("is not a Pipfile.lock object")
    sets = _pyproject_direct(_sibling(root, rel, "Pipfile"))
    default = _dict(data.get("default"))
    for section in ("default", "develop"):
        for name, meta in _dict(data.get(section)).items():
            meta = _dict(meta)
            if section == "develop" and name in default:
                continue
            ver = meta.get("version")
            direct = (normalize("PyPI", name) in sets[0] | sets[1]) if sets is not None else None
            if isinstance(ver, str) and ver.startswith("=="):
                yield name, ver.lstrip("="), section == "develop", direct, "registry"
            elif any(k in meta for k in ("git", "path", "file", "editable")):
                yield name, "", False, direct, "local"
            else:
                yield name, "", section == "develop", direct, "unpinned"


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _is_requirements_file(rel: str) -> bool:
    parts = rel.lower().split("/")
    base = parts[-1]
    if not base.endswith(".txt"):
        return False
    return base.startswith("requirements") or base.endswith(("-requirements.txt", "_requirements.txt")) or (
        len(parts) > 1 and parts[-2] in ("requirements", "requirements.d", "reqs"))


def _requirements_dev(rel: str) -> bool:
    stem = rel.lower().rsplit(".", 1)[0]
    return _is_dev_group(stem.replace("/", "-").replace("requirements", ""))


def _requirements(root: str, rel: str, out: list, problems: list):
    """Follow -r / -c includes inside the project, bounded and cycle-safe. Appends Package entries."""
    root_real = os.path.realpath(root)
    pins, unpinned, constraints = [], [], {}
    seen: set = set()
    dev = _requirements_dev(rel)

    def visit(path_rel: str, depth: int, constraint: bool):
        full = os.path.realpath(os.path.join(root, path_rel))
        if full in seen or len(seen) >= MAX_REQUIREMENT_FILES or depth > MAX_INCLUDE_DEPTH:
            return
        if not (full == root_real or full.startswith(root_real + os.sep)):
            problems.append(f"{rel} includes {path_rel}, which is outside the project, so it was not read.")
            return
        seen.add(full)
        try:
            text = _read(full)
        except LockfileError as exc:
            problems.append(f"{path_rel} {exc}, so its Python requirements were not checked.")
            return
        here = os.path.dirname(path_rel)
        for line in re.sub(r"\\\r?\n", " ", text).splitlines():
            line = line.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            inc = re.match(r"^(-r|--requirement|-c|--constraint)[=\s]+(\S+)", line)
            if inc:
                target = os.path.normpath(os.path.join(here, inc.group(2))).replace(os.sep, "/")
                visit(target, depth + 1, constraint or inc.group(1) in ("-c", "--constraint"))
                continue
            if line.startswith("-e") or line.startswith("--editable"):
                egg = re.search(r"#egg=([A-Za-z0-9_.\-]+)", line)
                if egg and not constraint:
                    out.append(Package("PyPI", egg.group(1), "", path_rel, dev, None, "local"))
                continue
            if line.startswith("-") or re.match(r"^[a-z]+\+?[a-z]*://", line) or line.startswith((".", "/")):
                continue
            m = _REQ_LINE.match(line)
            if not m:
                continue
            name, spec = m.group(1), re.split(r"\s--?[a-z]", " " + m.group(3).split(";", 1)[0])[0].strip()
            pin = re.match(r"^(===|==)\s*([^\s,;*]+)\s*$", spec)
            if spec.startswith("@"):
                if not constraint:
                    out.append(Package("PyPI", name, "", path_rel, dev, None, "local"))
            elif pin:
                (constraints.__setitem__(normalize("PyPI", name), (pin.group(2), path_rel)) if constraint
                 else pins.append(Package("PyPI", name, pin.group(2), path_rel, dev, None)))
            elif not constraint:
                unpinned.append((name, path_rel))

    visit(rel, 0, False)
    out.extend(pins)
    pinned_names = {normalize("PyPI", p.name) for p in pins}
    for name, where in unpinned:
        n = normalize("PyPI", name)
        if n in pinned_names:
            continue
        if n in constraints:
            out.append(Package("PyPI", name, constraints[n][0], constraints[n][1], dev, None))
        else:
            out.append(Package("PyPI", name, "", where, dev, None, "unpinned"))


# ---------------------------------------------------------------- Go, Rust, Ruby, PHP

def _gomod_directives(text: str):
    """Yield (verb, fields, comment) for each require/replace/exclude line, block or single."""
    block = None
    for line in text.splitlines():
        code, _, comment = line.partition("//")
        code = code.strip()
        if block:
            if code == ")":
                block = None
                continue
            if code:
                yield block, code.split(), comment.strip()
            continue
        m = re.match(r"^(require|replace|exclude|retract)\s*(\(?)\s*(.*)$", code)
        if not m:
            continue
        if m.group(2) == "(" and not m.group(3):
            block = m.group(1)
        elif m.group(3):
            yield m.group(1), m.group(3).split(), comment.strip()


def _gomod(text: str, root: str, rel: str):
    requires, excluded, replace = {}, set(), {}
    go_version = re.search(r"(?m)^go\s+(\d+)\.(\d+)", text)
    for verb, f, comment in _gomod_directives(text):
        if verb == "require" and len(f) >= 2:
            requires[f[0]] = (f[1], "indirect" not in comment)
        elif verb == "exclude" and len(f) >= 2:
            excluded.add((f[0], f[1]))
        elif verb == "replace" and "=>" in f:
            i = f.index("=>")
            left, right = f[:i], f[i + 1:]
            if left and right:
                replace[(left[0], left[1] if len(left) > 1 else None)] = (right[0], right[1] if len(right) > 1 else None)
    for mod, (ver, direct) in requires.items():
        if (mod, ver) in excluded:
            continue
        target = replace.get((mod, ver)) or replace.get((mod, None))
        if target:
            new_mod, new_ver = target
            if new_ver is None:  # replaced by a local directory
                yield mod, ver, False, direct, "local"
                continue
            mod, ver = new_mod, new_ver
        yield mod, ver, False, direct, "registry"
    if go_version is None or (int(go_version.group(1)), int(go_version.group(2))) < (1, 17):
        # Before Go 1.17, go.mod listed only direct requirements; go.sum knows the rest.
        listed = set(requires) | {r[0] for r in replace}
        gosum = _sibling(root, rel, "go.sum")
        if gosum:
            for name, ver, _, _, src in _gosum(gosum, root, rel):
                if name not in listed:
                    yield name, ver, False, False, src


def _gosum(text: str, root: str, rel: str):
    best = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 3 or f[1].endswith("/go.mod"):
            continue
        k = vkey(f[1], "Go")
        if k is not None and (f[0] not in best or k > vkey(best[f[0]], "Go")):
            best[f[0]] = f[1]
    for name, ver in best.items():
        yield name, ver, False, None, "registry"


def _cargo_lock(text: str, root: str, rel: str):
    blocks = _toml_packages(text)
    real = any("source" in b for b in blocks)  # cargo writes `source` for every registry crate
    direct_names = set()
    for b in blocks:
        if "source" not in b and "dependencies" in b:
            direct_names |= {d.split()[0] for d in _toml_value(b["dependencies"]) or []}
    for b in blocks:
        name, version = _toml_value(b.get("name", '""')), _toml_value(b.get("version", '""'))
        if not name:
            continue
        src = _toml_value(b["source"]) if "source" in b else ("" if real else "registry+")
        if not isinstance(src, str) or not src.startswith(("registry+", "sparse+")):
            yield name, version, False, None, "local"
            continue
        yield name, version, False, name in direct_names if direct_names else None, "registry"


def _gemfile_lock(text: str, root: str, rel: str):
    section, specs, direct = None, [], set()
    in_specs = False
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section, in_specs = line.strip(), False
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if section == "DEPENDENCIES":
            m = re.match(r"^  ([A-Za-z0-9_.\-]+)", line)
            if m:
                direct.add(m.group(1))
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([\w.\-]+)\)$", line)
        if m and in_specs:
            specs.append((m.group(1), m.group(2), section))
    for name, ver, sec in specs:
        yield name, ver, False, (name in direct) if direct else None, "registry" if sec == "GEM" else "local"


def _composer_lock(text: str, root: str, rel: str):
    data = _json(text)
    if not isinstance(data, dict):
        raise LockfileError("is not a composer lockfile object")
    req, req_dev = set(), set()
    cj = _sibling(root, rel, "composer.json")
    if cj:
        try:
            j = json.loads(cj)
            req, req_dev = set(_dict(j.get("require"))), set(_dict(j.get("require-dev")))
        except (ValueError, AttributeError):
            pass
    for section, dev in (("packages", False), ("packages-dev", True)):
        items = data.get(section)
        if items is None:
            continue
        if not isinstance(items, list):
            raise LockfileError(f"has a malformed {section} section")
        for p in items:
            if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("version"), str):
                continue
            ver = p["version"]
            ver = ver[1:] if ver[:1] in "vV" and ver[1:2].isdigit() else ver
            direct = (p["name"] in req or p["name"] in req_dev) if (req or req_dev) else None
            yield p["name"], ver, dev, direct, "registry"


# ---------------------------------------------------------------- Java

def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_child(el, name):
    if el is None:
        return None
    return next((c for c in el if _xml_local(c.tag) == name), None)


def _xml_text(el, name) -> str:
    c = _xml_child(el, name)
    return (c.text or "").strip() if c is not None else ""


def _load_pom(full: str):
    text = _read(full)
    if "<!ENTITY" in text:
        raise LockfileError("declares XML entities, which hardn does not expand")
    try:
        return ElementTree.fromstring(text.encode("utf-8"))
    except ElementTree.ParseError as exc:
        raise LockfileError(f"is not valid XML ({exc})") from exc


def _pom(root: str, rel: str, problems: list):
    """Direct dependencies of a pom.xml with ${property} and dependencyManagement resolution via parents."""
    chain, path, seen = [], os.path.join(root, rel), set()
    root_real = os.path.realpath(root)
    while path and len(chain) < 10:
        real = os.path.realpath(path)
        if real in seen or not real.startswith(root_real) or not os.path.isfile(real):
            break
        seen.add(real)
        try:
            el = _load_pom(real)
        except LockfileError:
            if not chain:
                raise
            break
        chain.append(el)
        parent = _xml_child(el, "parent")
        if parent is None:
            break
        relp = _xml_text(parent, "relativePath") or "../pom.xml"
        cand = os.path.join(os.path.dirname(real), relp)
        path = os.path.join(cand, "pom.xml") if os.path.isdir(cand) else cand
    project = chain[0]
    props: dict = {}
    for el in reversed(chain):  # child values override parents
        for p in _xml_child(el, "properties") or []:
            props[_xml_local(p.tag)] = (p.text or "").strip()
        for key in ("version", "groupId", "artifactId"):
            if _xml_text(el, key):
                props[f"project.{key}"] = props[key] = _xml_text(el, key)
        parent = _xml_child(el, "parent")
        if parent is not None:
            for key in ("version", "groupId"):
                if _xml_text(parent, key):
                    props.setdefault(f"project.{key}", _xml_text(parent, key))
                    props[f"project.parent.{key}"] = _xml_text(parent, key)

    def resolve(s: str) -> str:
        for _ in range(10):
            new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), s)
            if new == s:
                break
            s = new
        return s

    managed = {}
    for el in reversed(chain):
        dm = _xml_child(_xml_child(el, "dependencyManagement"), "dependencies")
        for d in dm if dm is not None else []:
            ga = (resolve(_xml_text(d, "groupId")), resolve(_xml_text(d, "artifactId")))
            if _xml_text(d, "scope") == "import":
                continue
            managed[ga] = (resolve(_xml_text(d, "version")), _xml_text(d, "scope"))
    imports = [d for el in chain for d in (_xml_child(_xml_child(el, "dependencyManagement"), "dependencies") or [])
               if _xml_text(d, "scope") == "import"]
    deps = _xml_child(project, "dependencies")
    unresolved = []
    for d in deps if deps is not None else []:
        g, a = resolve(_xml_text(d, "groupId")), resolve(_xml_text(d, "artifactId"))
        if not g or not a:
            continue
        ver = resolve(_xml_text(d, "version"))
        scope = _xml_text(d, "scope") or (managed.get((g, a)) or ("", ""))[1]
        if not ver:
            ver = (managed.get((g, a)) or ("", ""))[0]
        name = f"{g}:{a}"
        if not ver or "${" in ver or ver[:1] in "[(" or "," in ver:
            unresolved.append(name)
            yield name, "", scope == "test", True, "unpinned"
            continue
        yield name, ver, scope == "test", True, "registry"
    if unresolved and imports:
        problems.append(f"{rel} imports a BOM, which hardn cannot read offline, so {len(unresolved)} Maven "
                        f"dependencies have no known version ({', '.join(unresolved[:3])}).")


_GRADLE_DEV = re.compile(r"(?i)^test|test(compile|runtime|annotation|implementation|fixtures)|^androidTest|^unitTest")


def _gradle_lock(text: str, root: str, rel: str):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coords, _, confs = line.partition("=")
        parts = coords.split(":")
        if len(parts) < 3:
            continue
        configs = [c for c in confs.split(",") if c]
        dev = bool(configs) and all(_GRADLE_DEV.search(c) for c in configs)
        yield f"{parts[0]}:{parts[1]}", parts[2], dev, None, "registry"


# ---------------------------------------------------------------- collection

_LOCKFILES = {
    "package-lock.json": ("npm", _npm_lock), "npm-shrinkwrap.json": ("npm", _npm_lock),
    "yarn.lock": ("npm", _yarn_lock), "pnpm-lock.yaml": ("npm", _pnpm), "bun.lock": ("npm", _bun),
    "poetry.lock": ("PyPI", _python_lock), "pdm.lock": ("PyPI", _python_lock), "uv.lock": ("PyPI", _python_lock),
    "Pipfile.lock": ("PyPI", _pipfile_lock), "Cargo.lock": ("crates.io", _cargo_lock),
    "go.mod": ("Go", _gomod), "Gemfile.lock": ("RubyGems", _gemfile_lock), "gems.locked": ("RubyGems", _gemfile_lock),
    "composer.lock": ("Packagist", _composer_lock), "gradle.lockfile": ("Maven", _gradle_lock),
    "buildscript-gradle.lockfile": ("Maven", _gradle_lock),
}


def _collect(root: str, all_paths: list) -> tuple:
    """(packages, problems, manifests read). Packages with an empty name or version could not be checked."""
    found, problems, files = [], [], []
    dirs_with = {}
    for rel in all_paths:
        d, _, base = rel.rpartition("/")
        dirs_with.setdefault(d, set()).add(base)
    for rel in all_paths:
        d, _, base = rel.rpartition("/")
        entry = _LOCKFILES.get(base)
        if entry is None and rel.endswith(".lockfile") and "/dependency-locks/" in f"/{rel}":
            entry = ("Maven", _gradle_lock)
        eco = entry[0] if entry else None
        before = len(found)
        try:
            if entry:
                text = _read(os.path.join(root, rel))
                for name, version, dev, direct, source in entry[1](text, root, rel):
                    found.append(Package(eco, name, version if source != "unpinned" else "", rel, bool(dev),
                                         direct, source))
            elif base == "go.sum" and "go.mod" not in dirs_with.get(d, ()):
                eco = "Go"
                for name, version, dev, direct, source in _gosum(_read(os.path.join(root, rel)), root, rel):
                    found.append(Package("Go", name, version, rel, False, None, source))
            elif base == "bun.lockb" and "bun.lock" not in dirs_with.get(d, ()):
                eco = "npm"
                raise LockfileError("is in bun's binary format. Run `bun install --save-text-lockfile` to write bun.lock")
            elif base == "pom.xml" and not ({"gradle.lockfile"} & dirs_with.get(d, set())):
                eco = "Maven"
                for name, version, dev, direct, source in _pom(root, rel, problems):
                    found.append(Package("Maven", name, version, rel, bool(dev), direct, source))
            elif base == "requirements.in" and "requirements.txt" in dirs_with.get(d, ()):
                continue
            elif _is_requirements_file(rel) or base == "requirements.in":
                eco = "PyPI"
                _requirements(root, rel, found, problems)
        except LockfileError as exc:
            problems.append(f"{rel} {exc}, so its {eco} dependencies were not checked.")
            found.append(Package(eco, "", "", rel, False, None, "unreadable"))
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError) as exc:
            problems.append(f"{rel} could not be parsed ({type(exc).__name__}), so its {eco} dependencies were "
                            "not checked.")
            found.append(Package(eco, "", "", rel, False, None, "unreadable"))
        if eco and (len(found) > before or entry or base in ("go.sum", "pom.xml")):
            files.append(rel)
    poms = sorted({p.path for p in found if p.eco == "Maven" and p.path.endswith("pom.xml") and p.name})
    if poms:
        problems.append(f"{', '.join(poms[:3])} {'lists' if len(poms) == 1 else 'list'} only direct Maven "
                        "dependencies, so the transitive ones were not checked. Enable Gradle dependency locking "
                        "or check `mvn dependency:tree` output by hand.")
    return found, problems, files


def collect_packages(root: str, all_paths: list) -> list:
    """Every dependency entry: Package(eco, name, version, path, dev, direct, source).

    Entries with an empty version are unpinned or unreadable. They still name the ecosystem, so
    `hardn update --for` downloads data for every ecosystem the project uses.
    """
    return _collect(root, all_paths)[0]


def _merge(pkgs: list) -> list:
    """One entry per (ecosystem, name, version): runtime wins over dev, direct wins over transitive."""
    out: dict = {}
    for p in pkgs:
        key = (p.eco, normalize(p.eco, p.name), p.version)
        cur = out.get(key)
        if cur is None:
            out[key] = [p, []]
            continue
        base, also = cur
        direct = True if (p.direct or base.direct) else (None if p.direct is None or base.direct is None else False)
        if base.dev and not p.dev:
            base, also = p, also + [base.path]
        elif p.path != base.path:
            also.append(p.path)
        out[key] = [base._replace(dev=base.dev and p.dev, direct=direct), also]
    return [(p, sorted(set(a) - {p.path})) for p, a in out.values()]


# ---------------------------------------------------------------- scan (offline)

def _eco_list(ecos) -> str:
    ecos = sorted(ecos)
    return ecos[0] if len(ecos) == 1 else ", ".join(ecos[:-1]) + " and " + ecos[-1]


def _clusters(ids: list, aliases: dict) -> int:
    """Number of distinct issues once advisories that alias each other are merged."""
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for vid in ids:
        for a in aliases.get(vid, []):
            parent[find(a)] = find(vid)
    return len({find(v) for v in ids})


def scan(root: str, all_paths: list, db: Path | None = None):
    """Match lockfile entries against the local advisory DB. Returns (findings, note, gaps)."""
    raw, gaps, files = _collect(root, all_paths)
    merged = _merge([p for p in raw if p.name and p.version and p.source == "registry"])
    unpinned = [p for p in raw if p.source == "unpinned" and p.name]
    local = [p for p in raw if p.source == "local"]
    pinned_names = {(p.eco, normalize(p.eco, p.name)) for p, _ in merged}
    unpinned = [p for p in unpinned if (p.eco, normalize(p.eco, p.name)) not in pinned_names]
    if unpinned:
        by_eco: dict = {}
        for p in unpinned:
            by_eco.setdefault(p.eco, []).append(p)
        for eco, items in sorted(by_eco.items()):
            names = sorted({p.name for p in items})
            files = sorted({p.path for p in items})
            gaps.append(f"{len(names)} {eco} requirement{'s' if len(names) != 1 else ''} in {', '.join(files[:3])} "
                        f"{'have' if len(names) != 1 else 'has'} no pinned version ({', '.join(names[:5])}"
                        f"{', ...' if len(names) > 5 else ''}), so hardn cannot tell which release is installed. "
                        "Pin exact versions or commit a lockfile.")
    extras = []
    if unpinned:
        extras.append(f"{len(unpinned)} unpinned")
    if local:
        extras.append(f"{len(local)} from git, URLs or local paths not matched")
    tail = (" · " + " · ".join(extras)) if extras else ""
    if not merged:
        if not raw:
            if files:
                return [], f"{len(files)} lockfile{'s' if len(files) != 1 else ''} read, no dependencies listed", gaps
            return [], "no lockfiles found", gaps
        return [], "no pinned packages could be read" + tail, gaps

    used = sorted({p.eco for p, _ in merged})
    st = status(db)
    if st.get("error"):
        gaps.append(f"{len(merged)} {_eco_list(used)} packages were not checked. {st['error']}")
        return [], f"{len(merged)} packages found, advisory DB unusable — run `hardn update`" + tail, gaps
    if not st["present"]:
        gaps.append(f"There is no advisory data, so {len(merged)} {_eco_list(used)} packages were not checked "
                    "for known vulnerabilities. Run `hardn update`.")
        return [], f"{len(merged)} packages found, no advisory DB — run `hardn update`" + tail, gaps
    covered = set(st["ecosystems"])
    missing = [e for e in used if e not in covered]
    for eco in missing:
        n = sum(1 for p, _ in merged if p.eco == eco)
        gaps.append(f"The advisory database has no {eco} data, so {n} {eco} package{'s' if n != 1 else ''} "
                    f"{'were' if n != 1 else 'was'} not checked. Run `hardn update` "
                    f"(or `hardn update --ecosystems {eco}`).")
    ages = st.get("eco_age_days") or {}
    checked_ecos = [e for e in used if e in covered]
    stale = [e for e in checked_ecos if ages.get(e) is None or ages[e] > STALE_DAYS]
    if stale:
        known = [ages[e] for e in stale if ages.get(e) is not None]
        age = f"{max(known):.0f} days old" if known else "of unknown age"
        gaps.append(f"The {_eco_list(stale)} advisory data is {age}, past the {STALE_DAYS}-day limit, so newer "
                    "advisories were not checked. Run `hardn update`.")
    if st.get("legacy"):
        gaps.append("The advisory database was written by an older hardn, so severities may be understated. "
                    "Run `hardn update`.")
    try:
        con = _connect(db, create=False)
    except AdvisoryDbError as exc:
        gaps.append(f"{len(merged)} packages were not checked. {exc}")
        return [], f"{len(merged)} packages found, advisory DB unusable" + tail, gaps
    findings = []
    try:
        kev = {r[0] for r in con.execute("SELECT cve FROM kev")}
        if not kev:
            gaps.append("The CISA known-exploited list is missing, so actively exploited packages are not raised "
                        "to critical. Run `hardn update`.")
        for p, also in merged:
            if p.eco not in covered:
                continue
            try:
                f = _match(con, p, also, kev)
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                gaps.append(f"{p.name}@{p.version} in {p.path} could not be compared with its advisories "
                            f"({type(exc).__name__}), so it was not checked.")
                continue
            if f:
                findings.append(f)
    except (sqlite3.Error, ValueError, TypeError) as exc:
        gaps.append(f"Reading the advisory database failed ({exc}), so the dependency results are incomplete. "
                    "Run `hardn update`.")
    finally:
        con.close()
    n_checked = sum(1 for p, _ in merged if p.eco in covered)
    if missing:
        note = f"{n_checked} of {len(merged)} packages had advisory data; no {_eco_list(missing)} data"
    else:
        note = f"{n_checked} packages checked"
    age = st.get("age_days")
    if age is not None and age > WARN_DAYS:
        note += f" · advisories {age:.0f}d old — run `hardn update`"
    return findings, note + tail, gaps


def _match(con: sqlite3.Connection, p: Package, also: list, kev: set):
    eco, name, version = p.eco, p.name, p.version
    rows = con.execute("SELECT id, summary, severity, aliases, affected FROM vulns WHERE eco=? AND name=?",
                       (eco, normalize(eco, name))).fetchall()
    hits, others, info, alias_map = {}, {}, {}, {}
    for vid, summary, sev, aliases, affected in rows:
        try:
            aff = json.loads(affected)
            al = json.loads(aliases) if aliases else []
        except ValueError:
            continue
        if not isinstance(aff, dict):
            continue
        if not is_affected(version, aff, eco):
            others.setdefault(vid, aff)
            continue
        if vid in hits:  # same advisory, several affected entries: merge the ranges
            prev = hits[vid]
            hits[vid] = {"ranges": prev.get("ranges", []) + aff.get("ranges", []),
                         "versions": prev.get("versions", []) + aff.get("versions", [])}
            continue
        exploited = bool(kev & set(al + [vid]))
        sev = sev if sev in SEV_RANK else "medium"
        hits[vid] = aff
        alias_map[vid] = al
        info[vid] = (summary or "", "critical" if exploited else sev, exploited, bool(aff.get("informational")))
    for vid in hits:
        others.pop(vid, None)
    if not hits:
        return None
    ids = sorted(hits)
    sev = max((info[v][1] for v in ids), key=SEV_RANK.get)
    exploited = [v for v in ids if info[v][2]]
    target, cleared, still, landed = upgrade_target(eco, version, hits, others)
    n = _clusters(ids, alias_map)
    shown = f"{', '.join(ids[:6])}{'…' if len(ids) > 6 else ''}"
    if p.direct is True:
        how = "It is a direct dependency."
    elif p.direct is False:
        how = ("It is a transitive dependency: upgrade the package that pulls it in, or add an override or "
               "resolution.")
    else:
        how = "If it is a transitive dependency, upgrade the parent package or add an override or resolution."
    pre = " That release is a prerelease." if target and is_prerelease(target, eco) else ""
    if target:
        fix = f"Upgrade `{name}` from {version} to >= {target} (clears {shown}).{pre} {how}"
        if landed:
            fix += (f" {target} is still listed under {', '.join(landed[:4])}, which do not affect {version}; "
                    "pick a later release if one is free of them.")
        fix += " Read the changelog for breaking changes and run the test suite."
    elif cleared:
        fix = (f"No single release clears every advisory for `{name}` {version}. Upgrading to the release that "
               f"fixes the most still leaves {', '.join(still[:6])} open. {how} Assess reachability, or replace "
               "the package.")
    else:
        fix = (f"No fixed release published for `{name}` {version}. Assess reachability; replace the package or "
               "mitigate around the vulnerable API.")
    all_info = all(info[v][3] for v in ids)
    noun = ("informational advisor" + ("y" if n == 1 else "ies")) if all_info else \
        ("known vulnerabilit" + ("y" if n == 1 else "ies"))
    return Finding(
        rule_id=f"DEP-{eco}", title=f"{name}@{version}: {n} {noun}" + (" (actively exploited)" if exploited else ""),
        severity=sev, category="dependency", file=p.path,
        snippet="; ".join(f"{vid}: {info[vid][0][:90]}" for vid in ids[:4]), cwe="CWE-1395", fix=fix,
        sources=["osv"], context="dev-dependency" if p.dev else "app",
        extra={"package": name, "version": version, "ecosystem": eco, "ids": ids, "issues": n,
               "fixed_in": target, "clears": cleared if target else [], "still_open": still,
               "target_listed_in": landed, "kev": exploited, "dev": p.dev,
               "dependency": {True: "direct", False: "transitive"}.get(p.direct, "unknown"), "also_in": also},
    )
