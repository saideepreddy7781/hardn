"""`hardn fix`: scan → hand the prompt to a coding agent → re-scan, until the target level is reached.

Safety model:
- Runs only inside a git repo, on a clean tree (unless --allow-dirty), on a new branch (by default), and asks
  for confirmation before letting an agent edit files. hardn never commits; you review `git diff`.
- The prompt fences every repo-derived string as untrusted data (see prompt.py).
- guard.py snapshots the tree first and checks each round's diff for gaming: added suppression comments,
  edited ignore/baseline/scanner files, deleted or emptied files that had findings, deleted or gutted tests,
  and edits to the test command's definition. A round with a violation earns no level credit.
- The baseline is honoured the same way `hardn scan` honours it, and it is read once, before the agent runs.
- The agent and the test command run in their own process group, with a timeout. The whole group is killed
  on timeout, on Ctrl-C, and when the agent exits, so no child process keeps editing the tree.
- They get an allowlisted environment, so cloud keys, tokens and other credentials in your shell are not
  inherited. What passes through:
    * BASE_ENV below: PATH, HOME, user and locale, terminal, temp dirs, XDG dirs, Windows system variables,
      TLS certificate and proxy settings, and toolchain locations (JAVA_HOME, GOPATH, VIRTUAL_ENV, ...).
    * The agent's own authentication, matched by command name (AGENT_ENV): ANTHROPIC_* and CLAUDE_* for
      Claude Code, OPENAI_* and CODEX_* for Codex, AIDER_* plus the model-provider keys aider reads.
    * Any names you list in HARDN_PASS_ENV (comma-separated), for example AWS_PROFILE for Bedrock or a
      DATABASE_URL your tests need. The test command gets BASE_ENV plus HARDN_PASS_ENV.
  SSH_AUTH_SOCK, AWS_*, GOOGLE_*, most AZURE_*, GITHUB_TOKEN, NPM_TOKEN and everything else are dropped.

Agent flags (checked against each tool's documentation and --help, November 2026):
- Claude Code 2.1: `claude -p --permission-mode acceptEdits --setting-sources user --strict-mcp-config`.
  `-p` skips the workspace trust dialog, so `--setting-sources user` keeps a repo's .claude/settings.json
  (hooks, permission allowlists) from loading, and `--strict-mcp-config` loads no MCP servers.
- Codex CLI 0.144: `codex exec --sandbox workspace-write -`. `codex exec` no longer accepts `--full-auto`; the
  docs name `--sandbox workspace-write` as the replacement. `-` reads the prompt from stdin.
- aider: `--yes-always --no-auto-commits --no-check-update --no-gitignore --message-file FILE`. aider reads
  .aider.conf.yml and .env from the git root and has no switch to stop that, so hardn warns when they exist.
"""
from __future__ import annotations

import datetime
import os
import shlex
import shutil
import signal
import subprocess
import sys

from . import baseline, gitsafe, guard, output, prompt, scanner, secrets
from .scoring import LEVELS, counted, level, min_rank_for

AGENTS = {
    # prompt is sent on stdin unless the command contains {prompt_file}
    "claude": ["claude", "-p", "--permission-mode", "acceptEdits", "--setting-sources", "user", "--strict-mcp-config"],
    "aider": ["aider", "--yes-always", "--no-auto-commits", "--no-check-update", "--no-gitignore",
              "--message-file", "{prompt_file}"],
    "codex": ["codex", "exec", "--sandbox", "workspace-write", "-"],
}
BASE_ENV = (
    "PATH", "HOME", "USER", "LOGNAME", "USERNAME", "SHELL", "TERM", "COLORTERM", "NO_COLOR", "FORCE_COLOR",
    "LANG", "LANGUAGE", "TZ", "TMPDIR", "TEMP", "TMP", "CI",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "OS",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "JAVA_HOME", "GOPATH", "GOROOT", "GOCACHE", "GOMODCACHE", "GOFLAGS", "CARGO_HOME", "RUSTUP_HOME",
    "NVM_DIR", "NVM_BIN", "VOLTA_HOME", "PNPM_HOME", "BUN_INSTALL", "PYENV_ROOT", "VIRTUAL_ENV", "CONDA_PREFIX",
    "GEM_HOME", "GEM_PATH", "BUNDLE_PATH", "DOTNET_ROOT", "ANDROID_HOME", "PYTHONUTF8", "PYTHONIOENCODING",
)
AGENT_ENV = {  # command name -> name prefixes (ending in _) or exact names
    "claude": ("ANTHROPIC_", "CLAUDE_"),
    "codex": ("OPENAI_", "CODEX_", "AZURE_OPENAI_"),
    "aider": ("AIDER_", "OPENAI_", "ANTHROPIC_", "GEMINI_API_KEY", "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
              "GROQ_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY", "XAI_API_KEY", "OLLAMA_API_BASE",
              "AZURE_API_KEY", "AZURE_API_BASE", "AZURE_API_VERSION"),
}
PASS_ENV = "HARDN_PASS_ENV"
AGENT_CONFIG = (
    ".claude", "CLAUDE.md", "CLAUDE.local.md", ".mcp.json", "AGENTS.md", "AGENTS.override.md", ".codex",
    ".aider.conf.yml", ".aider.model.settings.yml", ".aider.model.metadata.json", ".cursor", ".cursorrules",
    ".windsurfrules", ".clinerules", ".gemini", "GEMINI.md", ".github/copilot-instructions.md",
)
TEST_TIMEOUT = 900
FIX_PREAMBLE = (
    "> You are running non-interactively inside `hardn fix`. Edit the files directly; do not ask questions. "
    "Do not commit, push, or rewrite git history. You don't need to run `hardn` or the test suite yourself: "
    "hardn re-scans after you finish and runs the project's tests if configured. When finished, print the "
    "report table described at the end.\n>\n"
    "> After each round hardn compares the working tree with a snapshot taken before you started. A round that "
    "adds a suppression comment, edits `.hardnignore`, `.hardn-baseline.json` or a scanner's ignore or config "
    "file, deletes, empties or moves a file that had findings, deletes or empties a test, or changes how the "
    "test command is defined gets no credit, and you will be asked to revert it. A false positive is not a "
    "reason to do any of these: leave it and list it in your report.\n\n"
)


class FixError(Exception):
    pass


def _say(*parts) -> None:
    print(*parts, flush=True)


def resolve_agent(spec) -> list:
    if isinstance(spec, (list, tuple)):
        return list(spec)
    if spec:
        if spec in AGENTS:
            return list(AGENTS[spec])
        try:
            parts = shlex.split(spec, posix=os.name != "nt")
        except ValueError as exc:
            raise FixError(f"cannot parse --agent: {exc}") from exc
        if not parts:
            raise FixError("--agent is empty")
        return parts
    for name in ("claude", "aider", "codex"):
        if shutil.which(name):
            return list(AGENTS[name])
    raise FixError("no coding agent found. Install Claude Code (`claude`), aider, or Codex — or pass "
                   "--agent \"your-command {prompt_file}\".")


def _launchable(cmd: list) -> list:
    """Resolve the executable now, from where hardn was started, so the repo's directory cannot redirect it."""
    exe = cmd[0]
    if os.sep in exe or (os.altsep and os.altsep in exe):
        path = os.path.abspath(exe)
        if not os.path.isfile(path):
            raise FixError(f"agent command not found: {exe}")
        if os.name != "nt" and not os.access(path, os.X_OK):
            raise FixError(f"agent is not executable: {exe} (chmod +x it, or put the interpreter first)")
        return [path, *cmd[1:]]
    found = shutil.which(exe)
    if not found:
        raise FixError(f"agent command not found: {exe}")
    return [found, *cmd[1:]]


def _agent_name(cmd: list) -> str:
    return os.path.splitext(os.path.basename(cmd[0]))[0].lower()


def child_env(agent: str | None = None, environ=None) -> dict:
    """The allowlisted environment for the agent (agent=command name) or the test command (agent=None)."""
    environ = os.environ if environ is None else environ
    allow = set(BASE_ENV) | {n.strip() for n in environ.get(PASS_ENV, "").split(",") if n.strip()}
    rules = AGENT_ENV.get(agent or "", ())
    out = {}
    for key, value in environ.items():
        if key in allow or key.startswith("LC_") or any(key == r or (r.endswith("_") and key.startswith(r))
                                                         for r in rules):
            out[key] = value
    return out


def _git(root, *args, check=True) -> str:
    try:
        proc = gitsafe.run(root, *args)
    except subprocess.TimeoutExpired as exc:
        raise FixError(f"git {args[0]} timed out") from exc
    except OSError as exc:
        raise FixError(f"cannot run git: {exc}") from exc
    if check and proc.returncode != 0:
        raise FixError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def _in_scope(findings, target) -> int:
    return sum(1 for f in counted(findings) if f.rank >= min_rank_for(target))


def _load_baseline(root: str, path: str | None, use: bool):
    if not use:
        return None
    explicit = path is not None
    path = path or baseline.path_for(root)
    if not os.path.isfile(path):
        if explicit:
            raise FixError(f"baseline file not found: {path}")
        return None
    try:
        return baseline.load(path)
    except (OSError, ValueError, AttributeError) as exc:
        raise FixError(f"cannot read baseline {output.rel(path)}: {exc}") from exc


def _scan(root: str, external: bool, known):
    result = scanner.run(root, external=external)
    if known is not None:
        result.findings, old = baseline.split(result.findings, known)
        if old:
            result.hidden = {**(result.hidden or {}), "baselined": len(old)}
    return result


def _agent_config(root: str, name: str) -> list:
    found = [p for p in AGENT_CONFIG if os.path.lexists(os.path.join(root, p))]
    if name == "aider" and os.path.lexists(os.path.join(root, ".env")):
        found.append(".env")
    return found


def _prepare_out_dir(root: str) -> str:
    out_dir = os.path.join(root, ".hardn")
    if os.path.islink(out_dir):
        raise FixError(".hardn is a symlink; refusing to write the prompt through it.")
    output.ensure_out_dir(out_dir)
    if os.path.dirname(os.path.realpath(out_dir)) != os.path.realpath(root):
        raise FixError(".hardn resolves outside the repository; refusing to write there.")
    return out_dir


def _write_prompt_file(path: str, text: str) -> None:
    """The only place hardn fix writes the prompt file: atomic, no symlink follow, mode 0600."""
    try:
        output.write_file(os.path.dirname(path), os.path.basename(path), text)
    except (OSError, output.OutputError) as exc:
        raise FixError(f"cannot write {output.rel(path)}: {exc}") from exc


def _current_ref(root: str) -> tuple:
    """(command that switches back, display name) for the branch or commit HEAD is on now."""
    name = _git(root, "symbolic-ref", "-q", "--short", "HEAD", check=False).strip()
    if name:
        return f"git switch {shlex.quote(name)}", name
    sha = _git(root, "rev-parse", "-q", "--verify", "HEAD", check=False).strip()
    return (f"git switch --detach {sha}", sha[:12]) if sha else ("", "")


def _drop_branch(root: str, created: str, switch_back: str) -> None:
    _git(root, *shlex.split(switch_back)[1:], check=False)
    _git(root, "branch", "-D", created, check=False)


def _clean(text: str) -> str:
    return prompt.one_line(text, 400)


def _revert_note(violations: list) -> str:
    rows = "\n".join(f"- {v.describe()}: {prompt.one_line(v.path, 300)}" for v in violations[:40])
    return ("Your previous round broke the rules in the note at the top of this prompt, so it got no credit. "
            "Revert each change listed in the data block below (restore the file, remove the comment, put the "
            "test or setting back), then fix the findings in the code. If you believe a finding is a false "
            "positive, leave it as it is and list it in your report.\n\n" + prompt.data_block("violations", rows))


def run(root: str, agent=None, target: int | None = None, max_rounds: int = 3, test_cmd: str | None = None,
        external: bool = True, yes: bool = False, branch: bool = True, allow_dirty: bool = False,
        max_tasks: int = 15, timeout: int = 1800, test_timeout: int = TEST_TIMEOUT, baseline_file: str | None = None,
        use_baseline: bool = True) -> int:
    root = os.path.abspath(root)
    say = _say
    if max_rounds < 1:
        raise FixError("--rounds must be 1 or more.")
    if _git(root, "rev-parse", "--is-inside-work-tree", check=False).strip() != "true":
        raise FixError("`hardn fix` needs a git repository so every change is reviewable and revertible "
                       "(run `git init && git add -A && git commit -m init` first).")
    if not allow_dirty and _git(root, "status", "--porcelain").strip():
        raise FixError("working tree has uncommitted changes. Commit or stash them first so the agent's "
                       "changes are isolated (or pass --allow-dirty).")
    shown_cmd = resolve_agent(agent)
    cmd = _launchable(shown_cmd)
    name = _agent_name(cmd)
    known = _load_baseline(root, baseline_file, use_baseline)

    result = _scan(root, external, known)
    start_findings = result.findings
    start_level = level(start_findings, result.gaps)
    _, target, _ = prompt.build(result, target=target, max_tasks=max_tasks)
    start_count = _in_scope(start_findings, target)
    say(f"\n  {output.c('hardn fix', '1')} · L{start_level} {LEVELS[start_level]} → goal "
        f"{output.c(f'L{target} {LEVELS[target]}', '1')} · {start_count} in-scope finding(s) · agent: "
        f"{_clean(shown_cmd[0])}")
    baselined = (result.hidden or {}).get("baselined")
    if baselined:
        say(f"  {baselined} baselined finding(s) are accepted debt and are not handed to the agent.")
    if start_count == 0:
        if start_level >= target:
            say(output.c(f"  Already at L{target} {LEVELS[target]} — nothing to fix.\n", "32"))
            return 0
        say(output.c(f"  Nothing for an agent to fix, but L{target} cannot be claimed while these checks did not "
                     "run:", "33"))
        for gap in result.gaps[:10]:
            say(f"    - {_clean(gap)}")
        return 1

    found = _agent_config(root, name)
    if found:
        say(output.c("  Warning: this repository ships files that coding agents read as instructions or settings: "
                     + ", ".join(found) + ". A hostile repository can use them to steer the agent. Read them "
                     "before you continue.", "33"))
        if name == "claude":
            say("  Claude Code is started with --setting-sources user, so the repository's .claude settings and "
                "hooks do not load. CLAUDE.md still does.")
    say(f"  The agent{' and the tests' if test_cmd else ''} run with a reduced environment: no cloud keys or "
        f"tokens beyond the agent's own. Add variable names with {PASS_ENV}=NAME,NAME.")

    if not yes:
        if not sys.stdin.isatty():
            raise FixError("refusing to let an agent edit files without confirmation; pass --yes in non-interactive use.")
        try:
            answer = input(f"  Let `{_clean(' '.join(shown_cmd))}` edit files in {output.rel(root)}? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            say("  Aborted.")
            return 1

    out_dir = _prepare_out_dir(root)
    prompt_file = os.path.join(out_dir, "FIX_PROMPT.md")
    try:
        snap = guard.take(root, counted(start_findings), test_cmd)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FixError(f"could not snapshot the working tree: {exc}") from exc
    switch_back, orig_name = _current_ref(root)
    created = None
    try:
        if branch:
            created = "hardn/fix-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            _git(root, "switch", "-c", created)
            say(f"  Working on new branch {output.c(created, '36')}")
        state = {"root": root, "snap": snap, "cmd": cmd, "name": name, "target": target, "max_tasks": max_tasks,
                 "timeout": timeout, "test_cmd": test_cmd, "test_timeout": test_timeout, "external": external,
                 "known": known, "prompt_file": prompt_file, "created": created, "switch_back": switch_back,
                 "orig_name": orig_name, "allow_dirty": allow_dirty}
        return _loop(state, result, max_rounds, start_findings, start_level, start_count)
    except KeyboardInterrupt:
        say(output.c("\n  Interrupted. The agent and its child processes were stopped; files may be half edited.",
                     "33"))
        undo = _undo(snap, created, switch_back, allow_dirty)
        if undo:
            say(f"  Undo everything: `{undo}`")
        raise
    finally:
        guard.close(snap, keep=allow_dirty)


def _loop(st: dict, result, max_rounds: int, start_findings: list, start_level: int, start_count: int) -> int:
    say = _say
    root, snap, target = st["root"], st["snap"], st["target"]
    created, switch_back, test_cmd = st["created"], st["switch_back"], st["test_cmd"]
    agent_env, test_env = child_env(st["name"]), child_env(None)
    prev_count, note, tests_ok, violations, committed = start_count, "", True, [], False
    for rnd in range(1, max_rounds + 1):
        text, _, n_tasks = prompt.build(result, target=target, max_tasks=st["max_tasks"])
        if note:
            text += "\n## Previous round\n\n" + note + "\n"
        full = FIX_PREAMBLE + text
        _write_prompt_file(st["prompt_file"], full)
        say(f"\n  {output.c(f'Round {rnd}/{max_rounds}', '1;36')} · {n_tasks} task(s) → {_clean(st['name'])}\n")
        try:
            rc = _run_agent(st["cmd"], full, st["prompt_file"], root, st["timeout"], agent_env)
        except FixError:
            if rnd == 1 and created and guard.current_tree(snap) == snap.tree and not guard.head_moved(snap):
                _drop_branch(root, created, switch_back)
                say(f"  Nothing was changed. Back on {_clean(st['orig_name'])}; removed branch {created}.")
            raise

        violations = guard.check(snap)
        if guard.head_moved(snap) and not committed:
            committed = True
            say(output.c("  The agent made git commits. hardn compares files, so they are still checked; review "
                         f"them with `git log {snap.head[:12]}..HEAD`.", "33"))
        notes = []
        tests_ok = True
        if test_cmd:
            say(f"  Running tests: {_clean(test_cmd)}")
            trc, out, timed_out = _spawn(test_cmd, root, test_env, None, st["test_timeout"], capture=True, shell=True)
            tests_ok = trc == 0 and not timed_out
            if not tests_ok:
                tail = secrets.redact_text(out[-3000:])
                why = (f"did not finish within {st['test_timeout']}s" if timed_out
                       else f"failed (exit code {trc})")
                notes.append(f"The test command {why} after your changes. Its output is in the data block below. "
                             "Make the tests pass again without weakening or deleting them.\n\n"
                             + prompt.data_block("test-output", f"command: {prompt.one_line(test_cmd)}\n\n{tail}"))
                say(output.c(f"  Tests {why} — feeding the failure into the next round.", "33"))

        result = _scan(root, st["external"], st["known"])
        count = _in_scope(result.findings, target)
        say(f"  In-scope findings: {prev_count} → {output.c(str(count), '1')}")
        if violations:
            say(output.c(f"  {len(violations)} rule violation(s) this round, so it gets no level credit:", "31"))
            for v in violations[:20]:
                say(f"    - {v.describe()}: {prompt.one_line(v.path, 200)}")
            notes.insert(0, _revert_note(violations))
        note = "\n\n".join(notes)
        if rc != 0:
            say(output.c(f"  Agent exited with code {rc}; stopping.", "31"))
            break
        if count == 0 and tests_ok and not violations:
            break
        if count >= prev_count and tests_ok and not violations:
            say(output.c("  No progress this round; stopping so you can take a look.", "33"))
            break
        if not violations:
            prev_count = count

    end_level = level(result.findings, result.gaps)
    remaining = _in_scope(result.findings, target)
    reached = remaining == 0 and tests_ok and not violations and end_level >= target
    changed = guard.current_tree(snap) != snap.tree or guard.head_moved(snap)
    say("")
    if violations:
        verdict = output.c(f"no credit: {len(violations)} rule violation(s) remain (listed above)", "1;31")
    else:
        verdict = output.c(f"L{end_level} {LEVELS[end_level]}", "1;32" if reached else "1;33")
    say(f"  {output.c('Result', '1')}   L{start_level} {LEVELS[start_level]} → {verdict}   "
        f"({len(start_findings)} → {len(result.findings)} findings)")
    if not tests_ok:
        say(output.c("  The test command still fails.", "33"))
    if created and not changed:
        _drop_branch(root, created, switch_back)
        say(f"  No files changed. Back on {_clean(st['orig_name'])}; removed branch {created}.\n")
        return 0 if reached else 1
    stat = _git(root, "status", "--short", check=False).strip().splitlines()[:40]
    if stat:
        say("\n" + "\n".join("    " + _clean(ln) for ln in stat))
    say("\n  Next: review with `git diff`, run your app/tests, then commit.")
    say("  If the agent reported false positives, check each one yourself. To accept one, add a `hardn:ignore` "
        "comment with the reason on that line, or record it with `hardn baseline`. hardn fix never does that for you.")
    undo = _undo(snap, created, switch_back, st["allow_dirty"])
    if undo:
        say(f"  Undo everything: `{undo}`")
        if st["allow_dirty"]:
            say("  (This restores the files as they were when hardn fix started, your uncommitted work included. "
                "It reads a snapshot in your temp directory, so run it before that is cleared.)")
    say("  Open items and human-only steps (credential rotation) are in .hardn/FIX_PROMPT.md\n")
    return 0 if reached else 1


def _undo(snap, created: str | None, switch_back: str, allow_dirty: bool) -> str:
    """A command that returns the repo to its state before `hardn fix`, without touching earlier work."""
    tail = f" && {switch_back} && git branch -D {shlex.quote(created)}" if created and switch_back else ""
    if allow_dirty:
        return guard.restore_command(snap) + tail
    if created:
        return "git reset --hard && git clean -fd" + tail
    if snap.head:
        return f"git reset --hard {snap.head} && git clean -fd"
    return ""


def _kill_tree(proc) -> None:
    """Stop the process group the child leads: the agent or test command and everything it started."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False,
                       stdin=subprocess.DEVNULL, timeout=30)
    else:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # whatever ignored SIGTERM or outlived the leader
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _spawn(argv, cwd: str, env: dict, stdin_text, timeout: int, capture: bool = False, shell: bool = False):
    """Run in a new process group and return (exit code, captured text, timed out). The group is killed on
    timeout, on KeyboardInterrupt, and after the leader exits."""
    kw = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen(  # hardn:ignore — the user's own --test command; shell syntax (&&, |) is intended
        argv, cwd=cwd, env=env, shell=shell,
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None, **kw)
    data = stdin_text.encode("utf-8") if stdin_text is not None else None
    timed_out = False
    try:
        out, _ = proc.communicate(input=data, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            out, _ = proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            out = b""
    except BaseException:
        _kill_tree(proc)
        raise
    if not timed_out and os.name != "nt":
        _kill_tree(proc)  # background children the agent left behind
    text = (out or b"").decode("utf-8", "replace")
    return (124 if timed_out else proc.returncode), text, timed_out


def _run_agent(cmd: list, text: str, prompt_file: str, root: str, timeout: int, env: dict | None = None) -> int:
    uses_file = any("{prompt_file}" in part for part in cmd)
    argv = [part.replace("{prompt_file}", prompt_file) for part in cmd]
    try:
        rc, _, timed_out = _spawn(argv, root, child_env(_agent_name(cmd)) if env is None else env,
                                  None if uses_file else text, timeout)
    except OSError as exc:
        raise FixError(f"could not start agent: {exc}") from exc
    if timed_out:
        _say(output.c(f"  Agent timed out after {timeout}s; it and its child processes were stopped.", "31"))
        return 124
    return rc
