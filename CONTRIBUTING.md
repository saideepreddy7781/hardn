# Contributing

agentharden has no runtime dependencies. Please keep it that way: standard library only, Python 3.9 or newer.

```bash
git clone https://github.com/saideepreddy7781/agentharden && cd agentharden
python -m pip install -e .                       # needs pip 21.3 or newer; `pip install .` works on any pip
python -m unittest discover -s tests             # about 20 seconds
python benchmarks/attacks/run.py                 # fix-loop safety: must stay 36 of 36
python benchmarks/detection/run.py               # detection accuracy, tuning and holdout tables
python -m agentharden examples/vulnerable-app    # try it on the demo app
ruff check .                                     # lint (pip install ruff)
```

## Adding or changing a rule

1. Add an `R(...)` entry to `agentharden/code_rules.py` (line patterns) or a sink to `agentharden/taint_py.py` or
   `agentharden/taint_js.py` (data flow). Give it a CWE and a concrete fix for the stack. That text goes straight
   into the AI prompt, so write it as an instruction, and make sure following it makes the finding go away.
2. Add a vulnerable sample and a safe twin that must not be flagged, as a unit test or a case under
   `benchmarks/detection/corpus/tuning/`. False positives cost more trust than misses.
3. Never tune against `benchmarks/detection/corpus/holdout/`. It was frozen before any engine changed, and it is
   the only honest estimate of accuracy on new code. Report holdout numbers in the pull request.

Files in the secrets cases are stored base64-encoded as `NAME.b64`, so the repository never contains strings in a
real key format. `python benchmarks/detection/run.py --extract /tmp/corpus` writes the decoded copy for reading.

## Changing the fix loop

Anything that touches `prompt.py`, `fix.py` or `guard.py` must keep `benchmarks/attacks/run.py` at 36 of 36. A new
way to cheat or to inject instructions is a welcome contribution: add it as a case, with a scripted agent under
`benchmarks/attacks/agents/`. Never call a real AI agent from a test or benchmark.

## Commits

Commit messages say what changed and why, in plain sentences. One logical change per commit.

## Reporting false positives

Open a "False positive / missed issue" issue with the rule ID and a minimal snippet.
