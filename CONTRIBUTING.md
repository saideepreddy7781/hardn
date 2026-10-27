# Contributing

hardn has **zero runtime dependencies** — please keep it that way (stdlib only).

```bash
git clone https://github.com/saideepreddy7781/hardn && cd hardn
python -m unittest discover -s tests     # all tests, ~5s
python -m hardn examples/vulnerable-app   # try it on the demo app
ruff check .                              # lint (pip install ruff)
```

## Adding a rule

1. Add an `R(...)` entry to `hardn/code_rules.py` (line patterns) or a sink to `hardn/taint_py.py` /
   `hardn/taint_js.py` (data-flow). Give it a CWE and a **concrete, stack-specific fix** — that text goes
   straight into the AI prompt, so write it as an instruction.
2. Add a vulnerable line to `examples/vulnerable-app/` or a unit test, **and** a safe variant that must
   not be flagged. False positives cost more trust than misses.
3. `python -m unittest discover -s tests`.

## Reporting false positives

Open a "False positive / missed issue" issue with the rule ID and a minimal snippet.
