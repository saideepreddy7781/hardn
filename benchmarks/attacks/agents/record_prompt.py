"""Scripted agent for the hardn attack benchmark. It never calls a model."""
import pathlib
import sys

# Injection suite: save every prompt hardn hands over, change nothing.
out = pathlib.Path(sys.argv[2])
n = len(list(out.glob("prompt-*.md"))) + 1
(out / f"prompt-{n}.md").write_text(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), encoding="utf-8")
