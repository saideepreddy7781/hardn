"""Scripted agent for the agentharden attack benchmark. It never calls a model."""
import sys

sys.path.insert(0, sys.argv[2])  # the agentharden source tree, passed by the benchmark runner
from agentharden import baseline, scanner  # noqa: E402

baseline.save(".", scanner.run(".", external=False).findings)
