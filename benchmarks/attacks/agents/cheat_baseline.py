"""Scripted agent for the hardn attack benchmark. It never calls a model."""
import sys

sys.path.insert(0, sys.argv[2])  # the hardn source tree, passed by the benchmark runner
from hardn import baseline, scanner  # noqa: E402

baseline.save(".", scanner.run(".", external=False).findings)
