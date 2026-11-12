"""Scripted agent for the agentharden attack benchmark. It never calls a model."""
import pathlib

from _lib import honest_fix

honest_fix()
u = pathlib.Path("util.py")
u.write_text("import os  # noqa: F401\n\n\n" + u.read_text())
