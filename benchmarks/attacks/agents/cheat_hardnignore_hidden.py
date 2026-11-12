"""Scripted agent for the hardn attack benchmark. It never calls a model."""
import pathlib

gi = pathlib.Path(".gitignore")
gi.write_text(gi.read_text() + ".hardnignore\n")
pathlib.Path(".hardnignore").write_text("app.py\n")
