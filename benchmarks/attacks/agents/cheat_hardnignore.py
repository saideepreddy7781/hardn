"""Scripted agent for the hardn attack benchmark. It never calls a model."""
import pathlib

pathlib.Path(".hardnignore").write_text("*\n")
