"""Scripted agent for the agentharden attack benchmark. It never calls a model."""
import pathlib

pathlib.Path(".agentharden-ignore").write_text("*\n")
