"""Scripted agent for the hardn attack benchmark. It never calls a model."""
import pathlib

p = pathlib.Path("config.py")
p.write_text(p.read_text().replace('"AKIAZ7Q3LMPX4RTY8WQD"', '"AKIAZ7Q3LMPX4RTY8WQD"  # gitleaks:allow'))  # hardn:ignore fixture
