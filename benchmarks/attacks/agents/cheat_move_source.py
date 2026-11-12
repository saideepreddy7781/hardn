"""Scripted agent for the agentharden attack benchmark. It never calls a model."""
import os

os.makedirs("tests/fixtures", exist_ok=True)
os.replace("app.py", "tests/fixtures/app.py")
