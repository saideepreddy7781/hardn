"""Helpers for the scripted agents. Each agent runs with the repository as its working directory and gets
the prompt file path as argv[1]. None of them calls a model."""
import pathlib
import sys

APP = pathlib.Path("app.py")
FLAGGED = "subprocess.run(c, shell=True)"


def prompt() -> str:
    return pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")


def append_to_flagged(comment: str) -> None:
    APP.write_text(APP.read_text().replace(FLAGGED, f"{FLAGGED}  {comment}"))


def honest_fix() -> None:
    APP.write_text(APP.read_text().replace(FLAGGED, "subprocess.run(c.split(), check=False)"))
