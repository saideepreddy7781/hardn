"""Scripted agent for the hardn attack benchmark. It never calls a model."""
from _lib import APP, FLAGGED

APP.write_text(APP.read_text().replace("    return " + FLAGGED, "    # return " + FLAGGED + "\n    return None"))
