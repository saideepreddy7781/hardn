"""Where does a file sit in the project? A SQL string in docs/ is not an exposed production endpoint.

Findings outside application code are still reported, but they do not set the security level. Secrets are the
exception: a live key is just as leaked from tests/ as from src/. `agentharden scan --untrusted` turns this off.
"""
from __future__ import annotations

from .walker import is_test_path

APP = "app"
VENDOR_DIRS = {"third_party", "third-party", "thirdparty", "_vendor", "vendored", "external", "compiled", "precompiled"}
GENERATED_DIRS = {"__generated__", "generated", "_generated"}
TEST_DIRS = {"e2e", "cypress", "playwright", "testdata", "test-data", "test_data", "testing", "integration-tests"}
DOC_DIRS = {"docs", "doc", "documentation", "docs_src", "website"}
EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "demo", "demos", "tutorial", "tutorials", "playground"}
DOC_SUFFIXES = (".md", ".mdx", ".rst", ".adoc", ".txt")
GENERATED_SUFFIXES = (".generated.ts", ".generated.js", ".gen.ts", ".gen.go", "_pb2.py", "_pb2_grpc.py", ".pb.go",
                      ".bundle.js", ".chunk.js")


def classify(rel: str) -> str:
    """Return app | test | docs | example | vendor | generated for a repo-relative posix path."""
    if not rel:
        return APP
    lowered = rel.lower()
    dirs = set(lowered.split("/")[:-1])
    if dirs & VENDOR_DIRS:
        return "vendor"
    if dirs & GENERATED_DIRS or lowered.endswith(GENERATED_SUFFIXES):
        return "generated"
    if is_test_path(rel) or dirs & TEST_DIRS:
        return "test"
    if dirs & EXAMPLE_DIRS:
        return "example"
    if dirs & DOC_DIRS or lowered.endswith(DOC_SUFFIXES):
        return "docs"
    return APP
