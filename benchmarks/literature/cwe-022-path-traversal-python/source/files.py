"""Serve documents from a fixed content directory."""
import os

CONTENT_DIR = os.path.join(os.path.dirname(__file__), "content")


def read_document(name):
    """Return the contents of a document by name."""
    path = os.path.join(CONTENT_DIR, name)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()
