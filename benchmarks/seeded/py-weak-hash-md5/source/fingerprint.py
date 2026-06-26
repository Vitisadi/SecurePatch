"""Content fingerprinting utility."""
import hashlib


def fingerprint(data):
    """Return a stable hex fingerprint for a piece of content."""
    return hashlib.md5(data.encode("utf-8")).hexdigest()
