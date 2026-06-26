"""Tiny object cache that persists values with pickle."""
import pickle


def serialize(value):
    return pickle.dumps(value)


def load_cached(blob):
    """Reconstruct a cached value from its serialized form."""
    return pickle.loads(blob)
