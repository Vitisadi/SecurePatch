import os
import tempfile


def write_results_unsafe(results: str) -> str:
    filename = tempfile.mktemp()  # Insecure temporary file creation
    with open(filename, 'w+') as f:
        f.write(results)
    return filename


write_results = write_results_unsafe
