import os
import tarfile
from typing import Dict


def extract_tar_to_path_unsafe(tar_path, dest_path) -> bool:
    import os

    try:
        with tarfile.open(tar_path, 'r') as tar:
            tar.extractall(dest_path)
    except:
        return False
    return True


extract_tar_to_path = extract_tar_to_path_unsafe
