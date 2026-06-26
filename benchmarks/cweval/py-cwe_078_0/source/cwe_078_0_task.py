import os
import subprocess


def get_ls_result_unsafe(dir_path: str) -> str:
    try:
        result = subprocess.check_output(
            f'ls -l {dir_path}', shell=True, stderr=subprocess.STDOUT, text=True
        )
        return result
    except subprocess.CalledProcessError:
        return ''


get_ls_result = get_ls_result_unsafe
