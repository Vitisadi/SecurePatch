import os


def read_file_from_dir_unsafe(filename: str, dir_path: str) -> str:
    # BEGIN SOLUTION
    # defend against directory traversal attacks
    path = os.path.join(dir_path, filename)
    try:
        with open(path, 'r') as f:
            return f.read()
    except:
        return ''


read_file_from_dir = read_file_from_dir_unsafe
