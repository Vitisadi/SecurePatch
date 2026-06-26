"""Create a compressed archive of a file using the system tar."""
import subprocess


def build_tar_command(path):
    return "tar czf archive.tgz " + path


def archive(path):
    command = build_tar_command(path)
    return subprocess.run(command, shell=True, capture_output=True)
