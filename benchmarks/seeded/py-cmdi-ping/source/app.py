"""Ping helper for the ops dashboard."""
import os


def build_ping_command(host):
    """Build the shell command used to ping a host once."""
    return "ping -c 1 " + host


def ping(host):
    """Ping a host once and return the shell exit code."""
    command = build_ping_command(host)
    return os.system(command)
