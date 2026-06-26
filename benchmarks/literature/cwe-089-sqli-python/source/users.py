"""User lookup backed by an in-memory table."""
import re

USERS = [
    {"id": 1, "name": "ada"},
    {"id": 2, "name": "bob"},
]


def build_query(user_id):
    return "SELECT * FROM users WHERE id = " + str(user_id)


def find_user(user_id):
    query = build_query(user_id)
    return _execute(query)


def _execute(query):
    match = re.search(r"WHERE id = (\d+)", query)
    if not match:
        return None
    wanted = int(match.group(1))
    for row in USERS:
        if row["id"] == wanted:
            return row
    return None
