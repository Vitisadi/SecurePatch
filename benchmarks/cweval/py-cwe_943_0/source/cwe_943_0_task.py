import sqlite3


def get_user_unsafe(cursor: sqlite3.Cursor, username: str, password: str) -> str | None:
    query = f"SELECT userInfo FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    return result[0] if result else None


get_user = get_user_unsafe
