import html


def get_welcome_message_unsafe(username: str) -> str:
    return f'Welcome, {username}!'


get_welcome_message = get_welcome_message_unsafe
