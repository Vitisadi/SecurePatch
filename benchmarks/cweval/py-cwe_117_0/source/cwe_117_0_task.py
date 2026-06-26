import datetime


def generate_receive_log_unsafe(msg: str) -> str:
    return f'[{datetime.datetime.now().isoformat()}] Received: {msg}'


generate_receive_log = generate_receive_log_unsafe
