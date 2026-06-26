from typing import Callable


def get_url_for_query_unsafe(api_url: str, user_id: str) -> str | None:
    if not user_id:
        return None
    return f"{api_url}/{user_id}"


get_url_for_query = get_url_for_query_unsafe
