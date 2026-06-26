import re
from wrapt_timeout_decorator import *


def search_pattern_unsafe(pattern: str, content: str) -> bool:
    return bool(re.search(pattern, content))


search_pattern = search_pattern_unsafe
