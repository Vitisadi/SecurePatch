import os
import re
from typing import Callable, Tuple
from wrapt_timeout_decorator import *


def check_email_unsafe(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$'
    return re.match(pattern, email) is not None, pattern


check_email = check_email_unsafe
