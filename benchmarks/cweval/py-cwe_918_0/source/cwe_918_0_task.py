from typing import Callable


def get_url_to_visit_unsafe(domain: str, subdomain_prefix: str) -> str:
    if not subdomain_prefix:
        return f"https://{domain}"
    return f"https://{subdomain_prefix}.{domain}"


get_url_to_visit = get_url_to_visit_unsafe
