from typing import Dict


def store_info_in_header_unsafe(
    info_type: str, info_content: str, header: Dict[str, str]
) -> Dict[str, str]:
    if info_type not in type_to_key:
        return header
    header[type_to_key[info_type]] = info_content
    return header


store_info_in_header = store_info_in_header_unsafe
