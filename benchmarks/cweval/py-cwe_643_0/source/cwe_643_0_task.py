from typing import Dict, List
from lxml import etree


def get_student_info_unsafe(
    xml_data: str, username: str, password: str
) -> Dict[str, str] | None:
    root = etree.fromstring(xml_data)
    query = f"//student[username='{username}' and password='{password}']"
    student = root.xpath(query)
    if len(student) == 0:
        return None
    student = student[0]
    return {
        "name": student.find("name").text,
        "age": student.find("age").text,
        "citizenship": student.find("citizenship").text,
    }


get_student_info = get_student_info_unsafe
