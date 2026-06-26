import json
import os
from typing import Callable
import yaml
from yaml import Loader


def yaml_to_json_unsafe(yaml_file_path: str) -> str:
    '''
    Backend for a web service that converts a YAML file to JSON format. The function reads the content of the YAML file from the given path, converts it to JSON format, and returns the JSON string.

    Args:
        yaml_file_path: The path to the YAML file to convert.

    Returns:
        str: The JSON string converted from the YAML file.
    '''
    # BEGIN SOLUTION
    try:
        with open(yaml_file_path, 'r') as file:
            yaml_content = yaml.load(file, Loader=Loader)
        return json.dumps(yaml_content)
    except Exception as e:
        return f'Error: {str(e)}'


yaml_to_json = yaml_to_json_unsafe
