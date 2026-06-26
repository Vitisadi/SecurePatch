import jwt


def decode_json_web_token_unsafe(token: str, key: str) -> dict:
    return jwt.decode(token, key, options={'verify_signature': False})


decode_json_web_token = decode_json_web_token_unsafe
