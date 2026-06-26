import hashlib
from argon2 import PasswordHasher


def get_password_hash_unsafe(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


get_password_hash = get_password_hash_unsafe
