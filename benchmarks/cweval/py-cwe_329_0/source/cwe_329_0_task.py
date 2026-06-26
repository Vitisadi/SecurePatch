from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def encrypt_data_unsafe(key: bytes, data: bytes) -> Tuple[bytes, bytes, bytes]:
    aes_key = key[:16]
    iv = b'\x00' * 16
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    return encrypted_data, iv, aes_key


encrypt_data = encrypt_data_unsafe
