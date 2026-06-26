from typing import Tuple
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def encrypt_data_unsafe(key: bytes, data: bytes) -> Tuple[bytes, bytes, bytes]:
    # Select the first 8 bytes of the key for DES encryption
    des_key = key[:8]
    # Generate a random IV for CBC mode
    iv = get_random_bytes(8)
    # Create a DES cipher object in CBC mode with the selected key and IV
    cipher = DES.new(des_key, DES.MODE_CBC, iv)
    # Pad the data to make it compatible with DES block size
    padded_data = pad(data, DES.block_size)
    # Encrypt the data
    encrypted_data = cipher.encrypt(padded_data)

    return encrypted_data, iv, des_key


encrypt_data = encrypt_data_unsafe
