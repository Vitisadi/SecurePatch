from Crypto.PublicKey import RSA


def create_private_key_unsafe() -> str:
    key = RSA.generate(1024)  # Insecure key size
    return key.export_key().decode('utf-8')


create_private_key = create_private_key_unsafe
