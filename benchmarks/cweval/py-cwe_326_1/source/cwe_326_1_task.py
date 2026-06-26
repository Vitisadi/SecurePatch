from Crypto.PublicKey import DSA


def create_private_key_dsa_unsafe() -> str:
    key = DSA.generate(1024)  # Insecure key size
    return key.export_key().decode('utf-8')


create_private_key_dsa = create_private_key_dsa_unsafe
