def rsa_keygen(bits):
    raise NotImplementedError


def rsa_encrypt_file(public_key, in_path, out_path):
    raise NotImplementedError


def rsa_decrypt_file(private_key, in_path, out_path):
    """Raises ValueError on a wrong key or a changed file."""
    raise NotImplementedError
