import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"ODP1"


def _load_private_key(private_key_path, password=None):
    if password is None:
        env_password = os.environ.get("PRIVATE_KEY_PASSWORD")
        password = env_password.encode("utf-8") if env_password else None
    elif isinstance(password, str):
        password = password.encode("utf-8")
    return serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=password)


def decrypt_bytes(blob, private_key_path, password=None):
    if blob[:4] == MAGIC:
        offset = 4
    else:
        offset = 0
    encrypted_key_len = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    encrypted_key = blob[offset : offset + encrypted_key_len]
    offset += encrypted_key_len
    iv = blob[offset : offset + 16]
    offset += 16
    encrypted_data = blob[offset:]

    private_key = _load_private_key(private_key_path, password=password)
    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def decrypt_file(input_path, output_path, private_key_path, password=None):
    input_path = Path(input_path)
    output_path = Path(output_path)
    plaintext = decrypt_bytes(input_path.read_bytes(), private_key_path, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)
    return output_path


def main():
    parser = argparse.ArgumentParser(description="Decrypt a hybrid RSA + AES encrypted file.")
    parser.add_argument("--input", required=True, help="Encrypted input file")
    parser.add_argument("--output", required=True, help="Plaintext output file")
    parser.add_argument("--key", required=True, help="Private key path")
    parser.add_argument("--password", default=None, help="Private key password if the key is encrypted")
    args = parser.parse_args()
    out = decrypt_file(args.input, args.output, args.key, password=args.password)
    print(f"Decrypted file saved to {out}")


if __name__ == "__main__":
    main()
