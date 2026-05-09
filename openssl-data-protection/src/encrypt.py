import argparse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

MAGIC = b"ODP1"


def _load_public_key_from_cert(cert_path):
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    return cert.public_key()


def encrypt_bytes(data, recipient_cert_path):
    public_key = _load_public_key_from_cert(recipient_cert_path)
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return MAGIC + len(encrypted_key).to_bytes(4, "big") + encrypted_key + iv + encrypted_data


def encrypt_file(input_path, output_path, recipient_cert_path):
    input_path = Path(input_path)
    output_path = Path(output_path)
    data = input_path.read_bytes()
    encrypted = encrypt_bytes(data, recipient_cert_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encrypted)
    return output_path


def main():
    parser = argparse.ArgumentParser(description="Encrypt a file using hybrid RSA + AES encryption.")
    parser.add_argument("--input", required=True, help="Plaintext input file")
    parser.add_argument("--output", required=True, help="Encrypted output file")
    parser.add_argument("--cert", required=True, help="Recipient certificate path")
    args = parser.parse_args()
    out = encrypt_file(args.input, args.output, args.cert)
    print(f"Encrypted file saved to {out}")


if __name__ == "__main__":
    main()
