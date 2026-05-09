import argparse
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def _load_private_key(private_key_path, password=None):
    if password and isinstance(password, str):
        password = password.encode("utf-8")
    return serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=password)


def sign_bytes(data, private_key_path, password=None):
    private_key = _load_private_key(private_key_path, password=password)
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def sign_file(file_path, private_key_path, signature_output_path, password=None):
    data = Path(file_path).read_bytes()
    signature = sign_bytes(data, private_key_path, password=password)
    signature_output_path = Path(signature_output_path)
    signature_output_path.parent.mkdir(parents=True, exist_ok=True)
    signature_output_path.write_bytes(signature)
    return signature_output_path


def main():
    parser = argparse.ArgumentParser(description="Digitally sign a file using RSA-PSS and SHA-256.")
    parser.add_argument("--file", required=True, help="File to sign")
    parser.add_argument("--key", required=True, help="Private key path")
    parser.add_argument("--out", required=True, help="Signature output path")
    parser.add_argument("--password", default=None, help="Private key password if encrypted")
    args = parser.parse_args()
    out = sign_file(args.file, args.key, args.out, password=args.password)
    print(f"Signature saved to {out}")


if __name__ == "__main__":
    main()
