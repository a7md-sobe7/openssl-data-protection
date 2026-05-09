import argparse
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def verify_signature(file_path, signature_path, cert_path):
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    public_key = cert.public_key()
    data = Path(file_path).read_bytes()
    signature = Path(signature_path).read_bytes()
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def main():
    parser = argparse.ArgumentParser(description="Verify a digital signature using a certificate public key.")
    parser.add_argument("--file", required=True, help="Original file")
    parser.add_argument("--sig", required=True, help="Signature file")
    parser.add_argument("--cert", required=True, help="Signer certificate path")
    args = parser.parse_args()
    ok = verify_signature(args.file, args.sig, args.cert)
    if ok:
        print("Signature VALID")
    else:
        print("Signature INVALID - file may be tampered")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
