import argparse
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

try:
    from .common import DEFAULT_CA_PASSWORD, PROJECT_ROOT, ensure_project_dirs, save_private_key, save_public_pem
except ImportError:
    from common import DEFAULT_CA_PASSWORD, PROJECT_ROOT, ensure_project_dirs, save_private_key, save_public_pem


def _utc_now():
    return dt.datetime.now(dt.timezone.utc)


def _name(common_name, organization="MyProject"):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EG"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Assiut"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def generate_private_key(key_size):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def create_ca_certificate(ca_key):
    now = _utc_now()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EG"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Assiut"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyProject CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "MyProject Root CA"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )


def create_csr(private_key, common_name, organization="MyProject", san_list=None):
    builder = x509.CertificateSigningRequestBuilder().subject_name(_name(common_name, organization))
    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)
    return builder.sign(private_key, hashes.SHA256())


def sign_csr(csr, ca_cert, ca_key, days_valid=365, usage="server"):
    now = _utc_now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
    )

    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        builder = builder.add_extension(san, critical=False)
    except x509.ExtensionNotFound:
        pass

    if usage == "server":
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    else:
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    builder = builder.add_extension(eku, critical=False)

    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def verify_signed_by_ca(child_cert, ca_cert):
    ca_cert.public_key().verify(
        child_cert.signature,
        child_cert.tbs_certificate_bytes,
        asym_padding.PKCS1v15(),
        child_cert.signature_hash_algorithm,
    )
    return True


def generate_all_certificates(project_root=PROJECT_ROOT, overwrite=True, ca_password=DEFAULT_CA_PASSWORD):
    project_root = Path(project_root)
    ensure_project_dirs(project_root)

    ca_dir = project_root / "ca"
    server_dir = project_root / "server"
    client_dir = project_root / "client"
    data_dir = project_root / "data"

    ca_key_path = ca_dir / "ca.key"
    ca_cert_path = ca_dir / "ca.crt"
    server_key_path = server_dir / "server.key"
    server_csr_path = server_dir / "server.csr"
    server_cert_path = server_dir / "server.crt"
    client_key_path = client_dir / "client.key"
    client_csr_path = client_dir / "client.csr"
    client_cert_path = client_dir / "client.crt"

    required = [ca_key_path, ca_cert_path, server_key_path, server_cert_path, client_key_path, client_cert_path]
    if not overwrite and all(path.exists() for path in required):
        return {"status": "exists", "message": "Certificates already exist. Use overwrite=True to regenerate."}

    ca_key = generate_private_key(4096)
    ca_cert = create_ca_certificate(ca_key)
    save_private_key(ca_key, ca_key_path, password=ca_password)
    save_public_pem(ca_cert, ca_cert_path)

    server_key = generate_private_key(2048)
    server_san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    server_csr = create_csr(server_key, "localhost", san_list=server_san)
    server_cert = sign_csr(server_csr, ca_cert, ca_key, usage="server")
    save_private_key(server_key, server_key_path, password=None)
    save_public_pem(server_csr, server_csr_path)
    save_public_pem(server_cert, server_cert_path)

    client_key = generate_private_key(2048)
    client_csr = create_csr(client_key, "client")
    client_cert = sign_csr(client_csr, ca_cert, ca_key, usage="client")
    save_private_key(client_key, client_key_path, password=None)
    save_public_pem(client_csr, client_csr_path)
    save_public_pem(client_cert, client_cert_path)

    verify_signed_by_ca(server_cert, ca_cert)
    verify_signed_by_ca(client_cert, ca_cert)

    sample_path = data_dir / "sample.txt"
    if overwrite or not sample_path.exists():
        sample_path.write_text(
            "Hello, secure world!\nThis file is used to test encryption, signatures, and hashes.\n",
            encoding="utf-8",
        )

    return {
        "status": "generated",
        "message": "Certificate chain verified successfully.",
        "files": [str(path.relative_to(project_root)) for path in required],
    }


def main():
    parser = argparse.ArgumentParser(description="Generate CA, server, and client certificates.")
    parser.add_argument("--root", default=str(PROJECT_ROOT), help="Project root directory")
    parser.add_argument("--no-overwrite", action="store_true", help="Do not overwrite existing certificates")
    parser.add_argument("--ca-password", default=DEFAULT_CA_PASSWORD.decode("utf-8"), help="Password for ca/ca.key")
    args = parser.parse_args()

    result = generate_all_certificates(
        project_root=Path(args.root),
        overwrite=not args.no_overwrite,
        ca_password=args.ca_password.encode("utf-8"),
    )
    print(result["message"])
    if "files" in result:
        print("Generated files:")
        for item in result["files"]:
            print(f" - {item}")


if __name__ == "__main__":
    main()
