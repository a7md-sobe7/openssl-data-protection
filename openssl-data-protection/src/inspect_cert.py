import argparse
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

try:
    from .common import OUTPUTS_DIR, PROJECT_ROOT
except ImportError:
    from common import OUTPUTS_DIR, PROJECT_ROOT


def _cert_time(cert, attr):
    utc_attr = attr + "_utc"
    value = getattr(cert, utc_attr, None)
    if value is not None:
        return value
    value = getattr(cert, attr)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value


def _name_to_string(name):
    parts = []
    order = [NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME, NameOID.COUNTRY_NAME]
    for oid in order:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            label = "CN" if oid == NameOID.COMMON_NAME else "O" if oid == NameOID.ORGANIZATION_NAME else "C"
            parts.append(f"{label}={attrs[0].value}")
    return ", ".join(parts) if parts else name.rfc4514_string()


def _format_time(value):
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_certificate(cert_path):
    cert_path = Path(cert_path)
    return x509.load_pem_x509_certificate(cert_path.read_bytes())


def inspect_certificate(cert_path, output_path=None):
    cert = load_certificate(cert_path)
    public_key = cert.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        key_algorithm = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_algorithm = "EC"
        key_size = public_key.key_size
    else:
        key_algorithm = public_key.__class__.__name__
        key_size = "unknown"

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_items = []
        for name in san_ext:
            if isinstance(name, x509.DNSName):
                san_items.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                san_items.append(f"IP:{name.value}")
            else:
                san_items.append(str(name.value))
        sans = ", ".join(san_items)
    except x509.ExtensionNotFound:
        sans = "None"

    not_before = _cert_time(cert, "not_valid_before")
    not_after = _cert_time(cert, "not_valid_after")
    now = dt.datetime.now(dt.timezone.utc)
    expired = now > not_after
    days_left = (not_after - now).days
    if expired:
        status = "Expired"
    elif days_left <= 30:
        status = "Expires within 30 days"
    else:
        status = "Valid"

    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    fingerprint = ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))

    info = {
        "Subject": _name_to_string(cert.subject),
        "Issuer": _name_to_string(cert.issuer),
        "Serial Number": format(cert.serial_number, "X"),
        "Valid From": _format_time(not_before),
        "Valid Until": _format_time(not_after),
        "Status": status,
        "Is Expired": "Yes" if expired else "No",
        "Days Left": days_left,
        "Key Algorithm": key_algorithm,
        "Key Size": f"{key_size} bits" if isinstance(key_size, int) else key_size,
        "Signature Algo": cert.signature_algorithm_oid._name,
        "SANs": sans,
        "Fingerprint SHA-256": fingerprint,
    }

    lines = [
        "============================================",
        "  Certificate Details",
        "============================================",
    ]
    width = max(len(key) for key in info.keys())
    for key, value in info.items():
        lines.append(f"{key + ':':<{width + 2}} {value}")
    lines.append("============================================")
    text = "\n".join(lines)

    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")

    return info, text


def main():
    parser = argparse.ArgumentParser(description="Inspect an X.509 certificate.")
    parser.add_argument("--cert", required=True, help="Path to a PEM certificate (.crt)")
    parser.add_argument("--out", default=str(OUTPUTS_DIR / "cert_info.txt"), help="Output text file")
    args = parser.parse_args()
    _, text = inspect_certificate(args.cert, args.out)
    print(text)
    print(f"Saved to {args.out}")


if __name__ == "__main__":
    main()
