from pathlib import Path
import hashlib
import tempfile
import os
import sys

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.generate_certificates import generate_all_certificates
from src.inspect_cert import inspect_certificate
from src.encrypt import encrypt_bytes
from src.decrypt import decrypt_bytes
from src.sign import sign_bytes
from src.verify import verify_signature

CA_CERT = PROJECT_ROOT / "ca" / "ca.crt"
SERVER_CERT = PROJECT_ROOT / "server" / "server.crt"
CLIENT_CERT = PROJECT_ROOT / "client" / "client.crt"
SERVER_KEY = PROJECT_ROOT / "server" / "server.key"
CLIENT_KEY = PROJECT_ROOT / "client" / "client.key"

CERT_CHOICES = {
    "Server certificate": SERVER_CERT,
    "Client certificate": CLIENT_CERT,
}
KEY_CHOICES = {
    "Server private key": SERVER_KEY,
    "Client private key": CLIENT_KEY,
}

st.set_page_config(page_title="OpenSSL Data Protection", page_icon="lock", layout="wide")
st.title("OpenSSL Data Protection System")
st.caption("PKI certificates, hybrid encryption, digital signatures, hashes, and mutual TLS demo.")


def certs_ready():
    return all(path.exists() for path in [CA_CERT, SERVER_CERT, CLIENT_CERT, SERVER_KEY, CLIENT_KEY])


def write_temp_file(uploaded_file, suffix=""):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(uploaded_file.getvalue())
    tmp.close()
    return Path(tmp.name)


def compute_hash(data, algorithm):
    algorithm = algorithm.lower().replace("-", "")
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def show_cert_table():
    rows = []
    for name, path in [
        ("Root CA", CA_CERT),
        ("Server Certificate", SERVER_CERT),
        ("Client Certificate", CLIENT_CERT),
    ]:
        if not path.exists():
            rows.append({"Name": name, "Issued By": "Missing", "Valid From": "Missing", "Valid Until": "Missing", "Status": "Missing"})
            continue
        try:
            info, _ = inspect_certificate(path)
            rows.append(
                {
                    "Name": name,
                    "Issued By": info["Issuer"],
                    "Valid From": info["Valid From"],
                    "Valid Until": info["Valid Until"],
                    "Status": info["Status"],
                }
            )
        except Exception as exc:
            rows.append({"Name": name, "Issued By": "Error", "Valid From": "Error", "Valid Until": "Error", "Status": str(exc)})
    st.table(rows)


def require_certificates():
    if not certs_ready():
        st.warning("Certificates and keys are missing. Open the Certificate Manager tab and click Generate All Certificates first.")
        return False
    return True


tab1, tab2, tab3, tab4 = st.tabs([
    "Certificate Manager",
    "Encrypt and Decrypt",
    "Sign and Verify",
    "Hash and Integrity",
])

with tab1:
    st.header("Certificate Manager")
    col1, col2 = st.columns([1, 2])
    with col1:
        if st.button("Generate All Certificates", type="primary"):
            try:
                result = generate_all_certificates(PROJECT_ROOT, overwrite=True)
                st.success(result["message"])
            except Exception as exc:
                st.error(f"Certificate generation failed: {exc}")
    with col2:
        st.code("MyProject Root CA\n|-- Server Certificate\n`-- Client Certificate", language="text")

    st.subheader("Certificate Status")
    show_cert_table()

    st.subheader("Inspect Certificate")
    uploaded_cert = st.file_uploader("Upload a PEM certificate (.crt)", type=["crt", "pem"], key="inspect_cert")
    if uploaded_cert:
        temp_path = write_temp_file(uploaded_cert, suffix=".crt")
        try:
            _, text = inspect_certificate(temp_path)
            st.text(text)
        except Exception as exc:
            st.error(f"Could not inspect certificate: {exc}")
        finally:
            temp_path.unlink(missing_ok=True)

with tab2:
    st.header("Encrypt and Decrypt")
    if require_certificates():
        left, right = st.columns(2)

        with left:
            st.subheader("Encrypt a File")
            plain_upload = st.file_uploader("Upload plaintext file", key="plain_upload")
            cert_label = st.selectbox("Encrypt for recipient", list(CERT_CHOICES.keys()), key="cert_encrypt")
            if plain_upload and st.button("Encrypt File"):
                try:
                    encrypted = encrypt_bytes(plain_upload.getvalue(), CERT_CHOICES[cert_label])
                    st.info(f"Original size: {plain_upload.size} bytes")
                    st.info(f"Encrypted size: {len(encrypted)} bytes")
                    st.download_button(
                        "Download encrypted.bin",
                        data=encrypted,
                        file_name="encrypted.bin",
                        mime="application/octet-stream",
                    )
                except Exception as exc:
                    st.error(f"Encryption failed: {exc}")

        with right:
            st.subheader("Decrypt a File")
            encrypted_upload = st.file_uploader("Upload encrypted.bin", key="encrypted_upload")
            key_label = st.selectbox("Private key to decrypt with", list(KEY_CHOICES.keys()), key="key_decrypt")
            if encrypted_upload and st.button("Decrypt File"):
                try:
                    plaintext = decrypt_bytes(encrypted_upload.getvalue(), KEY_CHOICES[key_label])
                    st.info(f"Encrypted size: {encrypted_upload.size} bytes")
                    st.info(f"Decrypted size: {len(plaintext)} bytes")
                    st.download_button(
                        "Download decrypted file",
                        data=plaintext,
                        file_name="decrypted_output.txt",
                        mime="application/octet-stream",
                    )
                except Exception as exc:
                    st.error(f"Decryption failed. Check that you selected the matching private key. Details: {exc}")

with tab3:
    st.header("Sign and Verify")
    if require_certificates():
        left, right = st.columns(2)

        with left:
            st.subheader("Sign a File")
            file_to_sign = st.file_uploader("Upload file to sign", key="file_to_sign")
            sign_key_label = st.selectbox("Signing private key", list(KEY_CHOICES.keys()), key="sign_key")
            if file_to_sign and st.button("Sign File"):
                try:
                    signature = sign_bytes(file_to_sign.getvalue(), KEY_CHOICES[sign_key_label])
                    st.download_button(
                        "Download signature.sig",
                        data=signature,
                        file_name="signature.sig",
                        mime="application/octet-stream",
                    )
                except Exception as exc:
                    st.error(f"Signing failed: {exc}")

        with right:
            st.subheader("Verify Signature")
            verify_file = st.file_uploader("Upload original file", key="verify_file")
            signature_file = st.file_uploader("Upload signature.sig", key="signature_file")
            verify_cert_label = st.selectbox("Signer certificate", list(CERT_CHOICES.keys()), key="verify_cert")
            if verify_file and signature_file and st.button("Verify Signature"):
                file_path = write_temp_file(verify_file)
                sig_path = write_temp_file(signature_file, suffix=".sig")
                try:
                    valid = verify_signature(file_path, sig_path, CERT_CHOICES[verify_cert_label])
                    if valid:
                        st.success("Signature is VALID - file is authentic and untampered.")
                    else:
                        st.error("Signature is INVALID - file may have been tampered with.")
                except Exception as exc:
                    st.error(f"Verification failed: {exc}")
                finally:
                    file_path.unlink(missing_ok=True)
                    sig_path.unlink(missing_ok=True)

with tab4:
    st.header("Hash and Integrity")
    st.subheader("Compute and Verify a Hash")
    hash_upload = st.file_uploader("Upload a file to hash", key="hash_upload")
    algorithm = st.selectbox("Algorithm", ["md5", "sha1", "sha256", "sha512"], index=2)
    if hash_upload:
        digest = compute_hash(hash_upload.getvalue(), algorithm)
        st.code(digest, language="text")
        expected_hash = st.text_input("Paste expected hash to verify")
        if expected_hash and st.button("Verify Integrity"):
            if digest.lower() == expected_hash.lower().strip():
                st.success("Hash VALID - file integrity verified.")
            else:
                st.error("Hash INVALID - file changed or expected hash is wrong.")

    st.subheader("Compare Two Files")
    c1, c2 = st.columns(2)
    with c1:
        file_a = st.file_uploader("Upload first file", key="compare_a")
    with c2:
        file_b = st.file_uploader("Upload second file", key="compare_b")
    if file_a and file_b and st.button("Compare Files"):
        hash_a = compute_hash(file_a.getvalue(), "sha256")
        hash_b = compute_hash(file_b.getvalue(), "sha256")
        if hash_a == hash_b:
            st.success("Files match. SHA-256 hashes are identical.")
        else:
            st.error("Files do not match. SHA-256 hashes are different.")
        st.write("File 1 SHA-256:")
        st.code(hash_a, language="text")
        st.write("File 2 SHA-256:")
        st.code(hash_b, language="text")
