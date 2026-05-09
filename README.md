# OpenSSL Data Protection System

A complete Python and Streamlit project that demonstrates real PKI concepts with a local Certificate Authority, signed server/client certificates, hybrid encryption, digital signatures, file hashing, and mutual TLS client-server communication.

## Features

- Root CA certificate and private key generation
- Server and client certificates signed by the CA
- Certificate inspection and human-readable certificate reports
- Hybrid encryption with RSA-OAEP and AES-256-CBC
- RSA-PSS digital signatures with SHA-256
- Hashing and integrity checks with MD5, SHA-1, SHA-256, and SHA-512
- Mutual TLS server and client using Python ssl and socket
- Streamlit dashboard with four tabs:
  - Certificate Manager
  - Encrypt and Decrypt
  - Sign and Verify
  - Hash and Integrity

## Project Structure

```text
openssl-data-protection/
|-- ca/
|   |-- ca.key
|   |-- ca.crt
|-- server/
|   |-- server.key
|   |-- server.csr
|   |-- server.crt
|   |-- server.py
|-- client/
|   |-- client.key
|   |-- client.csr
|   |-- client.crt
|   |-- client.py
|-- src/
|   |-- common.py
|   |-- generate_certificates.py
|   |-- inspect_cert.py
|   |-- encrypt.py
|   |-- decrypt.py
|   |-- sign.py
|   |-- verify.py
|   |-- hash_data.py
|-- data/
|   |-- sample.txt
|-- outputs/
|   |-- cert_info.txt
|-- streamlit_app.py
|-- requirements.txt
`-- README.md
```

Certificate and output files are generated when you run the certificate generation command.

## Setup

Use Python 3.10 or newer.

```bash
cd openssl-data-protection
python -m venv venv
```

On Windows:

```bash
venv\Scripts\activate
```

On macOS or Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

This project does not use Plotly, so you do not need to install it.

## Running the Project

### 1. Generate all certificates

```bash
python src/generate_certificates.py
```

This creates:

- `ca/ca.key` and `ca/ca.crt`
- `server/server.key`, `server/server.csr`, and `server/server.crt`
- `client/client.key`, `client/client.csr`, and `client/client.crt`

The CA private key is encrypted with the default password `changeit`. You can override it:

```bash
python src/generate_certificates.py --ca-password YourStrongPassword
```

### 2. Inspect a certificate

```bash
python src/inspect_cert.py --cert server/server.crt
```

The human-readable report is saved to:

```text
outputs/cert_info.txt
```

### 3. Encrypt and decrypt a file

```bash
python src/encrypt.py --input data/sample.txt --output data/encrypted.bin --cert server/server.crt
python src/decrypt.py --input data/encrypted.bin --output data/decrypted.txt --key server/server.key
```

### 4. Sign and verify a file

```bash
python src/sign.py --file data/sample.txt --key server/server.key --out data/signature.sig
python src/verify.py --file data/sample.txt --sig data/signature.sig --cert server/server.crt
```

Tamper test:

1. Edit `data/sample.txt` after signing it.
2. Run the verification command again.
3. It should print that the signature is invalid.

### 5. Hash a file

```bash
python src/hash_data.py --file data/sample.txt --algo sha256
```

Verify a hash:

```bash
python src/hash_data.py --verify data/sample.txt --hash YOUR_EXPECTED_HASH --algo sha256
```

Compare two files:

```bash
python src/hash_data.py --compare data/sample.txt data/decrypted.txt
```

### 6. Run the mutual TLS server and client

Open terminal 1:

```bash
python server/server.py
```

Open terminal 2:

```bash
python client/client.py
```

Expected client output looks like:

```text
[CLIENT] Connected. TLS: TLSv1.3, Cipher: (...)
[CLIENT] Server replied: Message received securely.
```

### 7. Launch the Streamlit dashboard

```bash
streamlit run streamlit_app.py
```

The Streamlit UI lets you generate certificates, inspect certificates, encrypt/decrypt files, sign/verify files, and compute/compare hashes.

## Security Notes

### Why RSA 4096 for CA and RSA 2048 for server/client?

The CA key is long-lived and signs other certificates, so it is a high-value target. A 4096-bit RSA key provides a stronger security margin for that root key. Server and client certificates are shorter-lived and can be rotated more often, so RSA 2048 is a practical balance between security and performance for this demo.

### Why hybrid encryption instead of RSA-only?

RSA is not designed to encrypt large files directly. With RSA 2048 and OAEP padding, only a small amount of data can be encrypted. Hybrid encryption solves this by using AES-256 to encrypt the file data efficiently, then using RSA to encrypt only the random AES key.

### Why SHA-256 for signatures and not MD5 or SHA-1?

MD5 and SHA-1 are no longer safe for cryptographic signatures because practical collision attacks exist. SHA-256 is the modern baseline used here for certificate signatures, file signatures, and integrity checks.

### What is mutual TLS?

In normal TLS, the client authenticates the server certificate. In mutual TLS, both sides authenticate each other. The server presents a certificate to the client, and the client also presents a certificate to the server. This is common in internal services, zero-trust systems, and service-to-service authentication.

### What is a CSR?

A Certificate Signing Request contains a public key and identity information such as common name and organization. The CA signs the CSR to create a certificate, proving that the certificate was issued by a trusted authority.


author
Ahmad sobeh
ahmadaymansobeh@gmail.com
