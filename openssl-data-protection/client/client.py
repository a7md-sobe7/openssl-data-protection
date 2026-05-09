import argparse
import socket
import ssl
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CA_CERT = PROJECT_ROOT / "ca" / "ca.crt"
CLIENT_CERT = PROJECT_ROOT / "client" / "client.crt"
CLIENT_KEY = PROJECT_ROOT / "client" / "client.key"


def connect_to_server(host="localhost", port=8443, message="Hello, secure world!"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(CA_CERT))
    context.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))
    context.check_hostname = True

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print(f"[CLIENT] Connected. TLS: {ssock.version()}, Cipher: {ssock.cipher()}")
            ssock.sendall(message.encode("utf-8"))
            response = ssock.recv(4096).decode("utf-8", errors="replace")
            print(f"[CLIENT] Server replied: {response}")
            return response


def main():
    parser = argparse.ArgumentParser(description="Connect to the mTLS protected server.")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--message", default="Hello, secure world!")
    args = parser.parse_args()
    connect_to_server(args.host, args.port, args.message)


if __name__ == "__main__":
    main()
