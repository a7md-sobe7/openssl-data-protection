import argparse
import socket
import ssl
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CA_CERT = PROJECT_ROOT / "ca" / "ca.crt"
SERVER_CERT = PROJECT_ROOT / "server" / "server.crt"
SERVER_KEY = PROJECT_ROOT / "server" / "server.key"


def _format_cert_subject(peer_cert):
    if not peer_cert:
        return "No certificate presented"
    parts = []
    for item in peer_cert.get("subject", []):
        for key, value in item:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else str(peer_cert)


def start_server(host="localhost", port=8443, once=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(CA_CERT))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            print(f"[SERVER] Listening on {host}:{port} with TLS...")
            while True:
                conn, addr = ssock.accept()
                with conn:
                    print(f"[SERVER] Client connected: {addr}")
                    print(f"[SERVER] TLS: {conn.version()}, Cipher: {conn.cipher()}")
                    print(f"[SERVER] Client Certificate: {_format_cert_subject(conn.getpeercert())}")
                    data = conn.recv(4096)
                    message = data.decode("utf-8", errors="replace")
                    print(f"[SERVER] Received: {message}")
                    conn.sendall(b"Message received securely.")
                if once:
                    break


def main():
    parser = argparse.ArgumentParser(description="Start an mTLS protected server.")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--once", action="store_true", help="Handle one client and exit")
    args = parser.parse_args()
    start_server(args.host, args.port, once=args.once)


if __name__ == "__main__":
    main()
