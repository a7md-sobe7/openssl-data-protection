from pathlib import Path
import os
from cryptography.hazmat.primitives import serialization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CA_DIR = PROJECT_ROOT / "ca"
SERVER_DIR = PROJECT_ROOT / "server"
CLIENT_DIR = PROJECT_ROOT / "client"
SRC_DIR = PROJECT_ROOT / "src"
DATA_DIR = PROJECT_ROOT / "data"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"

DEFAULT_CA_PASSWORD = os.environ.get("CA_KEY_PASSWORD", "changeit").encode("utf-8")


def ensure_project_dirs(root: Path = PROJECT_ROOT) -> None:
    for folder in ["ca", "server", "client", "src", "data", "outputs"]:
        (root / folder).mkdir(parents=True, exist_ok=True)


def load_private_key(path, password=None):
    path = Path(path)
    data = path.read_bytes()
    if password is not None and isinstance(password, str):
        password = password.encode("utf-8")
    return serialization.load_pem_private_key(data, password=password)


def save_private_key(key, path, password=None) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if password:
        if isinstance(password, str):
            password = password.encode("utf-8")
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        )
    )


def save_public_pem(obj, path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(obj.public_bytes(serialization.Encoding.PEM))
