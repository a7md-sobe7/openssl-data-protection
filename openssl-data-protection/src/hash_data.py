import argparse
import hashlib
from pathlib import Path

SUPPORTED = {"md5", "sha1", "sha256", "sha512"}


def hash_file(file_path, algorithm="sha256"):
    algorithm = algorithm.lower().replace("-", "")
    if algorithm not in SUPPORTED:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Choose one of {', '.join(sorted(SUPPORTED))}.")
    h = hashlib.new(algorithm)
    with Path(file_path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_hash(file_path, expected_hash, algorithm="sha256"):
    return hash_file(file_path, algorithm).lower() == expected_hash.lower().strip()


def compare_files(file1, file2):
    return hash_file(file1, "sha256") == hash_file(file2, "sha256")


def main():
    parser = argparse.ArgumentParser(description="Hash files and verify integrity.")
    parser.add_argument("--file", help="File to hash")
    parser.add_argument("--algo", default="sha256", help="Hash algorithm: md5, sha1, sha256, sha512")
    parser.add_argument("--verify", dest="verify_file", help="File to verify against --hash")
    parser.add_argument("--hash", dest="expected_hash", help="Expected hash value")
    parser.add_argument("--compare", nargs=2, metavar=("FILE1", "FILE2"), help="Compare two files by SHA-256")
    args = parser.parse_args()

    if args.compare:
        same = compare_files(args.compare[0], args.compare[1])
        print("Files are identical" if same else "Files are different")
        raise SystemExit(0 if same else 1)

    if args.verify_file:
        if not args.expected_hash:
            parser.error("--verify requires --hash")
        ok = verify_hash(args.verify_file, args.expected_hash, args.algo)
        print("Hash VALID - file integrity verified" if ok else "Hash INVALID - file changed or expected hash is wrong")
        raise SystemExit(0 if ok else 1)

    if args.file:
        print(hash_file(args.file, args.algo))
    else:
        parser.error("Use --file, --verify with --hash, or --compare FILE1 FILE2")


if __name__ == "__main__":
    main()
