import hashlib
import mimetypes
from pathlib import Path


HASH_ALGORITHMS = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
}


def calculate_hashes(file_path):
    path = Path(file_path)

    if not path.exists():
        print("\n[!] File not found.")
        return

    if not path.is_file():
        print("\n[!] The selected path is not a file.")
        return

    try:
        file_size = path.stat().st_size
        file_type, _ = mimetypes.guess_type(path.name)

        hash_objects = {
            name: algorithm()
            for name, algorithm in HASH_ALGORITHMS.items()
        }

        with path.open("rb") as file:
            while chunk := file.read(1024 * 1024):
                for hash_object in hash_objects.values():
                    hash_object.update(chunk)

        print("\n" + "=" * 65)
        print("                    FILE HASH ANALYSIS")
        print("=" * 65)

        print(f"File Name       : {path.name}")
        print(f"File Size       : {file_size:,} bytes")
        print(f"File Type       : {file_type or 'Unknown'}")
        print(f"Extension       : {path.suffix or 'None'}")

        print("\nCryptographic Hashes:")

        for name, hash_object in hash_objects.items():
            print(f"{name:<16}: {hash_object.hexdigest()}")

        print("=" * 65)

    except PermissionError:
        print("\n[!] Permission denied. Try a file you have access to.")

    except OSError as error:
        print(f"\n[!] Unable to read the file: {error}")