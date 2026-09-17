import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


def verify_integrity(file_path):
    path = Path(file_path)

    if not path.exists():
        print("\n[!] File not found.")
        return

    if not path.is_file():
        print("\n[!] The selected path is not a file.")
        return

    print("\n" + "=" * 65)
    print("                 EVIDENCE INTEGRITY VERIFIER")
    print("=" * 65)

    expected_hash = input(
        "\nEnter the expected SHA-256 hash: "
    ).strip().lower()

    if len(expected_hash) != 64:
        print("\n[!] Invalid SHA-256 hash.")
        print("[!] A SHA-256 hash must contain exactly 64 hexadecimal characters.")
        return

    if any(
        character not in "0123456789abcdef"
        for character in expected_hash
    ):
        print("\n[!] Invalid SHA-256 hash.")
        print("[!] Only hexadecimal characters are allowed.")
        return

    try:
        actual_hash = calculate_sha256(path)

    except PermissionError:
        print("\n[!] Permission denied.")
        return

    except OSError as error:
        print(f"\n[!] Error reading file: {error}")
        return

    print(f"\nFile           : {path.name}")
    print(f"Expected Hash  : {expected_hash}")
    print(f"Actual Hash    : {actual_hash}")

    print("\n" + "-" * 65)

    if actual_hash == expected_hash:
        print("[+] INTEGRITY VERIFIED")
        print("[+] The calculated SHA-256 matches the expected hash.")
    else:
        print("[!] INTEGRITY CHECK FAILED")
        print("[!] The calculated SHA-256 does not match the expected hash.")

    print("-" * 65)
    print("=" * 65)