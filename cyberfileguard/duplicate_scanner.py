import hashlib
from collections import defaultdict
from pathlib import Path


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_directory(directory_path):
    directory = Path(directory_path)

    if not directory.exists():
        print("\n[!] Directory not found.")
        return

    if not directory.is_dir():
        print("\n[!] The selected path is not a directory.")
        return

    file_hashes = defaultdict(list)

    total_files = 0
    scanned_files = 0
    failed_files = 0

    print("\n" + "=" * 70)
    print("              DIRECTORY & DUPLICATE SCANNER")
    print("=" * 70)
    print(f"Directory : {directory.resolve()}")
    print("\nScanning files...")

    try:
        for file_path in directory.rglob("*"):

            if not file_path.is_file():
                continue

            total_files += 1

            try:
                file_hash = calculate_sha256(file_path)

                file_hashes[file_hash].append(file_path)
                scanned_files += 1

            except (PermissionError, OSError):
                failed_files += 1

    except OSError as error:
        print(f"\n[!] Error scanning directory: {error}")
        return

    duplicate_groups = {
        file_hash: paths
        for file_hash, paths in file_hashes.items()
        if len(paths) > 1
    }

    duplicate_files = sum(
        len(paths)
        for paths in duplicate_groups.values()
    )

    print("\n" + "-" * 70)
    print("SCAN SUMMARY")
    print("-" * 70)

    print(f"Files Found       : {total_files}")
    print(f"Files Scanned     : {scanned_files}")
    print(f"Failed Files      : {failed_files}")
    print(f"Unique Hashes     : {len(file_hashes)}")
    print(f"Duplicate Groups  : {len(duplicate_groups)}")
    print(f"Duplicate Files   : {duplicate_files}")

    print("\n" + "-" * 70)
    print("DUPLICATE FILES")
    print("-" * 70)

    if not duplicate_groups:
        print("[+] No duplicate files detected.")

    else:
        group_number = 1

        for file_hash, paths in duplicate_groups.items():

            print(f"\nGroup {group_number}")
            print(f"SHA-256 : {file_hash}")

            for path in paths:
                print(f"  {path}")

            group_number += 1

    print("\n" + "=" * 70)