from datetime import datetime
from pathlib import Path


def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).astimezone().isoformat(
        timespec="seconds"
    )


def analyze_timeline(directory_path):
    directory = Path(directory_path)

    if not directory.exists():
        print("\n[!] Directory not found.")
        return

    if not directory.is_dir():
        print("\n[!] The selected path is not a directory.")
        return

    timeline = []
    failed_files = 0

    print("\n" + "=" * 75)
    print("                    FORENSIC TIMELINE ANALYZER")
    print("=" * 75)
    print(f"Directory : {directory.resolve()}")
    print("\nCollecting filesystem timestamps...")

    try:
        for file_path in directory.rglob("*"):

            if not file_path.is_file():
                continue

            try:
                stat_info = file_path.stat()

                timeline.append(
                    {
                        "path": file_path,
                        "modified": stat_info.st_mtime,
                        "accessed": stat_info.st_atime,
                        "changed": stat_info.st_ctime,
                    }
                )

            except (PermissionError, OSError):
                failed_files += 1

    except OSError as error:
        print(f"\n[!] Error scanning directory: {error}")
        return

    timeline.sort(
        key=lambda item: item["modified"],
        reverse=True
    )

    print("\n" + "-" * 75)
    print("TIMELINE SUMMARY")
    print("-" * 75)

    print(f"Files Found   : {len(timeline)}")
    print(f"Failed Files  : {failed_files}")

    print("\n" + "-" * 75)
    print("FILE TIMELINE")
    print("-" * 75)

    if not timeline:
        print("[+] No files found.")
        print("=" * 75)
        return

    for number, entry in enumerate(timeline, start=1):

        print(f"\n[{number}] {entry['path']}")

        print(
            f"    Modified : "
            f"{format_timestamp(entry['modified'])}"
        )

        print(
            f"    Accessed : "
            f"{format_timestamp(entry['accessed'])}"
        )

        print(
            f"    Changed  : "
            f"{format_timestamp(entry['changed'])}"
        )

    print("\n" + "-" * 75)
    print("TIMELINE ORDER")
    print("-" * 75)
    print("[+] Files are displayed from newest modification to oldest.")

    print("\n[!] Timestamp note:")
    print(
        "[!] On Windows, st_ctime commonly represents creation time."
    )
    print(
        "[!] On Linux/Unix, st_ctime represents metadata change time."
    )

    print("=" * 75)