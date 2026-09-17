import hashlib
import mimetypes
import os
import stat
from datetime import datetime
from pathlib import Path


def calculate_sha256(path):
    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).astimezone().isoformat(
        timespec="seconds"
    )


def analyze_metadata(file_path):
    path = Path(file_path)

    if not path.exists():
        print("\n[!] File not found.")
        return

    if not path.is_file():
        print("\n[!] The selected path is not a file.")
        return

    try:
        stat_info = path.stat()

        file_size = stat_info.st_size
        file_type, encoding = mimetypes.guess_type(path.name)

        mode = stat_info.st_mode

        permissions = stat.filemode(mode)

        readable = os.access(path, os.R_OK)
        writable = os.access(path, os.W_OK)
        executable = os.access(path, os.X_OK)

        sha256 = calculate_sha256(path)

        # Unix hidden files normally begin with "."
        # Windows hidden attribute is checked separately where available.
        hidden = path.name.startswith(".")

        if os.name == "nt":
            try:
                import ctypes

                attributes = ctypes.windll.kernel32.GetFileAttributesW(
                    str(path)
                )

                if attributes != -1:
                    hidden = bool(attributes & 0x2)

            except (AttributeError, OSError):
                pass

        print("\n" + "=" * 65)
        print("                  FILE METADATA v2.0")
        print("=" * 65)

        print(f"Name              : {path.name}")
        print(f"Absolute Path     : {path.resolve()}")
        print(f"Extension         : {path.suffix or 'None'}")
        print(f"Size              : {file_size:,} bytes")
        print(f"MIME Type         : {file_type or 'Unknown'}")
        print(f"Encoding          : {encoding or 'Unknown'}")

        print("\nTimestamps:")
        print(f"Created           : {format_timestamp(stat_info.st_ctime)}")
        print(f"Modified          : {format_timestamp(stat_info.st_mtime)}")
        print(f"Last Accessed     : {format_timestamp(stat_info.st_atime)}")

        print("\nPermissions:")
        print(f"Permission Mode    : {permissions}")
        print(f"Readable           : {'Yes' if readable else 'No'}")
        print(f"Writable           : {'Yes' if writable else 'No'}")
        print(f"Executable         : {'Yes' if executable else 'No'}")

        print("\nFile Attributes:")
        print(f"Hidden             : {'Yes' if hidden else 'No'}")

        print("\nIntegrity:")
        print(f"SHA-256            : {sha256}")

        print("=" * 65)

    except PermissionError:
        print("\n[!] Permission denied.")

    except OSError as error:
        print(f"\n[!] Error analyzing file: {error}")

