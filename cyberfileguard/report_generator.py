import hashlib
import json
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path


TOOL_NAME = "CyberFileGuard"
TOOL_VERSION = "2.0"


def calculate_hashes(file_path):
    algorithms = {
        "MD5": hashlib.md5(),
        "SHA-1": hashlib.sha1(),
        "SHA-256": hashlib.sha256(),
        "SHA-512": hashlib.sha512(),
    }

    with file_path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            for hash_object in algorithms.values():
                hash_object.update(chunk)

    return {
        name: hash_object.hexdigest()
        for name, hash_object in algorithms.items()
    }


def get_permissions(path):
    try:
        return stat.filemode(path.stat().st_mode)
    except OSError:
        return "Unknown"


def generate_report(file_path):
    path = Path(file_path)

    if not path.exists():
        print("\n[!] File not found.")
        return

    if not path.is_file():
        print("\n[!] The selected path is not a file.")
        return

    try:
        stat_info = path.stat()
        hashes = calculate_hashes(path)

        evidence_id = f"CFG-{uuid.uuid4().hex[:12].upper()}"

        generated_at = datetime.now(timezone.utc).isoformat()

        report = {
            "tool": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
            },
            "report_type": "Digital Forensic Evidence Report",
            "evidence": {
                "evidence_id": evidence_id,
                "file_name": path.name,
                "absolute_path": str(path.resolve()),
                "extension": path.suffix or None,
                "size_bytes": stat_info.st_size,
                "permissions": get_permissions(path),
            },
            "timestamps": {
                "created_or_changed": datetime.fromtimestamp(
                    stat_info.st_ctime
                ).astimezone().isoformat(timespec="seconds"),
                "modified": datetime.fromtimestamp(
                    stat_info.st_mtime
                ).astimezone().isoformat(timespec="seconds"),
                "last_accessed": datetime.fromtimestamp(
                    stat_info.st_atime
                ).astimezone().isoformat(timespec="seconds"),
            },
            "cryptographic_hashes": hashes,
            "integrity": {
                "algorithm": "SHA-256",
                "sha256": hashes["SHA-256"],
                "verification_note": (
                    "Hash calculated directly from the original file bytes."
                ),
            },
            "investigation": {
                "status": "Collected",
                "investigator_notes": "",
                "chain_of_custody": [
                    {
                        "timestamp": generated_at,
                        "action": "Evidence analyzed",
                        "evidence_id": evidence_id,
                    }
                ],
            },
            "generated_at": generated_at,
        }

        reports_directory = Path("reports")
        reports_directory.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        report_path = (
            reports_directory
            / f"forensic_report_{timestamp}_{evidence_id}.json"
        )

        with report_path.open("w", encoding="utf-8") as report_file:
            json.dump(
                report,
                report_file,
                indent=4
            )

        print("\n" + "=" * 65)
        print("             FORENSIC REPORT GENERATED")
        print("=" * 65)

        print(f"Evidence ID : {evidence_id}")
        print(f"File        : {path.name}")
        print(f"Size        : {stat_info.st_size:,} bytes")
        print(f"MD5         : {hashes['MD5']}")
        print(f"SHA-1       : {hashes['SHA-1']}")
        print(f"SHA-256     : {hashes['SHA-256']}")
        print(f"SHA-512     : {hashes['SHA-512']}")
        print(f"Report      : {report_path}")

        print("=" * 65)

    except PermissionError:
        print("\n[!] Permission denied.")

    except OSError as error:
        print(f"\n[!] Error generating report: {error}")