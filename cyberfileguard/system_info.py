import getpass
import os
import platform
from datetime import datetime


def collect_system_info():
    try:
        system_info = {
            "Operating System": platform.system(),
            "OS Release": platform.release(),
            "OS Version": platform.version(),
            "Architecture": platform.machine(),
            "Processor": platform.processor() or "Unknown",
            "Hostname": platform.node(),
            "Username": getpass.getuser(),
            "Python Version": platform.python_version(),
            "Python Implementation": platform.python_implementation(),
            "CPU Count": os.cpu_count() or "Unknown",
            "Current Directory": os.getcwd(),
            "Timestamp": datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
        }

        print("\n" + "=" * 70)
        print("                  SYSTEM INFORMATION")
        print("=" * 70)

        for key, value in system_info.items():
            print(f"{key:<24}: {value}")

        print("\n" + "-" * 70)
        print("FORENSIC COLLECTION NOTE")
        print("-" * 70)

        print(
            "[+] Information collected using Python standard-library APIs."
        )
        print(
            "[+] This module performs read-only system information collection."
        )
        print(
            "[!] System information may contain identifying information."
        )
        print(
            "[!] Review sensitive fields before sharing forensic reports."
        )

        print("=" * 70)

    except OSError as error:
        print(f"\n[!] Unable to collect system information: {error}")

    except Exception as error:
        print(f"\n[!] Unexpected error: {error}")
