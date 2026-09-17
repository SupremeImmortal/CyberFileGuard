from getpass import getpass

from .hash_analyzer import calculate_hashes
from .password_checker import check_password
from .log_analyzer import analyze_log
from .ioc_extractor import extract_iocs
from .metadata_analyzer import analyze_metadata
from .report_generator import generate_report
from .integrity_verifier import verify_integrity
from .duplicate_scanner import scan_directory
from .timeline_analyzer import analyze_timeline
from .ioc_exporter import export_iocs
from .system_info import collect_system_info


def show_banner():
    print("=" * 60)
    print("                 CYBERFILEGUARD v3.0")
    print("        Cybersecurity & Digital Forensics")
    print("=" * 60)


def show_menu():
    print("\n[1] File Hash Analyzer")
    print("[2] Password Strength Analyzer")
    print("[3] Log Analyzer")
    print("[4] IOC Extractor")
    print("[5] Metadata Analyzer")
    print("[6] Forensic Report Generator")
    print("[7] Evidence Integrity Verifier")
    print("[8] Directory & Duplicate Scanner")
    print("[9] Forensic Timeline Analyzer")
    print("[10] IOC Exporter")
    print("[11] System Information")
    print("[12] Exit")


def main():
    show_banner()

    while True:
        show_menu()

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            file_path = input("\nEnter the file path: ").strip()
            calculate_hashes(file_path)

        elif choice == "2":
            password = getpass("\nEnter a password to analyze: ")
            check_password(password)

        elif choice == "3":
            log_path = input("\nEnter the log file path: ").strip()
            analyze_log(log_path)

        elif choice == "4":
            file_path = input("\nEnter the file path: ").strip()
            extract_iocs(file_path)

        elif choice == "5":
            file_path = input("\nEnter the file path: ").strip()
            analyze_metadata(file_path)

        elif choice == "6":
            file_path = input("\nEnter the file path: ").strip()
            generate_report(file_path)

        elif choice == "7":
            file_path = input("\nEnter the file path: ").strip()
            verify_integrity(file_path)

        elif choice == "8":
            directory_path = input(
                "\nEnter the directory path: "
            ).strip()
            scan_directory(directory_path)

        elif choice == "9":
            directory_path = input(
                "\nEnter the directory path: "
            ).strip()
            analyze_timeline(directory_path)

        elif choice == "10":
            file_path = input("\nEnter the file path: ").strip()
            export_iocs(file_path)

        elif choice == "11":
            collect_system_info()

        elif choice == "12":
            print("\nExiting CyberFileGuard...")
            break

        else:
            print("\n[!] Invalid option. Please select 1-12.")


if __name__ == "__main__":
    main()