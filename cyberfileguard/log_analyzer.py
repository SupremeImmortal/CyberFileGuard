import re
from collections import Counter
from pathlib import Path


FAILED_LOGIN_PATTERN = re.compile(
    r"LOGIN_FAILED.*?user=([^\s]+).*?ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"LOGIN_SUCCESS.*?user=([^\s]+).*?ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})"
)


def is_valid_ipv4(ip):
    parts = ip.split(".")

    if len(parts) != 4:
        return False

    return all(
        part.isdigit() and 0 <= int(part) <= 255
        for part in parts
    )


def analyze_log(file_path, threshold=3):
    path = Path(file_path)

    if not path.exists():
        print("\n[!] Log file not found.")
        return

    if not path.is_file():
        print("\n[!] The selected path is not a file.")
        return

    failed_ips = []
    successful_ips = []
    failed_users = []
    successful_users = []

    total_lines = 0
    failed_events = 0
    successful_events = 0

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line in file:
                total_lines += 1

                failed_match = FAILED_LOGIN_PATTERN.search(line)

                if failed_match:
                    user = failed_match.group(1)
                    ip = failed_match.group(2)

                    if is_valid_ipv4(ip):
                        failed_ips.append(ip)
                        failed_users.append(user)
                        failed_events += 1

                success_match = SUCCESS_LOGIN_PATTERN.search(line)

                if success_match:
                    user = success_match.group(1)
                    ip = success_match.group(2)

                    if is_valid_ipv4(ip):
                        successful_ips.append(ip)
                        successful_users.append(user)
                        successful_events += 1

    except PermissionError:
        print("\n[!] Permission denied.")
        return

    except OSError as error:
        print(f"\n[!] Error reading log: {error}")
        return

    failed_ip_counts = Counter(failed_ips)
    successful_ip_counts = Counter(successful_ips)

    failed_user_counts = Counter(failed_users)
    successful_user_counts = Counter(successful_users)

    suspicious_ips = {
        ip: count
        for ip, count in failed_ip_counts.items()
        if count >= threshold
    }

    suspicious_users = {
        user: count
        for user, count in failed_user_counts.items()
        if count >= threshold
    }

    total_events = failed_events + successful_events

    print("\n" + "=" * 65)
    print("                    LOG ANALYSIS v2.0")
    print("=" * 65)

    print(f"File                  : {path.name}")
    print(f"Total Log Lines       : {total_lines}")
    print(f"Total Authentication  : {total_events}")
    print(f"Failed Logins         : {failed_events}")
    print(f"Successful Logins     : {successful_events}")
    print(f"Unique Failed IPs     : {len(failed_ip_counts)}")
    print(f"Unique Failed Users   : {len(failed_user_counts)}")
    print(f"Detection Threshold   : {threshold}")

    print("\n" + "-" * 65)
    print("SUSPICIOUS IP ADDRESSES")
    print("-" * 65)

    if suspicious_ips:
        for ip, count in sorted(
            suspicious_ips.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"  {ip:<20} {count} failed attempts")
    else:
        print("  None detected.")

    print("\n" + "-" * 65)
    print("SUSPICIOUS USER ACCOUNTS")
    print("-" * 65)

    if suspicious_users:
        for user, count in sorted(
            suspicious_users.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"  {user:<20} {count} failed attempts")
    else:
        print("  None detected.")

    print("\n" + "-" * 65)
    print("SUCCESSFUL LOGIN SOURCES")
    print("-" * 65)

    if successful_ip_counts:
        for ip, count in sorted(
            successful_ip_counts.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"  {ip:<20} {count} successful login(s)")
    else:
        print("  None.")

    print("\n" + "-" * 65)
    print("SUCCESSFUL LOGIN ACCOUNTS")
    print("-" * 65)

    if successful_user_counts:
        for user, count in sorted(
            successful_user_counts.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"  {user:<20} {count} successful login(s)")
    else:
        print("  None.")

    print("\n" + "-" * 65)
    print("ANALYSIS SUMMARY")
    print("-" * 65)

    if suspicious_ips or suspicious_users:
        print("[!] Suspicious authentication activity detected.")
    else:
        print("[+] No authentication source exceeded the threshold.")

    print("=" * 65)