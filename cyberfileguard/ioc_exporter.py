import csv
import json
import re
from pathlib import Path


IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

IPV6_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:[0-9A-Fa-f]{1,4}:){2,7}"
    r"[0-9A-Fa-f]{1,4}"
    r"(?![A-Za-z0-9])"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


def clean_url(url):
    return url.rstrip(".,;:!?)]}")


def is_valid_ipv4(ip):
    parts = ip.split(".")

    if len(parts) != 4:
        return False

    return all(
        part.isdigit() and 0 <= int(part) <= 255
        for part in parts
    )


def is_valid_ipv6(ip):
    return ":" in ip


def extract_iocs(file_path):
    path = Path(file_path)

    if not path.exists():
        print("\n[!] File not found.")
        return None

    if not path.is_file():
        print("\n[!] The selected path is not a file.")
        return None

    iocs = {
        "ipv4": set(),
        "ipv6": set(),
        "domains": set(),
        "urls": set(),
        "emails": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
    }

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line in file:

                for url in URL_PATTERN.findall(line):
                    iocs["urls"].add(clean_url(url))

                for email in EMAIL_PATTERN.findall(line):
                    iocs["emails"].add(email)

                for ip in IPV4_PATTERN.findall(line):
                    if is_valid_ipv4(ip):
                        iocs["ipv4"].add(ip)

                for ip in IPV6_PATTERN.findall(line):
                    if is_valid_ipv6(ip):
                        iocs["ipv6"].add(ip)

                for value in MD5_PATTERN.findall(line):
                    iocs["md5"].add(value.lower())

                for value in SHA1_PATTERN.findall(line):
                    iocs["sha1"].add(value.lower())

                for value in SHA256_PATTERN.findall(line):
                    iocs["sha256"].add(value.lower())

                for domain in DOMAIN_PATTERN.findall(line):
                    domain = domain.lower()

                    if (
                        domain not in iocs["ipv4"]
                        and "@" not in domain
                    ):
                        iocs["domains"].add(domain)

    except PermissionError:
        print("\n[!] Permission denied.")
        return None

    except OSError as error:
        print(f"\n[!] Error reading file: {error}")
        return None

    email_domains = {
        email.split("@", 1)[1].lower()
        for email in iocs["emails"]
        if "@" in email
    }

    iocs["domains"] -= email_domains

    return {
        key: sorted(values)
        for key, values in iocs.items()
    }


def export_iocs(file_path):
    path = Path(file_path)

    iocs = extract_iocs(path)

    if iocs is None:
        return

    export_directory = Path("reports")
    export_directory.mkdir(parents=True, exist_ok=True)

    json_path = export_directory / "ioc_export.json"
    csv_path = export_directory / "ioc_export.csv"

    total_iocs = sum(
        len(values)
        for values in iocs.values()
    )

    try:
        json_data = {
            "source_file": str(path.resolve()),
            "total_iocs": total_iocs,
            "iocs": iocs,
        }

        with json_path.open(
            "w",
            encoding="utf-8"
        ) as json_file:

            json.dump(
                json_data,
                json_file,
                indent=4
            )

        with csv_path.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as csv_file:

            writer = csv.writer(csv_file)

            writer.writerow(
                [
                    "IOC Type",
                    "IOC Value"
                ]
            )

            for ioc_type, values in iocs.items():

                for value in values:
                    writer.writerow(
                        [
                            ioc_type,
                            value
                        ]
                    )

    except OSError as error:
        print(f"\n[!] Error exporting IOCs: {error}")
        return

    print("\n" + "=" * 65)
    print("                     IOC EXPORTER")
    print("=" * 65)

    print(f"Source File : {path.name}")
    print(f"Total IOCs  : {total_iocs}")

    print("\nExported Files:")

    print(f"JSON : {json_path}")
    print(f"CSV  : {csv_path}")

    print("\n[+] IOC export completed successfully.")

    print("=" * 65)