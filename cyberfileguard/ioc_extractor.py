import ipaddress
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


def is_valid_ipv4(ip):
    try:
        return isinstance(
            ipaddress.ip_address(ip),
            ipaddress.IPv4Address
        )
    except ValueError:
        return False


def is_valid_ipv6(ip):
    try:
        return isinstance(
            ipaddress.ip_address(ip),
            ipaddress.IPv6Address
        )
    except ValueError:
        return False


def clean_url(url):
    return url.rstrip(".,;:!?)]}")


def extract_iocs(file_path):
    path = Path(file_path)

    if not path.exists():
        print("\n[!] File not found.")
        return

    if not path.is_file():
        print("\n[!] The selected path is not a file.")
        return

    ipv4_addresses = set()
    ipv6_addresses = set()
    urls = set()
    emails = set()
    domains = set()
    md5_hashes = set()
    sha1_hashes = set()
    sha256_hashes = set()

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line in file:

                # URLs
                for url in URL_PATTERN.findall(line):
                    urls.add(clean_url(url))

                # Email addresses
                for email in EMAIL_PATTERN.findall(line):
                    emails.add(email)

                # IPv4
                for ip in IPV4_PATTERN.findall(line):
                    if is_valid_ipv4(ip):
                        ipv4_addresses.add(ip)

                # IPv6
                for ip in IPV6_PATTERN.findall(line):
                    if is_valid_ipv6(ip):
                        ipv6_addresses.add(ip)

                # Hashes
                for value in MD5_PATTERN.findall(line):
                    md5_hashes.add(value.lower())

                for value in SHA1_PATTERN.findall(line):
                    sha1_hashes.add(value.lower())

                for value in SHA256_PATTERN.findall(line):
                    sha256_hashes.add(value.lower())

                # Domains
                for domain in DOMAIN_PATTERN.findall(line):
                    domain = domain.lower()

                    if (
                        domain not in ipv4_addresses
                        and "@" not in domain
                    ):
                        domains.add(domain)

    except PermissionError:
        print("\n[!] Permission denied.")
        return

    except OSError as error:
        print(f"\n[!] Error reading file: {error}")
        return

    # Remove domains that are actually part of email addresses
    email_domains = {
        email.split("@", 1)[1].lower()
        for email in emails
        if "@" in email
    }

    domains -= email_domains

    print("\n" + "=" * 65)
    print("                  IOC EXTRACTION v2.0")
    print("=" * 65)

    print(f"Source File : {path.name}")

    print(f"\nIPv4 Addresses ({len(ipv4_addresses)}):")
    if ipv4_addresses:
        for ip in sorted(ipv4_addresses):
            print(f"  {ip}")
    else:
        print("  None")

    print(f"\nIPv6 Addresses ({len(ipv6_addresses)}):")
    if ipv6_addresses:
        for ip in sorted(ipv6_addresses):
            print(f"  {ip}")
    else:
        print("  None")

    print(f"\nDomains ({len(domains)}):")
    if domains:
        for domain in sorted(domains):
            print(f"  {domain}")
    else:
        print("  None")

    print(f"\nURLs ({len(urls)}):")
    if urls:
        for url in sorted(urls):
            print(f"  {url}")
    else:
        print("  None")

    print(f"\nEmail Addresses ({len(emails)}):")
    if emails:
        for email in sorted(emails):
            print(f"  {email}")
    else:
        print("  None")

    print(f"\nMD5 Hashes ({len(md5_hashes)}):")
    if md5_hashes:
        for value in sorted(md5_hashes):
            print(f"  {value}")
    else:
        print("  None")

    print(f"\nSHA-1 Hashes ({len(sha1_hashes)}):")
    if sha1_hashes:
        for value in sorted(sha1_hashes):
            print(f"  {value}")
    else:
        print("  None")

    print(f"\nSHA-256 Hashes ({len(sha256_hashes)}):")
    if sha256_hashes:
        for value in sorted(sha256_hashes):
            print(f"  {value}")
    else:
        print("  None")

    total_iocs = (
        len(ipv4_addresses)
        + len(ipv6_addresses)
        + len(domains)
        + len(urls)
        + len(emails)
        + len(md5_hashes)
        + len(sha1_hashes)
        + len(sha256_hashes)
    )

    print("\n" + "-" * 65)
    print(f"Total Unique IOCs : {total_iocs}")
    print("-" * 65)

    print("=" * 65)