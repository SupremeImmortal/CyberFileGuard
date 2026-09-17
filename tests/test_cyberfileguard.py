import hashlib

from cyberfileguard.hash_analyzer import HASH_ALGORITHMS
from cyberfileguard.password_checker import (
    calculate_entropy,
    has_repeated_characters,
    has_sequential_pattern,
)
from cyberfileguard.ioc_exporter import extract_iocs


def test_hash_algorithms():
    test_data = b"CyberFileGuard"

    expected = {
        "MD5": hashlib.md5(test_data).hexdigest(),
        "SHA-1": hashlib.sha1(test_data).hexdigest(),
        "SHA-256": hashlib.sha256(test_data).hexdigest(),
        "SHA-512": hashlib.sha512(test_data).hexdigest(),
    }

    for name, algorithm in HASH_ALGORITHMS.items():
        hash_object = algorithm()
        hash_object.update(test_data)

        assert hash_object.hexdigest() == expected[name]


def test_password_entropy():
    weak_entropy = calculate_entropy("password")
    strong_entropy = calculate_entropy("CyberFileGuard2026!")

    assert weak_entropy > 0
    assert strong_entropy > weak_entropy


def test_repeated_characters():
    assert has_repeated_characters("aaa")
    assert has_repeated_characters("password111")
    assert not has_repeated_characters("CyberFileGuard")


def test_sequential_pattern():
    assert has_sequential_pattern("abc123")
    assert has_sequential_pattern("987")
    assert not has_sequential_pattern("CyberFileGuard")


def test_ioc_extraction(tmp_path):
    sample_file = tmp_path / "ioc_test.txt"

    sample_file.write_text(
        """
        Suspicious IP: 192.168.1.100
        Domain: malicious-example.com
        URL: https://malicious-example.com/login
        Email: analyst@securitylab.org
        MD5: 5d41402abc4b2a76b9719d911017c592
        """,
        encoding="utf-8",
    )

    iocs = extract_iocs(sample_file)

    assert "192.168.1.100" in iocs["ipv4"]
    assert "malicious-example.com" in iocs["domains"]
    assert "https://malicious-example.com/login" in iocs["urls"]
    assert "analyst@securitylab.org" in iocs["emails"]
    assert "5d41402abc4b2a76b9719d911017c592" in iocs["md5"]