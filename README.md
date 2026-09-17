# CyberFileGuard v3.0

**Cybersecurity & Digital Forensics Toolkit**

CyberFileGuard is a Python-based command-line toolkit designed for cybersecurity analysis, digital forensics, evidence integrity verification, IOC extraction, log analysis, filesystem investigation, and basic security assessment workflows.

It is designed to work on **Windows, Linux, and Kali Linux** using Python's standard library without requiring external Python packages.

---

## 🚀 Features

CyberFileGuard currently provides **11 security and digital forensics modules**.

| #  | Module                        | Description                                                                               |
| -- | ----------------------------- | ----------------------------------------------------------------------------------------- |
| 1  | File Hash Analyzer            | Calculates MD5, SHA-1, SHA-256, and SHA-512 hashes                                        |
| 2  | Password Strength Analyzer    | Evaluates password length, character diversity, patterns, warnings, and estimated entropy |
| 3  | Log Analyzer                  | Detects repeated failed logins, suspicious IP addresses, and suspicious user accounts     |
| 4  | IOC Extractor                 | Extracts IP addresses, domains, URLs, emails, and file hashes                             |
| 5  | Metadata Analyzer             | Examines file metadata, timestamps, permissions, attributes, and SHA-256                  |
| 6  | Forensic Report Generator     | Generates structured JSON forensic evidence reports                                       |
| 7  | Evidence Integrity Verifier   | Verifies evidence using SHA-256 comparison                                                |
| 8  | Directory & Duplicate Scanner | Recursively scans directories and identifies duplicate files                              |
| 9  | Forensic Timeline Analyzer    | Builds a filesystem timeline using file timestamps                                        |
| 10 | IOC Exporter                  | Exports extracted IOCs to JSON and CSV                                                    |
| 11 | System Information            | Collects basic read-only system information                                               |

---

## 🛡️ Security Purpose

CyberFileGuard focuses on **defensive cybersecurity and digital forensics**.

The toolkit can be used for:

* File integrity verification
* Evidence examination
* Basic incident investigation
* IOC identification
* Authentication log analysis
* Duplicate file detection
* Filesystem timeline analysis
* Forensic report generation
* Security learning and laboratory exercises

It does **not** perform exploitation, credential theft, malware execution, or unauthorized system access.

---

## 💻 Supported Platforms

CyberFileGuard is designed for:

* Windows
* Linux
* Kali Linux

The application uses Python standard-library modules wherever possible.

---

## 📋 Requirements

### Python

Python **3.10 or newer** is recommended.

Check your Python version:

```powershell
python --version
```

On Linux/Kali:

```bash
python3 --version
```

The CyberFileGuard application itself uses only Python's standard library.
Pytest is used as a development/testing dependency and is listed in
requirements-dev.txt.
---

## 📥 Installation

Clone the repository:

```bash
git clone https://github.com/SupremeImmortal/CyberFileGuard.git
```

Enter the project directory:

```bash
cd CyberFileGuard
```

Verify Python:

```bash
python --version
```

On Linux/Kali:

```bash
python3 --version
```

---

## ▶️ Running CyberFileGuard

Windows:

```powershell
python -m cyberfileguard
```

Linux/Kali:

```bash
python3 -m cyberfileguard
```

The application displays the main menu:

```text
============================================================
                 CYBERFILEGUARD v3.0
        Cybersecurity & Digital Forensics
============================================================

[1] File Hash Analyzer
[2] Password Strength Analyzer
[3] Log Analyzer
[4] IOC Extractor
[5] Metadata Analyzer
[6] Forensic Report Generator
[7] Evidence Integrity Verifier
[8] Directory & Duplicate Scanner
[9] Forensic Timeline Analyzer
[10] IOC Exporter
[11] System Information
[12] Exit
```

---

# 🔍 Module Documentation

## 1. File Hash Analyzer

Calculates multiple cryptographic hashes from the original file bytes.

Supported algorithms:

* MD5
* SHA-1
* SHA-256
* SHA-512

Example:

```text
Select an option: 1

Enter the file path: samples\sample.log
```

The analyzer displays:

* File name
* File size
* File type
* Extension
* Cryptographic hashes

Hashes can be used to verify whether a file has changed.

---

## 2. Password Strength Analyzer

Analyzes a password without storing it.

The module evaluates:

* Password length
* Lowercase characters
* Uppercase characters
* Numbers
* Special characters
* Common passwords
* Repeated characters
* Sequential patterns
* Estimated entropy

Example:

```text
Select an option: 2

Enter a password to analyze:
```

The password is entered using a hidden input prompt.

### Important

Entropy is an estimate based on the detected character pool. It should not be interpreted as an exact prediction of password cracking time.

---

## 3. Log Analyzer

Analyzes authentication logs for repeated failed login activity.

It can identify:

* Failed login attempts
* Successful login attempts
* Repeated failed IP addresses
* Repeated failed user accounts
* Successful login sources
* Authentication statistics

Example:

```text
Select an option: 3

Enter the log file path: samples\sample.log
```

The module uses a configurable detection threshold.

---

## 4. IOC Extractor

Extracts common Indicators of Compromise (IOCs) from text files.

Supported IOC categories:

* IPv4 addresses
* IPv6 addresses
* Domains
* URLs
* Email addresses
* MD5 hashes
* SHA-1 hashes
* SHA-256 hashes

Example:

```text
Select an option: 4

Enter the file path: samples\ioc_sample.txt
```

The module removes duplicate values and displays unique IOCs.

---

## 5. Metadata Analyzer

Examines filesystem metadata for a selected file.

Collected information includes:

* File name
* Absolute path
* Extension
* File size
* MIME type
* Encoding
* Timestamps
* Permission mode
* Readable status
* Writable status
* Executable status
* Hidden attribute
* SHA-256 hash

Example:

```text
Select an option: 5

Enter the file path: samples\sample.log
```

### Timestamp Consideration

Filesystem timestamp semantics differ between operating systems.

On Windows, `st_ctime` commonly represents file creation time.

On Linux/Unix, `st_ctime` represents filesystem metadata change time rather than creation time.

---

## 6. Forensic Report Generator

Creates a structured JSON forensic evidence report.

The report contains:

* Tool information
* Evidence ID
* File information
* File size
* Permissions
* Filesystem timestamps
* MD5
* SHA-1
* SHA-256
* SHA-512
* Integrity information
* Investigation status
* Chain-of-custody entry
* Report generation timestamp

Example:

```text
Select an option: 6

Enter the file path: samples\sample.log
```

Reports are generated inside:

```text
reports/
```

Generated reports are intentionally excluded from Git using `.gitignore`.

---

## 7. Evidence Integrity Verifier

Verifies whether a file matches a previously recorded SHA-256 hash.

Example workflow:

First calculate the hash:

```powershell
Get-FileHash samples\sample.log -Algorithm SHA256
```

Copy the SHA-256 value.

Then run:

```text
Select an option: 7

Enter the file path: samples\sample.log
Enter the expected SHA-256 hash:
```

The tool calculates the current SHA-256 and compares it with the expected value.

Possible results:

```text
[+] INTEGRITY VERIFIED
```

or:

```text
[!] INTEGRITY CHECK FAILED
```

This can be useful when validating forensic evidence against a previously recorded hash.

---

## 8. Directory & Duplicate Scanner

Recursively scans a directory and calculates SHA-256 hashes for files.

It reports:

* Total files found
* Files successfully scanned
* Failed files
* Unique hashes
* Duplicate groups
* Duplicate files

Example:

```text
Select an option: 8

Enter the directory path: samples
```

Files with identical SHA-256 hashes are grouped together as duplicates.

---

## 9. Forensic Timeline Analyzer

Builds a basic filesystem timeline by collecting timestamps from files.

The analyzer records:

* File path
* Modified time
* Accessed time
* Changed/creation-related timestamp depending on OS

Files are displayed from newest modification time to oldest.

Example:

```text
Select an option: 9

Enter the directory path: samples
```

### Forensic Note

Timestamp interpretation depends on the operating system. Investigators should preserve original evidence and avoid treating timestamps alone as proof of an event.

---

## 10. IOC Exporter

Extracts IOCs and exports them into structured files.

Output formats:

```text
JSON
CSV
```

Example:

```text
Select an option: 10

Enter the file path: samples\ioc_sample.txt
```

Generated files:

```text
reports/ioc_export.json
reports/ioc_export.csv
```

The exported data contains IOC categories and their values.

---

## 11. System Information

Collects basic read-only system information using Python standard-library APIs.

Information includes:

* Operating system
* OS release
* OS version
* Architecture
* Processor
* Hostname
* Username
* Python version
* Python implementation
* CPU count
* Current working directory
* Collection timestamp

Example:

```text
Select an option: 11
```

### Privacy Note

System information can contain identifying information such as usernames, hostnames, and filesystem paths.

Review this information before sharing reports publicly.

---

# 📁 Project Structure

```text
CyberFileGuard/
│
├── cyberfileguard/
│   ├── __init__.py
│   ├── __main__.py
│   ├── hash_analyzer.py
│   ├── password_checker.py
│   ├── log_analyzer.py
│   ├── ioc_extractor.py
│   ├── metadata_analyzer.py
│   ├── report_generator.py
│   ├── integrity_verifier.py
│   ├── duplicate_scanner.py
│   ├── timeline_analyzer.py
│   ├── ioc_exporter.py
│   └── system_info.py
│
├── reports/
│
├── samples/
│   ├── sample.log
│   └── ioc_sample.txt
│
├── .gitignore
└── README.md
```

---

# 🧪 Sample Files

The project includes sample files for testing.

### `samples/sample.log`

Used for authentication log analysis.

Example events include:

* Failed login attempts
* Successful login attempts
* Different users
* Different IP addresses

### `samples/ioc_sample.txt`

Used for testing IOC extraction and IOC export functionality.

---

# 🧪 Testing

Basic syntax verification can be performed with:

```powershell
python -m compileall cyberfileguard
```

Linux/Kali:

```bash
python3 -m compileall cyberfileguard
```

The application can then be tested through:

```powershell
python -m cyberfileguard
```

Test each menu option using the provided sample files.

---

# 🔐 Security Design

CyberFileGuard follows several basic defensive-security principles:

### Read-Only Analysis

Most modules analyze existing files and directories without modifying the evidence being examined.

### Hash-Based Integrity

SHA-256 is used for evidence integrity verification and duplicate detection.

### No Malware Execution

CyberFileGuard does not execute files being analyzed.

### No Credential Storage

Password analysis is performed locally and passwords are not intentionally stored.

### Defensive Purpose

The toolkit is intended for authorized cybersecurity, digital forensics, education, and laboratory environments.

---

# ⚠️ Limitations

CyberFileGuard is an educational and portfolio-oriented forensic toolkit and should not be considered a replacement for enterprise forensic platforms.

Current limitations include:

* IOC extraction uses pattern matching and may produce false positives.
* Log analysis currently supports specific authentication log formats.
* Filesystem timestamps depend on operating-system semantics.
* Password entropy is only an estimate.
* Metadata analysis is based primarily on standard filesystem information.
* No commercial threat-intelligence database is included.
* No automated malware execution or sandboxing is provided.
* No enterprise-scale distributed processing is implemented.
* Chain-of-custody functionality is currently basic and should not be treated as a complete legal evidence-management system.

---

# 🔮 Future Development

Potential future improvements include:

* Additional log formats
* More forensic artifact parsers
* PCAP analysis
* YARA integration
* SQLite evidence database
* Advanced timeline correlation
* File type identification
* Archive analysis
* Browser artifact analysis
* Windows event log analysis
* Linux authentication log support
* Plugin architecture
* Additional report formats
* Improved forensic chain-of-custody management

Future features should maintain the project's defensive and forensic focus.

---

# 🧰 Technologies

CyberFileGuard currently uses:

* Python
* Python Standard Library
* `hashlib`
* `pathlib`
* `re`
* `ipaddress`
* `json`
* `csv`
* `datetime`
* `platform`
* `os`
* `stat`
* `getpass`
* `collections`
* `uuid`
* `mimetypes`

No external Python dependencies are currently required.

---

# 🎓 Educational Use

CyberFileGuard is suitable for learning and practicing:

* Cybersecurity fundamentals
* Digital forensics
* File integrity verification
* Cryptographic hashing
* IOC analysis
* Log analysis
* Filesystem investigation
* Evidence handling concepts
* Python security automation

It can also serve as a cybersecurity and digital-forensics portfolio project.

---

# 📌 Project Status

**CyberFileGuard v3.0**

Current status:


- Core CLI implemented
- 11 security/forensic modules implemented
- Windows support tested
- Linux/Kali compatibility targeted
- Sample investigation files included
- JSON forensic reporting implemented
- IOC JSON/CSV export implemented
- SHA-256 integrity verification implemented
- Directory duplicate detection implemented
- Filesystem timeline analysis implemented
- System information collection implemented
- Automated pytest test suite implemented
- 5 automated tests currently passing
- GitHub Actions CI workflow implemented
- Python module compilation checked through CI
---

# ⚖️ Disclaimer

CyberFileGuard is provided for **authorized cybersecurity research, digital forensics education, defensive security analysis, and laboratory use**.

Only analyze systems, files, logs, and evidence that you own or have explicit authorization to examine.

The author is not responsible for misuse of this software.

---

# 📄 License

This project is currently intended as an educational and portfolio project.

A formal open-source license can be added to the repository in a future release.

---

# 👨‍💻 Author

**SupremeImmortal**

Cybersecurity & Digital Forensics Student

GitHub:

https://github.com/SupremeImmortal

---

## ⭐ CyberFileGuard

A practical Python toolkit for learning and demonstrating **cybersecurity, digital forensics, evidence integrity, IOC analysis, and security automation**.
