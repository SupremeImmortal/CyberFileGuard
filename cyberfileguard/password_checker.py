import math
import string


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
    "000000",
}


def calculate_entropy(password):
    character_pool = 0

    if any(char.islower() for char in password):
        character_pool += 26

    if any(char.isupper() for char in password):
        character_pool += 26

    if any(char.isdigit() for char in password):
        character_pool += 10

    if any(char in string.punctuation for char in password):
        character_pool += len(string.punctuation)

    if character_pool == 0:
        return 0.0

    return len(password) * math.log2(character_pool)


def has_repeated_characters(password):
    if len(password) < 3:
        return False

    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return True

    return False


def has_sequential_pattern(password):
    password_lower = password.lower()

    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "9876543210",
        "zyxwvutsrqponmlkjihgfedcba",
    ]

    for sequence in sequences:
        for i in range(len(sequence) - 2):
            pattern = sequence[i:i + 3]

            if pattern in password_lower:
                return True

    return False


def check_password(password):
    score = 0
    suggestions = []
    warnings = []

    if not password:
        print("\n[!] Password cannot be empty.")
        return

    password_lower = password.lower()

    # Length
    if len(password) >= 14:
        score += 2
    elif len(password) >= 10:
        score += 1
    else:
        suggestions.append("Use at least 10 characters; 14+ is preferable.")

    # Character diversity
    if any(char.islower() for char in password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    if any(char.isupper() for char in password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    if any(char.isdigit() for char in password):
        score += 1
    else:
        suggestions.append("Add numbers.")

    if any(char in string.punctuation for char in password):
        score += 1
    else:
        suggestions.append("Add special characters.")

    # Common password detection
    if password_lower in COMMON_PASSWORDS:
        warnings.append("This password appears in the built-in common-password list.")
        score = max(0, score - 3)

    # Repeated characters
    if has_repeated_characters(password):
        warnings.append("Repeated characters detected, such as 'aaa' or '111'.")

    # Sequential characters
    if has_sequential_pattern(password):
        warnings.append("Sequential character pattern detected.")

    # Entropy estimate
    entropy = calculate_entropy(password)

    # Strength classification
    if score >= 6 and not warnings:
        strength = "STRONG"
    elif score >= 4:
        strength = "MEDIUM"
    else:
        strength = "WEAK"

    print("\n" + "=" * 60)
    print("                 PASSWORD ANALYSIS")
    print("=" * 60)

    print(f"Length       : {len(password)}")
    print(f"Score        : {score}/6")
    print(f"Entropy      : {entropy:.2f} bits")
    print(f"Strength     : {strength}")

    if warnings:
        print("\nWarnings:")

        for warning in warnings:
            print(f"- {warning}")

    if suggestions:
        print("\nRecommendations:")

        for suggestion in suggestions:
            print(f"- {suggestion}")
    else:
        print("\n[+] No basic improvements required.")

    print("\n[!] Entropy is an estimate and is not a prediction of actual cracking time.")
    print("=" * 60)