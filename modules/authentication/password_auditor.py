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
}


def calculate_entropy(password):
    """
    Estimate password entropy in bits based on
    the character pool used by the password.
    """

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


def audit_password(password):
    """
    Analyze password strength and return structured findings.
    """

    findings = []
    score = 0

    length = len(password)

    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        findings.append("Password is shorter than 8 characters.")

    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)

    if has_lowercase:
        score += 1
    else:
        findings.append("Add lowercase letters.")

    if has_uppercase:
        score += 1
    else:
        findings.append("Add uppercase letters.")

    if has_digit:
        score += 1
    else:
        findings.append("Add numbers.")

    if has_special:
        score += 1
    else:
        findings.append("Add special characters.")

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        findings.append("Password appears in the common-password list.")

    entropy = calculate_entropy(password)

    if entropy < 40:
        strength = "Weak"
    elif entropy < 60:
        strength = "Moderate"
    elif entropy < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    if not findings:
        findings.append("No basic password-policy issues detected.")

    return {
        "length": length,
        "entropy_bits": round(entropy, 2),
        "strength": strength,
        "score": score,
        "findings": findings,
    }