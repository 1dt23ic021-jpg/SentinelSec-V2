from modules.authentication.password_auditor import audit_password


weak_result = audit_password("password123")

strong_result = audit_password("Tr9!mQ7#vL2@xP")


assert weak_result["strength"] in {
    "Weak",
    "Moderate"
}

assert strong_result["strength"] in {
    "Strong",
    "Very Strong"
}

assert strong_result["entropy_bits"] > weak_result["entropy_bits"]

print("Password auditor test passed.")

print("\nWeak password:")
print(weak_result)

print("\nStrong password:")
print(strong_result)