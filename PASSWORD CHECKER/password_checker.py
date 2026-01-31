import re
import math

COMMON_PASSWORDS = {"password", "123456", "qwerty", "letmein", "admin", "welcome"}

def calculate_entropy(password: str) -> float:
    charsets = 0
    if re.search(r"[a-z]", password): charsets += 26
    if re.search(r"[A-Z]", password): charsets += 26
    if re.search(r"[0-9]", password): charsets += 10
    if re.search(r"[^A-Za-z0-9]", password): charsets += 32  # approx special chars
    return round(math.log2(charsets ** len(password)), 2) if charsets else 0

def assess_password_strength(password: str) -> dict:
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")

    # Character diversity
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("Add at least one uppercase letter.")

    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("Add at least one lowercase letter.")

    if re.search(r"[0-9]", password): score += 1
    else: feedback.append("Include at least one number.")

    if re.search(r"[^A-Za-z0-9]", password): score += 1
    else: feedback.append("Include at least one special character.")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("Avoid common passwords — too easy to guess.")
        score = 0

    # Sequential/repeated pattern check
    if re.search(r"(.)\1{2,}", password):
        feedback.append("Avoid repeated characters.")
    if re.search(r"(1234|abcd|qwerty)", password.lower()):
        feedback.append("Avoid sequential patterns.")

    # Strength classification
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"

    entropy = calculate_entropy(password)

    return {
        "strength": strength,
        "score": score,
        "entropy_bits": entropy,
        "feedback": feedback
    }

# Example usage
if __name__ == "__main__":
    password = input("Enter a password to check: ")
    result = assess_password_strength(password)

    print(f"\nPassword Strength: {result['strength']}")
    print(f"Score: {result['score']}/6")
    print(f"Entropy: {result['entropy_bits']} bits")

    if result["feedback"]:
        print("Suggestions:")
        for item in result["feedback"]:
            print(f"- {item}")
    else:
        print("Excellent! Your password is strong and unique.")

