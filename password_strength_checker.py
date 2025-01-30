import re
import hashlib

# Common weak passwords (for simplicity, a short list; you can use a larger database)
COMMON_PASSWORDS = {"password", "123456", "qwerty", "letmein", "admin", "welcome"}

def check_password_strength(password: str) -> str:
    """
    Analyze the strength of a given password and return feedback.
    """
    length_score = len(password)
    
    # Check complexity
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[@$!%*?&]", password))
    
    complexity_score = sum([has_upper, has_lower, has_digit, has_special])
    
    # Check if password is common
    if password.lower() in COMMON_PASSWORDS:
        return "Weak: This is a very common password. Choose something unique."
    
    # Determine strength based on length and complexity
    if length_score >= 12 and complexity_score == 4:
        return "Strong: Excellent password! High security."
    elif length_score >= 8 and complexity_score >= 3:
        return "Moderate: Decent password, but consider adding more length or variety."
    else:
        return "Weak: Too short or lacks complexity. Improve security by using a mix of characters."

def hash_password(password: str) -> str:
    """
    Hashes the password using SHA-256 and returns the hashed value.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    """Main function to check user-entered passwords."""
    password = input("Enter a password to assess: ")
    feedback = check_password_strength(password)
    print(feedback)

    # Only hash if password is strong or moderate
    if feedback.startswith("Strong") or feedback.startswith("Moderate"):
        hashed_password = hash_password(password)
        print("Hashed Password (SHA-256):", hashed_password)

if __name__ == "__main__":
    main()
