"""PII validation using regex — should be detected as mathematical."""
import re

def check_email(text: str) -> bool:
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", text))

def check_ssn(text: str) -> list:
    return re.findall(r"\d{3}-\d{2}-\d{4}", text)
