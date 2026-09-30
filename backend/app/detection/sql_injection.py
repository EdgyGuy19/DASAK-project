import re

# Signatures for known SQL injection patterns
SQLI_PATTERNS = [
    r"'\s*--",
    r"(?i)'\s*or\s+1\s*=\s*1\b",
    r"(?i)'\s*;\s*drop\s+table\b",
]


def detect_sql_injection(input_text: str) -> bool:
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, input_text):
            return True

    return False