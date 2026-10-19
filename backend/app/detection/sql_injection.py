import re

# Signatures for known SQL injection patterns
SQLI_PATTERNS = [
    r"['\"]\s*--",
    r"\b(?:or|and)\s+(\d+)\s*=\s*\1\b",
    r"\b(?:or|and)\s+(['\"])([^'\"\r\n]+)\1\s*=\s*\1\2\1",
    r"\bunion\s+(?:all\s+|distinct\s+)?select\b",
    r";\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|select)\b",
    r"\b(?:pg_sleep|sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)",
    r"\bwaitfor\s+delay\s+['\"]\d{1,2}:\d{2}:\d{2}['\"]",
]


def detect_sql_injection(input_text: str) -> bool:
    normalized = re.sub(r"/\*.*?\*/", " ", input_text, flags=re.DOTALL)
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return True
    return False
