import re

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"<img[^>]*src\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<a[^>]*href\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<iframe[^>]*src\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<object[^>]*data\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<embed[^>]*src\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<link[^>]*rel\s*=\s*['\"]stylesheet['\"][^>]*>",
    r"<base[^>]*href\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<meta[^>]*http-equiv\s*=\s*['\"]refresh['\"][^>]*url\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<form[^>]*action\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<input[^>]*type\s*=\s*['\"]image['\"][^>]*src\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<button[^>]*onclick\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<div[^>]*onload\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<span[^>]*onmouseover\s*=\s*['\"]javascript:.*?['\"][^>]*>",
    r"<p[^>]*onmouseout\s*=\s*['\"]javascript:.*?['\"][^>)*]",
    r"<h1[^>]*onfocus\s*=\\'\"javascript:.*?\\'\"[^\"]*>",
]

def detect_xss(input_text: str) -> bool:
    normalized = re.sub(r"/\*.*?\*/", " ", input_text, flags=re.DOTALL)
    for pattern in XSS_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return True
    return False