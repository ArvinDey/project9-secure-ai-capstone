import re

MAX_LENGTH = 500

BLOCKED_PATTERNS = [
    (
        "Instruction override",
        r"\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b",
    ),
    (
        "Role reassignment",
        r"\byou\s+are\s+now\b",
    ),
    (
        "Role-play bypass",
        r"\bpretend\s+you\s+are\b",
    ),
    (
        "Unrestricted persona",
        r"\bact\s+as\s+if\s+you\s+have\s+no\b",
    ),
    (
        "Long Base64-like string",
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])",
    ),
]

COMPILED_PATTERNS = [
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in BLOCKED_PATTERNS
]


def validate_prompt(prompt):
    """Return (valid, reason) for a user prompt."""
    if not isinstance(prompt, str) or not prompt.strip():
        return False, "Prompt must be a non-empty string."

    if len(prompt) > MAX_LENGTH:
        return False, "Prompt exceeds the 500-character limit."

    for name, pattern in COMPILED_PATTERNS:
        if pattern.search(prompt):
            return False, f"Prompt blocked: {name}."

    return True, None
