import re

CREDENTIAL_PATTERN = re.compile(
    r"\b(?:password|api_key|token)\s*=",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)


def scan_output(response_text, system_prompt, user_prompt):
    """Return (safe, reason) after checking the model's response."""
    if not isinstance(response_text, str):
        return False, "Model response was not text."

    if system_prompt and system_prompt in response_text:
        return False, "System prompt disclosure detected."

    if CREDENTIAL_PATTERN.search(response_text):
        return False, "Credential pattern detected in model response."

    response_urls = set(URL_PATTERN.findall(response_text))
    requested_urls = set(URL_PATTERN.findall(user_prompt))

    if response_urls - requested_urls:
        return False, "Unsolicited URL detected in model response."

    return True, None

