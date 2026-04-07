import re

# Patterns that suggest a secret value follows — redact the value part.
_REDACT_ASSIGN_RE = re.compile(
    r"(?i)"
    r"((?:secret|password|passwd|token|api[_\-]?key|access[_\-]?key|"
    r"private[_\-]?key|auth[_\-]?token|credential|client[_\-]?secret)"
    r"[^=\s]*\s*=\s*)(\S+)"
)
# "Secret: <value>" and "Match: <value>" labels used by Gitleaks / DD descriptions.
_REDACT_LABEL_RE = re.compile(r"(?i)((?:secret|match):\s*)(\S+)")


def redact(text: str) -> str:
    """Replace secret values in text with [REDACTED]."""
    text = _REDACT_ASSIGN_RE.sub(r"\1[REDACTED]", text)
    text = _REDACT_LABEL_RE.sub(r"\1[REDACTED]", text)
    return text
