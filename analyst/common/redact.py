"""Secret redaction shared by detection, artifacts and report rendering.

Detection redacts at the source (snippets never carry a raw value). This
module is the second line of defence for text that is DERIVED from source
lines after detection, chiefly patch diffs, whose removed ('-') lines quote
the original secret. The in-memory diff is left intact because the patch loop
must apply it to the sandbox; only what is written out (artifacts, reports)
goes through scrub_text().
"""

from __future__ import annotations

import re

AWS_KEY_ID_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_SECRET_RE = re.compile(r"""aws_secret_access_key\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]""", re.IGNORECASE)
GH_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")
PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
# name = "literal" where the name suggests a credential (same shape as SECRET-005)
GENERIC_ASSIGN_RE = re.compile(
    r"""\w*(?:api[_-]?key|secret|password|token)\w*\s*(?::\s*\w+\s*)?[:=]\s*['"]([^'"]{8,})['"]""",
    re.IGNORECASE,
)


def redact_value(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}<len={len(value)}>"


def scrub_text(text: str) -> str:
    """Replace any recognisable raw secret in `text` with its redacted form.
    Idempotent: already-redacted text is left unchanged."""
    if not text:
        return text
    for rx in (AWS_KEY_ID_RE, GH_TOKEN_RE):
        text = rx.sub(lambda m: redact_value(m.group(0)), text)

    def _inner(m: re.Match) -> str:
        whole, val = m.group(0), m.group(1)
        if "<len=" in val:  # already redacted
            return whole
        return whole.replace(val, redact_value(val))

    text = AWS_SECRET_RE.sub(_inner, text)
    text = GENERIC_ASSIGN_RE.sub(_inner, text)
    return text
