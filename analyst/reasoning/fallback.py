"""
Multi-Tier Fallback — what the system does when the LLM is not available and
when an LLM-proposed patch cannot be verified.

THE PROBLEM THIS SOLVES
-----------------------
Before this module, `analyze_finding()` caught every exception from the Groq
call and returned `confirmed=False, "LLM call failed"`. That is not a fallback —
it is data loss dressed up as a clean exit. A rate limit on the third finding of
a scan silently downgraded a real SQL injection to "not a vulnerability", and the
report looked identical to a genuinely clean scan. In a security tool, failing
*open* like that is worse than crashing, because nobody notices.

THE TIERS
---------
    T0  PRIMARY        Groq structured-output call.
    T1  RETRY          Transient failures (429 / timeout / connectivity / 5xx)
                       are retried with exponential backoff + jitter.
    T2  CIRCUIT OPEN   After N consecutive hard failures the breaker opens and
                       the rest of the run skips the LLM entirely instead of
                       paying the timeout cost per finding.
    T3  DETERMINISTIC  Local rule-based confirmation (regex re-verification +
                       static severity table) and template-generated patches.
                       No network, no key, no nondeterminism.
    T4  MANUAL REVIEW  Nothing could be verified: the finding is marked
                       MANUAL_REVIEW_REQUIRED and carries safe default
                       remediation advice for a human.

Every transition emits a FallbackNotice on the A2A bus, so a degraded run is
visibly degraded in the report and the audit chain — it never masquerades as a
healthy one.

WHY DETERMINISTIC PATCHES ARE SAFE TO OFFER
-------------------------------------------
The templates below are best-effort syntactic transforms, not a substitute for
reasoning. They are safe to propose because they go through the *same*
verification gate as LLM patches: applied to a sandbox copy, re-scanned by the
real detection engine, and rejected if the rule still fires. A bad template
fails verification and falls through to T4 — it can never reach the report as a
verified fix.
"""

from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------
class FailureClass(str, Enum):
    RATE_LIMIT = "RATE_LIMIT"        # 429 — retryable, backoff matters
    TIMEOUT = "TIMEOUT"              # read/connect timeout — retryable
    CONNECTIVITY = "CONNECTIVITY"    # DNS/socket/TLS — retryable, often fatal for the run
    SERVER = "SERVER"                # 5xx / overloaded — retryable
    AUTH = "AUTH"                    # 401/403/bad key — NOT retryable, fail fast
    QUOTA = "QUOTA"                  # hard quota exhausted — NOT retryable
    SCHEMA = "SCHEMA"                # model returned unparseable/invalid JSON
    UNKNOWN = "UNKNOWN"


# Retrying a bad API key 3 times just wastes 3 timeouts and delays the fallback.
TRANSIENT = frozenset(
    {FailureClass.RATE_LIMIT, FailureClass.TIMEOUT, FailureClass.CONNECTIVITY, FailureClass.SERVER}
)

_PATTERNS: tuple[tuple[FailureClass, re.Pattern], ...] = (
    (FailureClass.RATE_LIMIT, re.compile(r"\b429\b|rate.?limit|too many requests", re.I)),
    (FailureClass.QUOTA, re.compile(r"quota|insufficient_quota|credit balance|billing", re.I)),
    (FailureClass.AUTH, re.compile(r"\b401\b|\b403\b|unauthorized|forbidden|invalid.?api.?key|authentication", re.I)),
    (FailureClass.TIMEOUT, re.compile(r"timeout|timed out|deadline exceeded|read timed", re.I)),
    (FailureClass.CONNECTIVITY, re.compile(r"connection|getaddrinfo|dns|ssl|tls|network is unreachable|name or service", re.I)),
    (FailureClass.SERVER, re.compile(r"\b50[0234]\b|server error|overloaded|service unavailable|bad gateway", re.I)),
    (FailureClass.SCHEMA, re.compile(r"json|schema|validation|unparse|pydantic|expecting value", re.I)),
)

_STATUS_MAP = {
    401: FailureClass.AUTH,
    403: FailureClass.AUTH,
    408: FailureClass.TIMEOUT,
    429: FailureClass.RATE_LIMIT,
    500: FailureClass.SERVER,
    502: FailureClass.SERVER,
    503: FailureClass.SERVER,
    504: FailureClass.TIMEOUT,
}


def classify_llm_error(exc: BaseException) -> FailureClass:
    """Map any exception raised by the LLM client onto a FailureClass.

    Deliberately duck-typed rather than importing groq/httpx exception classes:
    `langchain_groq` wraps provider errors in its own types, and those wrapper
    types change between minor versions. Classifying on (status_code, type name,
    message) survives a dependency bump; `except groq.RateLimitError` does not.
    """
    status = getattr(exc, "status_code", None)
    if status is None:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
    if isinstance(status, int) and status in _STATUS_MAP:
        return _STATUS_MAP[status]

    haystack = f"{type(exc).__name__} {exc}"
    for failure_class, pattern in _PATTERNS:
        if pattern.search(haystack):
            return failure_class
    if isinstance(exc, TimeoutError):
        return FailureClass.TIMEOUT
    if isinstance(exc, (ConnectionError, OSError)):
        return FailureClass.CONNECTIVITY
    return FailureClass.UNKNOWN


def is_transient(failure_class: FailureClass) -> bool:
    return failure_class in TRANSIENT


def backoff_delay(attempt: int, base: float = 0.5, cap: float = 8.0, jitter: bool = True) -> float:
    """Exponential backoff with full jitter.

    Full jitter (random in [0, computed]) rather than fixed backoff: when a
    scan fires many findings in parallel and they all hit the same 429, fixed
    backoff makes every worker retry at the same instant and re-trip the limit.
    """
    delay = min(cap, base * (2 ** max(0, attempt - 1)))
    return random.uniform(0, delay) if jitter else delay


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------
@dataclass
class CircuitBreaker:
    """Stops hammering a provider that is clearly down.

    CLOSED  -> normal operation
    OPEN    -> all calls short-circuit to the deterministic tier
    HALF_OPEN -> after `reset_after`, one probe call is allowed through
    """

    failure_threshold: int = 3
    reset_after: float = 60.0

    state: str = "CLOSED"
    consecutive_failures: int = 0
    opened_at: Optional[float] = None
    last_failure: Optional[FailureClass] = None
    trip_count: int = 0

    def allows_call(self, now: Optional[float] = None) -> bool:
        if self.state == "CLOSED":
            return True
        now = now or time.time()
        if self.state == "OPEN" and self.opened_at is not None:
            if now - self.opened_at >= self.reset_after:
                self.state = "HALF_OPEN"
                return True
            return False
        # HALF_OPEN: allow the single probe.
        return True

    def record_success(self) -> None:
        self.state = "CLOSED"
        self.consecutive_failures = 0
        self.opened_at = None

    def record_failure(self, failure_class: FailureClass, now: Optional[float] = None) -> None:
        self.last_failure = failure_class
        self.consecutive_failures += 1
        # Auth/quota failures are permanent for the run — one is enough.
        hard = failure_class in (FailureClass.AUTH, FailureClass.QUOTA)
        if hard or self.consecutive_failures >= self.failure_threshold:
            if self.state != "OPEN":
                self.trip_count += 1
            self.state = "OPEN"
            self.opened_at = now or time.time()

    def describe(self) -> str:
        if self.state == "CLOSED":
            return "closed (LLM tier healthy)"
        return (
            f"{self.state.lower()} after {self.consecutive_failures} failure(s), "
            f"last={self.last_failure.value if self.last_failure else 'n/a'}"
        )


# ---------------------------------------------------------------------------
# Deterministic (T3) analysis
# ---------------------------------------------------------------------------
# Severity here is static per rule family, derived from the same OWASP mapping
# used in Document/rules.md. It is intentionally conservative: without semantic
# analysis we cannot downgrade, so we keep the rule's inherent severity.
_STATIC_SEVERITY = {
    "SQLI-001": "CRITICAL",
    "CMDINJ-001": "CRITICAL",
    "DESER-001": "HIGH",
    "PATHTRAV-001": "HIGH",
    "XSS-002": "HIGH",
    "SECRET-005": "HIGH",
}
_DEFAULT_SEVERITY = "MEDIUM"

# Paths where a match is far more likely to be a fixture than a live bug. The
# LLM normally makes this call; without it we apply the cheap syntactic filter.
_NON_PRODUCTION_PATH = re.compile(
    r"(^|/)(tests?|test_[^/]*|fixtures?|examples?|samples?|docs?|demo_app[^/]*)(/|$)", re.I
)
_SUPPRESSION = re.compile(r"#\s*(nosec|noqa|security[- ]ok)", re.I)

MANUAL_REVIEW_ADVICE = {
    "SQL Injection": (
        "Replace string-built SQL with parameterised queries (`cursor.execute(sql, params)`) "
        "or an ORM query object. Never interpolate request data into SQL text. If dynamic "
        "table/column names are genuinely required, validate them against an allow-list "
        "rather than escaping."
    ),
    "Cross-Site Scripting": (
        "Stop returning raw interpolated HTML. Render through a template engine with "
        "autoescaping on (Jinja2's default), or escape explicitly with `markupsafe.escape()` "
        "at the point of interpolation. Add a Content-Security-Policy header as defence in depth."
    ),
    "Hardcoded Secrets": (
        "Move the value into an environment variable or secret manager and read it at runtime. "
        "Treat the committed value as compromised: rotate it now, then purge it from git "
        "history (`git filter-repo`) — deleting the line in a new commit does not remove it."
    ),
    "Command Injection": (
        "Call the binary through `subprocess.run([...], shell=False)` with an argument list. "
        "Never build a shell string from user input. If a shell is unavoidable, validate the "
        "input against a strict allow-list before it is used."
    ),
    "Path Traversal": (
        "Resolve the candidate path and confirm it stays inside the intended base directory "
        "(`Path(base).resolve() in Path(candidate).resolve().parents`). Reject rather than "
        "sanitise sequences like `../`, and never trust a client-supplied filename."
    ),
    "Unsafe Deserialization": (
        "Do not deserialise untrusted data with `pickle`/`yaml.load`/`eval`. Use a data-only "
        "format (JSON) with a schema, or `yaml.safe_load`. If pickle is unavoidable, "
        "authenticate the payload with an HMAC before it is loaded."
    ),
}
_GENERIC_ADVICE = (
    "Automated verification could not confirm a safe fix. Review the flagged line manually, "
    "confirm whether untrusted input reaches it, and apply the standard remediation for this "
    "vulnerability class before merging."
)


def manual_review_advice(vuln_class: str) -> str:
    return MANUAL_REVIEW_ADVICE.get(vuln_class, _GENERIC_ADVICE)


def _line_at(source_text: str, line_no: int) -> str:
    lines = source_text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def local_confirm(finding, source_text: str) -> tuple[bool, str, str]:
    """Rule-based stand-in for the LLM's confirm/reject judgement.

    Returns (confirmed, severity, reasoning). Conservative by design: when the
    evidence is ambiguous we CONFIRM and let a human triage, because a missed
    vulnerability costs more than a reviewed false positive.
    """
    line = _line_at(source_text, getattr(finding, "line", 0))

    if _SUPPRESSION.search(line):
        return (
            False,
            "NONE",
            "Local rule fallback: line carries an explicit suppression comment "
            "(# nosec / # noqa), treated as an accepted risk.",
        )

    if _NON_PRODUCTION_PATH.search(getattr(finding, "file", "")):
        return (
            True,
            "LOW",
            "Local rule fallback: pattern confirmed, but the path looks like test/demo "
            "code, so severity is downgraded rather than dismissed. LLM confirmation was "
            "unavailable — a human should decide whether this file ships.",
        )

    severity = _STATIC_SEVERITY.get(getattr(finding, "rule_id", ""), _DEFAULT_SEVERITY)
    return (
        True,
        severity,
        f"Local rule fallback: {finding.rule_id} pattern re-verified statically against the "
        f"source at {finding.file}:{finding.line}. Severity assigned from the static rule "
        f"table (no semantic model available this run), so it is not exploitability-adjusted.",
    )


# ---------------------------------------------------------------------------
# Deterministic patch templates
#
# Each returns a unified diff (or None). They are written against the same
# lenient, content-anchored diff applier patch_loop.py already uses, so the
# @@ headers carry no line numbers.
# ---------------------------------------------------------------------------
def _diff(file: str, hunks: list[tuple[list[str], list[str]]]) -> str:
    out = [f"--- a/{file}", f"+++ b/{file}"]
    for old, new in hunks:
        out.append("@@")
        out.extend(f"-{line}" for line in old)
        out.extend(f"+{line}" for line in new)
    return "\n".join(out) + "\n"


def _import_hunk(lines: list[str], required_import: str, module_token: str):
    """Build a hunk that inserts `required_import` after the file's first
    import line. Returns None if the import is already present or the file has
    no import to anchor on."""
    token_re = re.compile(rf"\b{re.escape(module_token)}\b")
    for line in lines:
        if line.strip().startswith(("import ", "from ")) and token_re.search(line):
            return None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            return ([line], [line, required_import])
    return None


_FSTRING_ASSIGN = re.compile(r"""^(\s*)([A-Za-z_]\w*)\s*=\s*f(["'])(.*)\3\s*$""")
_PLACEHOLDER = re.compile(r"'?\"?\{([^{}]+)\}\"?'?")


def _template_sqli_python(lines: list[str], finding) -> Optional[list]:
    """Turn `q = f"SELECT ... '{x}'"` + `execute(q)` into a parameterised query."""
    idx = finding.line - 1
    if not (0 <= idx < len(lines)):
        return None
    match = _FSTRING_ASSIGN.match(lines[idx])
    if not match:
        return None
    indent, var, quote, body = match.groups()

    params = [p.strip() for p in _PLACEHOLDER.findall(body)]
    if not params or any(not re.fullmatch(r"[A-Za-z_][\w\.\[\]'\"]*", p) for p in params):
        # Expressions inside the placeholder (calls, arithmetic) are not safe to
        # mechanically hoist into a parameter tuple — bail out to manual review.
        return None

    parameterised = _PLACEHOLDER.sub("?", body)
    tuple_body = f"({params[0]},)" if len(params) == 1 else f"({', '.join(params)})"
    hunks = [
        (
            [lines[idx]],
            [
                f"{indent}{var} = {quote}{parameterised}{quote}",
                f"{indent}{var}_params = {tuple_body}",
            ],
        )
    ]

    exec_re = re.compile(rf"^(\s*)(.*?\.execute(?:many)?)\(\s*{re.escape(var)}\s*\)(.*)$")
    for line in lines:
        exec_match = exec_re.match(line)
        if exec_match:
            ex_indent, call, tail = exec_match.groups()
            hunks.append(([line], [f"{ex_indent}{call}({var}, {var}_params){tail}"]))
            break
    else:
        # Query built here but executed elsewhere (or via a helper) — a partial
        # patch would leave a broken call site, so decline.
        return None
    return hunks


_FSTRING_RETURN = re.compile(r"""^(\s*)return\s+f(["'])(.*)\2\s*$""")


def _template_xss_python(lines: list[str], finding) -> Optional[list]:
    """Replace `return f"<div>{x}</div>"` with escaped concatenation.

    Note this removes the f-string entirely rather than just wrapping the
    variable in escape(): XSS-002 keys on the f-string-with-tag shape, so
    `f"<div>{escape(x)}</div>"` would still fire the rule and the patch would
    (correctly) fail its own verification gate.
    """
    idx = finding.line - 1
    if not (0 <= idx < len(lines)):
        return None
    match = _FSTRING_RETURN.match(lines[idx])
    if not match:
        return None
    indent, quote, body = match.groups()

    parts: list[str] = []
    cursor = 0
    for placeholder in re.finditer(r"\{([^{}]+)\}", body):
        literal = body[cursor : placeholder.start()]
        if literal:
            parts.append(f"{quote}{literal}{quote}")
        expr = placeholder.group(1).strip()
        if not re.fullmatch(r"[A-Za-z_][\w\.]*", expr):
            return None
        parts.append(f"escape({expr})")
        cursor = placeholder.end()
    if not parts:
        return None
    trailing = body[cursor:]
    if trailing:
        parts.append(f"{quote}{trailing}{quote}")

    hunks = [([lines[idx]], [f"{indent}return {' + '.join(parts)}"])]
    imp = _import_hunk(lines, "from markupsafe import escape", "escape")
    if imp:
        hunks.insert(0, imp)
    return hunks


_SECRET_ASSIGN = re.compile(
    r"""^(\s*)([A-Za-z_]\w*)\s*(:\s*\w+\s*)?=\s*(["'])([^"']{8,})\4\s*$"""
)


def _template_secret_python(lines: list[str], finding) -> Optional[list]:
    """Replace a hardcoded literal with an environment lookup."""
    idx = finding.line - 1
    if not (0 <= idx < len(lines)):
        return None
    match = _SECRET_ASSIGN.match(lines[idx])
    if not match:
        return None
    indent, var, _annotation, _quote, _value = match.groups()
    env_name = re.sub(r"\W", "_", var).upper()

    hunks = [
        (
            [lines[idx]],
            [
                f'{indent}# Value moved to the environment. Rotate the previously '
                f'committed secret and purge it from git history.',
                f'{indent}{var} = os.environ["{env_name}"]',
            ],
        )
    ]
    imp = _import_hunk(lines, "import os", "os")
    if imp:
        hunks.insert(0, imp)
    return hunks


_TEMPLATES = {
    "SQLI-001": _template_sqli_python,
    "XSS-002": _template_xss_python,
    "SECRET-005": _template_secret_python,
}


def deterministic_patch(finding, source_text: str) -> Optional[str]:
    """Best-effort template patch for `finding`, or None when no template
    applies. A None here is a *correct* outcome, not a failure: it routes the
    finding to manual review rather than shipping a guess."""
    builder = _TEMPLATES.get(getattr(finding, "rule_id", ""))
    if builder is None:
        return None
    if not str(getattr(finding, "file", "")).endswith(".py"):
        # Templates are Python-syntax specific. JS/TS findings fall through to
        # manual review rather than getting a Python-shaped patch.
        return None
    lines = source_text.splitlines()
    try:
        hunks = builder(lines, finding)
    except Exception:  # noqa: BLE001 — a template bug must never break the run
        return None
    if not hunks:
        return None
    return _diff(finding.file, hunks)


# ---------------------------------------------------------------------------
# T3 entry point — build a ConfirmedFinding without any LLM
# ---------------------------------------------------------------------------
@dataclass
class FallbackOutcome:
    """Everything the caller needs to emit a FallbackNotice and to explain the
    degraded result in the report."""

    tier: str
    trigger: str
    detail: str
    attempts: int = 0
    failure_class: Optional[FailureClass] = None
    history: list = field(default_factory=list)

    def as_payload(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "trigger": self.trigger,
            "detail": self.detail,
            "attempts": self.attempts,
            "failure_class": self.failure_class.value if self.failure_class else None,
        }


def deterministic_analysis(finding, source: bytes, outcome: FallbackOutcome):
    """Produce a ConfirmedFinding using only local rules and templates.

    Imported lazily to avoid a circular import: engine.py imports this module
    for its fallback path, and this function needs engine.ConfirmedFinding.
    """
    from analyst.reasoning.engine import ConfirmedFinding  # local import, see docstring

    source_text = source.decode("utf-8", errors="replace") if isinstance(source, bytes) else str(source)
    confirmed, severity, reasoning = local_confirm(finding, source_text)
    patch = deterministic_patch(finding, source_text) if confirmed else None

    explanation = ""
    if confirmed:
        explanation = (
            f"{manual_review_advice(finding.vuln_class)} "
            f"(Generated by the deterministic fallback tier — {outcome.detail})"
        )

    return ConfirmedFinding(
        rule_id=finding.rule_id,
        vuln_class=finding.vuln_class,
        file=finding.file,
        line=finding.line,
        confirmed=confirmed,
        confirmation_reasoning=f"{reasoning} [fallback: {outcome.trigger}]",
        severity=None if severity == "NONE" else severity,
        explanation=explanation or None,
        patch_diff=patch,
        analysis_tier=outcome.tier,
        fallback_trigger=outcome.trigger,
    )


def manual_review_finding(finding, reason: str, attempts: int):
    """Terminal T4 result: no verified fix, hand to a human with safe defaults."""
    from analyst.reasoning.engine import ConfirmedFinding  # local import, see above

    base = getattr(finding, "vuln_class", "Unknown")
    return ConfirmedFinding(
        rule_id=finding.rule_id,
        vuln_class=base,
        file=finding.file,
        line=finding.line,
        confirmed=True,
        confirmation_reasoning=(
            f"MANUAL HUMAN REVIEW REQUIRED after {attempts} verification attempt(s): {reason}"
        ),
        severity=_STATIC_SEVERITY.get(finding.rule_id, _DEFAULT_SEVERITY),
        explanation=manual_review_advice(base),
        patch_diff=None,
        analysis_tier="T4_MANUAL_REVIEW",
        fallback_trigger=reason,
    )
