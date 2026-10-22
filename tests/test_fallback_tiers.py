"""
Multi-tier fallback tests (requirement 3).

Two separate guarantees are under test:

  3a  LLM FAILURE — a 429 / timeout / connectivity error must degrade to local
      rule-based scanning and deterministic patch templates, and the pipeline
      must keep running. Critically, the vulnerability must NOT be silently
      downgraded to "not confirmed", which is what the old bare `except` did.

  3b  PATCH VALIDATION — when iterative LLM patching fails verification after N
      attempts, the finding becomes MANUAL_REVIEW_REQUIRED with safe default
      remediation advice, and no unverified patch is offered as a fix.
"""

from unittest.mock import MagicMock

import pytest

from analyst.detection.engine import CandidateFinding
from analyst.reasoning import patch_loop
from analyst.reasoning.engine import (
    TIER_DETERMINISTIC,
    TIER_LLM,
    TIER_RETRY,
    analyze_finding,
)
from analyst.reasoning.fallback import (
    CircuitBreaker,
    FailureClass,
    backoff_delay,
    classify_llm_error,
    deterministic_patch,
    is_transient,
    local_confirm,
    manual_review_advice,
)

NO_SLEEP = lambda _seconds: None  # noqa: E731 — keeps retry tests instant


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class RateLimitError(Exception):
    def __init__(self):
        super().__init__("Error code: 429 - rate limit reached for model")
        self.status_code = 429


class ServerError(Exception):
    status_code = 503


class AuthError(Exception):
    def __init__(self):
        super().__init__("401 Unauthorized: Invalid API Key")
        self.status_code = 401


def _sqli_finding():
    return CandidateFinding(
        rule_id="SQLI-001",
        vuln_class="SQL Injection",
        file="app.py",
        line=5,  # matches the `query = f"..."` line in SQLI_SOURCE below
        snippet='query = f"SELECT * FROM users WHERE name = \'{name}\'"',
        confidence="high",
        source_scanner="static",
    )


SQLI_SOURCE = b'''import sqlite3


def login(name, conn):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn.cursor().execute(query)
'''


def _client_raising(exc_factory, succeed_on=None, payload=None):
    """Mock ChatGroq whose structured client raises until `succeed_on`."""
    calls = {"n": 0}

    def invoke(_messages):
        calls["n"] += 1
        if succeed_on is not None and calls["n"] >= succeed_on:
            return payload
        raise exc_factory()

    structured = MagicMock()
    structured.invoke.side_effect = invoke
    client = MagicMock()
    client.with_structured_output.return_value = structured
    client.calls = calls
    return client


# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "exc, expected",
    [
        (RateLimitError(), FailureClass.RATE_LIMIT),
        (ServerError("503 service unavailable"), FailureClass.SERVER),
        (AuthError(), FailureClass.AUTH),
        (TimeoutError("read timed out"), FailureClass.TIMEOUT),
        (ConnectionError("getaddrinfo failed"), FailureClass.CONNECTIVITY),
        (Exception("insufficient_quota: credit balance too low"), FailureClass.QUOTA),
        (ValueError("Expecting value: line 1 column 1"), FailureClass.SCHEMA),
        (Exception("something nobody predicted"), FailureClass.UNKNOWN),
    ],
)
def test_error_classification(exc, expected):
    assert classify_llm_error(exc) is expected


def test_only_infrastructure_failures_are_retried():
    """Retrying a bad API key three times just delays the fallback."""
    assert is_transient(FailureClass.RATE_LIMIT)
    assert is_transient(FailureClass.TIMEOUT)
    assert is_transient(FailureClass.CONNECTIVITY)
    assert is_transient(FailureClass.SERVER)
    assert not is_transient(FailureClass.AUTH)
    assert not is_transient(FailureClass.QUOTA)


def test_backoff_grows_and_stays_capped():
    assert backoff_delay(1, jitter=False) == 0.5
    assert backoff_delay(2, jitter=False) == 1.0
    assert backoff_delay(9, jitter=False) == 8.0  # capped
    assert 0 <= backoff_delay(4) <= 4.0  # full jitter stays in range


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------
def test_breaker_opens_after_repeated_transient_failures():
    breaker = CircuitBreaker(failure_threshold=3)
    for _ in range(2):
        breaker.record_failure(FailureClass.RATE_LIMIT)
    assert breaker.allows_call() is True

    breaker.record_failure(FailureClass.RATE_LIMIT)
    assert breaker.state == "OPEN"
    assert breaker.allows_call() is False


def test_breaker_opens_immediately_on_auth_failure():
    breaker = CircuitBreaker(failure_threshold=5)
    breaker.record_failure(FailureClass.AUTH)
    assert breaker.state == "OPEN"


def test_breaker_half_opens_then_closes_on_success():
    breaker = CircuitBreaker(failure_threshold=1, reset_after=0.0)
    breaker.record_failure(FailureClass.SERVER)
    assert breaker.allows_call() is True  # reset window elapsed -> probe
    assert breaker.state == "HALF_OPEN"
    breaker.record_success()
    assert breaker.state == "CLOSED"


# ---------------------------------------------------------------------------
# 3a — LLM failure fallback
# ---------------------------------------------------------------------------
def test_rate_limit_retries_then_recovers():
    payload = {
        "confirmed": True,
        "confirmation_reasoning": "tainted query",
        "severity": "CRITICAL",
        "explanation": "f-string into execute()",
        "patch_diff": "",
    }
    client = _client_raising(RateLimitError, succeed_on=3, payload=payload)

    result = analyze_finding(
        _sqli_finding(), SQLI_SOURCE, client, breaker=CircuitBreaker(failure_threshold=99),
        sleep_fn=NO_SLEEP,
    )

    assert client.calls["n"] == 3
    assert result.confirmed is True
    assert result.analysis_tier == TIER_RETRY
    assert result.fallback_trigger == "RECOVERED"


def test_persistent_rate_limit_falls_back_to_local_rules_not_to_dismissal():
    """The regression this guards: a 429 used to mark a real SQLi
    `confirmed=False` and the report looked identical to a clean scan."""
    client = _client_raising(RateLimitError)
    notices = []

    result = analyze_finding(
        _sqli_finding(), SQLI_SOURCE, client,
        breaker=CircuitBreaker(failure_threshold=99),
        on_fallback=notices.append,
        sleep_fn=NO_SLEEP,
    )

    assert result.confirmed is True, "a rate limit must never dismiss a finding"
    assert result.analysis_tier == TIER_DETERMINISTIC
    assert result.fallback_trigger == FailureClass.RATE_LIMIT.value
    assert result.severity == "CRITICAL"
    assert notices and notices[0].failure_class is FailureClass.RATE_LIMIT


def test_timeout_and_connectivity_also_fall_back():
    for exc in (lambda: TimeoutError("read timed out"), lambda: ConnectionError("dns failure")):
        result = analyze_finding(
            _sqli_finding(), SQLI_SOURCE, _client_raising(exc),
            breaker=CircuitBreaker(failure_threshold=99), sleep_fn=NO_SLEEP,
        )
        assert result.confirmed is True
        assert result.analysis_tier == TIER_DETERMINISTIC


def test_auth_failure_fails_fast_without_retrying():
    client = _client_raising(AuthError)
    result = analyze_finding(
        _sqli_finding(), SQLI_SOURCE, client, breaker=CircuitBreaker(), sleep_fn=NO_SLEEP
    )
    assert client.calls["n"] == 1, "non-retryable failures must not be retried"
    assert result.analysis_tier == TIER_DETERMINISTIC
    assert result.fallback_trigger == FailureClass.AUTH.value


def test_open_circuit_skips_the_call_entirely():
    client = _client_raising(RateLimitError)
    breaker = CircuitBreaker(failure_threshold=1, reset_after=999)
    breaker.record_failure(FailureClass.RATE_LIMIT)

    result = analyze_finding(
        _sqli_finding(), SQLI_SOURCE, client, breaker=breaker, sleep_fn=NO_SLEEP
    )
    assert client.calls["n"] == 0, "an open circuit must not pay another timeout"
    assert result.fallback_trigger == "CIRCUIT_OPEN"


def test_malformed_model_output_is_a_schema_failure_not_a_crash():
    structured = MagicMock()
    structured.invoke.return_value = {"unexpected": "shape"}
    client = MagicMock()
    client.with_structured_output.return_value = structured

    result = analyze_finding(
        _sqli_finding(), SQLI_SOURCE, client,
        breaker=CircuitBreaker(failure_threshold=99), sleep_fn=NO_SLEEP,
    )
    assert result.analysis_tier == TIER_DETERMINISTIC
    assert result.fallback_trigger == FailureClass.SCHEMA.value


def test_healthy_call_is_not_marked_as_degraded():
    payload = {
        "confirmed": True, "confirmation_reasoning": "ok", "severity": "HIGH",
        "explanation": "e", "patch_diff": "",
    }
    structured = MagicMock()
    structured.invoke.return_value = payload
    client = MagicMock()
    client.with_structured_output.return_value = structured

    result = analyze_finding(_sqli_finding(), SQLI_SOURCE, client, sleep_fn=NO_SLEEP)
    assert result.analysis_tier == TIER_LLM
    assert result.fallback_trigger is None


# ---------------------------------------------------------------------------
# Deterministic tier behaviour
# ---------------------------------------------------------------------------
def test_local_confirm_assigns_static_severity():
    confirmed, severity, reasoning = local_confirm(_sqli_finding(), SQLI_SOURCE.decode())
    assert confirmed is True
    assert severity == "CRITICAL"
    assert "fallback" in reasoning.lower()


def test_local_confirm_honours_an_explicit_suppression():
    finding = _sqli_finding()
    source = "x = 1\ny = 2\nquery = build()  # nosec\n"
    finding.line = 3
    confirmed, severity, _ = local_confirm(finding, source)
    assert confirmed is False
    assert severity == "NONE"


def test_deterministic_sqli_template_parameterises_the_query():
    diff = deterministic_patch(_sqli_finding(), SQLI_SOURCE.decode())
    assert diff is not None
    assert "?" in diff
    assert "query_params" in diff
    assert "execute(query, query_params)" in diff


def test_deterministic_template_declines_rather_than_guessing():
    """No template for this rule family, so the finding must route to manual
    review instead of receiving a plausible-looking wrong patch."""
    finding = CandidateFinding(
        rule_id="DESER-001", vuln_class="Unsafe Deserialization", file="a.py",
        line=1, snippet="pickle.loads(x)", confidence="high", source_scanner="static",
    )
    assert deterministic_patch(finding, "pickle.loads(x)\n") is None


def test_templates_do_not_emit_python_patches_for_js_files():
    finding = _sqli_finding()
    finding.file = "server.js"
    assert deterministic_patch(finding, SQLI_SOURCE.decode()) is None


def test_every_supported_class_has_remediation_advice():
    for vuln_class in (
        "SQL Injection", "Cross-Site Scripting", "Hardcoded Secrets",
        "Command Injection", "Path Traversal", "Unsafe Deserialization",
    ):
        assert len(manual_review_advice(vuln_class)) > 40
    assert "manually" in manual_review_advice("Something Unmapped").lower()


# ---------------------------------------------------------------------------
# 3b — patch validation fallback
# ---------------------------------------------------------------------------
def _repo(tmp_path):
    (tmp_path / "app.py").write_bytes(SQLI_SOURCE)
    return str(tmp_path)


def test_unfixable_finding_becomes_manual_review_after_n_attempts(tmp_path, monkeypatch):
    """The LLM answers fine every time, but its patch never resolves the rule.
    After MAX_ATTEMPTS the finding must be handed to a human — not shipped with
    an unverified patch, and not dropped."""
    finding = _sqli_finding()

    useless_patch = (
        "--- a/app.py\n+++ b/app.py\n@@\n"
        "-import sqlite3\n"
        "+import sqlite3  # cosmetic change that fixes nothing\n"
    )
    structured = MagicMock()
    structured.invoke.return_value = {
        "confirmed": True,
        "confirmation_reasoning": "genuine injection",
        "severity": "CRITICAL",
        "explanation": "tainted f-string",
        "patch_diff": useless_patch,
    }
    client = MagicMock()
    client.with_structured_output.return_value = structured

    result = patch_loop.verify_and_patch(
        finding, _repo(tmp_path), {"app.py": SQLI_SOURCE}, client
    )

    assert result.loop_status == patch_loop.STATUS_MANUAL_REVIEW
    assert result.attempts == patch_loop.MAX_ATTEMPTS
    assert result.finding.patch_diff is None, "no unverified patch may be offered as a fix"
    assert result.finding.confirmed is True, "the vulnerability is still real"
    assert "MANUAL HUMAN REVIEW REQUIRED" in result.finding.confirmation_reasoning
    assert result.remediation_advice == manual_review_advice("SQL Injection")
    assert result.finding.analysis_tier == "T4_MANUAL_REVIEW"
    assert len(result.attempt_log) == patch_loop.MAX_ATTEMPTS


def test_unapplyable_patch_also_routes_to_manual_review(tmp_path):
    """A diff whose anchor text is absent cannot be verified, so it is treated
    as unresolved rather than optimistically accepted."""
    structured = MagicMock()
    structured.invoke.return_value = {
        "confirmed": True,
        "confirmation_reasoning": "genuine",
        "severity": "HIGH",
        "explanation": "x",
        "patch_diff": "--- a/app.py\n+++ b/app.py\n@@\n-text that does not exist\n+replacement\n",
    }
    client = MagicMock()
    client.with_structured_output.return_value = structured

    result = patch_loop.verify_and_patch(
        _sqli_finding(), _repo(tmp_path), {"app.py": SQLI_SOURCE}, client
    )
    assert result.loop_status == patch_loop.STATUS_MANUAL_REVIEW
    assert all(entry["applied"] is False for entry in result.attempt_log)


def test_offline_mode_still_produces_findings_without_any_llm(tmp_path):
    """No client at all: the deterministic tier must carry the whole run."""
    results = patch_loop.run_patch_verify_loop(
        [_sqli_finding()], {"app.py": SQLI_SOURCE}, _repo(tmp_path), offline=True
    )
    assert len(results) == 1
    assert results[0].finding.confirmed is True
    assert results[0].finding.analysis_tier in (TIER_DETERMINISTIC, "T4_MANUAL_REVIEW")


def test_missing_api_key_degrades_instead_of_raising(tmp_path, monkeypatch):
    """Previously this raised RuntimeError and killed the scan."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    notices = []
    results = patch_loop.run_patch_verify_loop(
        [_sqli_finding()], {"app.py": SQLI_SOURCE}, _repo(tmp_path),
        on_fallback=notices.append,
    )
    assert len(results) == 1
    assert any(n.trigger == "NO_API_KEY" for n in notices)


def test_a_good_patch_is_still_accepted(tmp_path):
    """Guard against over-correcting: the fallback machinery must not make the
    happy path escalate."""
    good_patch = (
        "--- a/app.py\n+++ b/app.py\n@@\n"
        "-    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
        "+    query = \"SELECT * FROM users WHERE name = ?\"\n"
    )
    structured = MagicMock()
    structured.invoke.return_value = {
        "confirmed": True, "confirmation_reasoning": "genuine", "severity": "CRITICAL",
        "explanation": "x", "patch_diff": good_patch,
    }
    client = MagicMock()
    client.with_structured_output.return_value = structured

    result = patch_loop.verify_and_patch(
        _sqli_finding(), _repo(tmp_path), {"app.py": SQLI_SOURCE}, client
    )
    assert result.loop_status == patch_loop.STATUS_ACCEPTED
    assert result.attempts == 1
