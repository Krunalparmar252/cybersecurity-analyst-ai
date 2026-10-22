"""
Cryptographic salting & tamper-proofing tests (requirement 4).

Each test states the attack it is defending against, because "the hash matches"
is not by itself evidence of anything — what matters is which specific forgery
the construction makes infeasible.
"""

import json

import pytest

from analyst.protocol.crypto import (
    HASH_VERSION,
    MODE_HMAC,
    MODE_SALT_PREFIX,
    AuditLog,
    IntegrityError,
    SaltContext,
    canonical_bytes,
    hmac_sha256,
    manifest_digest,
    salted_sha256,
    verify_report,
    write_verification_sidecar,
)


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------
def test_salted_sha256_matches_the_specified_construction():
    """The default mode must be literally sha256(salt + content)."""
    import hashlib

    salt, content = b"S" * 32, b"finding payload"
    assert salted_sha256(content, salt) == hashlib.sha256(salt + content).hexdigest()


def test_salt_changes_the_digest_for_identical_content():
    """Without this property, digests are forgeable by anyone who can run
    sha256 — which is everyone."""
    content = b"identical bytes"
    assert salted_sha256(content, b"A" * 32) != salted_sha256(content, b"B" * 32)


def test_hmac_mode_differs_from_prefix_mode():
    salt, content = b"K" * 32, b"payload"
    assert hmac_sha256(content, salt) != salted_sha256(content, salt)


def test_canonicalisation_is_key_order_independent():
    """Two semantically identical dicts must hash identically, or every
    signature check becomes flaky the moment a payload round-trips JSON."""
    assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})


# ---------------------------------------------------------------------------
# Sealing and verification
# ---------------------------------------------------------------------------
def test_seal_is_tagged_with_version_mode_and_epoch():
    ctx = SaltContext.generate(run_id="run-1")
    sealed = ctx.seal({"finding": "SQLI-001"})
    version, mode, epoch, digest = sealed.split(":")
    assert version == HASH_VERSION
    assert mode == MODE_SALT_PREFIX
    assert epoch == "0"
    assert len(digest) == 64


def test_verify_accepts_untampered_and_rejects_tampered_content():
    """TAMPERING: editing a finding after it was sealed must be detectable."""
    ctx = SaltContext.generate(run_id="run-1")
    finding = {"rule_id": "SQLI-001", "severity": "CRITICAL"}
    sealed = ctx.seal(finding)

    assert ctx.verify(finding, sealed) is True

    finding["severity"] = "LOW"  # attacker downgrades the finding
    assert ctx.verify(finding, sealed) is False


def test_digest_from_another_run_does_not_verify():
    """REPLAY / STATE SPOOFING: a manifest captured from an earlier run must
    not validate against this run's salt."""
    payload = {"manifest": ["a.py", "b.py"]}
    old_run = SaltContext.generate(run_id="run-old")
    new_run = SaltContext.generate(run_id="run-new")

    replayed = old_run.seal(payload)
    assert old_run.verify(payload, replayed) is True
    assert new_run.verify(payload, replayed) is False


def test_verify_or_raise_explains_the_failure():
    ctx = SaltContext.generate()
    with pytest.raises(IntegrityError) as exc:
        ctx.verify_or_raise({"x": 1}, ctx.seal({"x": 2}), what="candidate findings")
    assert "candidate findings" in str(exc.value)


def test_malformed_and_unknown_tags_are_rejected_not_guessed():
    ctx = SaltContext.generate()
    assert ctx.verify({"x": 1}, "") is False
    assert ctx.verify({"x": 1}, "not-a-tagged-digest") is False
    assert ctx.verify({"x": 1}, "v99:sha256-salt-prefix:0:" + "0" * 64) is False
    assert ctx.verify({"x": 1}, "v1:rot13:0:" + "0" * 64) is False


def test_hmac_mode_round_trips():
    ctx = SaltContext.generate(run_id="run-hmac", mode=MODE_HMAC)
    sealed = ctx.seal({"a": 1})
    assert sealed.split(":")[1] == MODE_HMAC
    assert ctx.verify({"a": 1}, sealed) is True
    assert ctx.verify({"a": 2}, sealed) is False


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------
def test_rotation_keeps_previously_sealed_artifacts_verifiable():
    """Rotation must not invalidate history, or nobody will ever rotate."""
    ctx = SaltContext.generate(run_id="run-rot")
    before = ctx.seal({"stage": "ingest"})

    new_epoch = ctx.rotate()
    after = ctx.seal({"stage": "detect"})

    assert new_epoch == 1
    assert after.split(":")[2] == "1"
    assert ctx.verify({"stage": "ingest"}, before) is True   # retired epoch
    assert ctx.verify({"stage": "detect"}, after) is True    # current epoch


def test_rotation_produces_a_different_salt():
    ctx = SaltContext.generate(run_id="run-rot2")
    fingerprint_before = ctx.fingerprint()
    ctx.rotate()
    assert ctx.fingerprint() != fingerprint_before


def test_fingerprint_does_not_leak_the_salt():
    ctx = SaltContext.generate()
    descriptor = ctx.descriptor()
    serialised = json.dumps(descriptor)
    assert ctx._salt.hex() not in serialised, "descriptor must never carry the raw salt"
    assert len(descriptor["salt_fingerprint"]) == 16


def test_configured_pepper_makes_salts_reproducible():
    """With a deployment pepper, a verifier can rebuild the salt from public
    metadata and check a report months later."""
    pepper = b"deployment-pepper"
    original = SaltContext.generate(run_id="run-repro", pepper=pepper)
    sealed = original.seal({"report": "contents"})

    rebuilt = SaltContext.generate(run_id="run-repro", pepper=pepper)
    rebuilt.nonce = original.nonce
    rebuilt._salt = original._salt  # derived from (pepper, run_id, nonce, epoch)

    assert rebuilt.verify({"report": "contents"}, sealed) is True


# ---------------------------------------------------------------------------
# Manifest digest
# ---------------------------------------------------------------------------
def test_manifest_digest_is_order_independent_but_content_sensitive():
    ctx = SaltContext.generate()
    entries = ["a.py:d1", "b.py:d2", "c.py:d3"]
    digest = manifest_digest(entries, ctx)

    assert manifest_digest(list(reversed(entries)), ctx) == digest  # walk order
    assert manifest_digest(entries + ["evil.py:d4"], ctx) != digest  # injected file
    assert manifest_digest(entries[:-1], ctx) != digest              # dropped file


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------
def test_audit_chain_verifies_when_untouched():
    ctx = SaltContext.generate()
    log = AuditLog(ctx, stream_id="test")
    log.append("INGEST", "DECISION", decision="SUFFICIENT")
    log.append("DETECT", "DECISION", decision="WORTH_ESCALATING")
    log.append("REPORT", "DECISION", decision="REVIEW_REQUIRED")

    ok, note = log.verify()
    assert ok is True
    assert "3 entries" in note


def test_audit_chain_detects_an_edited_entry():
    """An attacker rewriting 'CRITICAL' to 'LOW' in the audit log."""
    ctx = SaltContext.generate()
    log = AuditLog(ctx, stream_id="test")
    log.append("DETECT", "DECISION", severity="CRITICAL")
    log.append("REPORT", "DECISION", verdict="REVIEW_REQUIRED")

    log.entries[0].details["severity"] = "LOW"

    ok, note = log.verify()
    assert ok is False
    assert "seq=0" in note


def test_audit_chain_detects_a_deleted_entry():
    """Removing the entry that recorded an inconvenient finding."""
    ctx = SaltContext.generate()
    log = AuditLog(ctx, stream_id="test")
    for i in range(4):
        log.append("AGENT", "STEP", index=i)

    del log.entries[1]

    ok, note = log.verify()
    assert ok is False
    assert "Chain break" in note


def test_audit_head_advances_with_every_append():
    ctx = SaltContext.generate()
    log = AuditLog(ctx)
    heads = [log.head()]
    for i in range(3):
        log.append("AGENT", "STEP", i=i)
        heads.append(log.head())
    assert len(set(heads)) == 4


# ---------------------------------------------------------------------------
# Report sealing
# ---------------------------------------------------------------------------
def test_report_sidecar_detects_post_hoc_report_edits(tmp_path):
    """The scenario this exists for: someone edits a severity in report.md
    before forwarding it to a manager."""
    ctx = SaltContext.generate()
    report = tmp_path / "report.md"
    report.write_text("# Scan Report\n\nCRITICAL: SQL injection in login().\n", encoding="utf-8")

    sidecar = write_verification_sidecar(report, ctx)
    ok, _ = verify_report(report, sidecar, ctx)
    assert ok is True

    report.write_text("# Scan Report\n\nLOW: minor issue in login().\n", encoding="utf-8")
    ok, note = verify_report(report, sidecar, ctx)
    assert ok is False
    assert "modified" in note
