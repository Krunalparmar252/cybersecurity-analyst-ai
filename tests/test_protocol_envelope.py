"""
Inter-agent protocol envelope tests (requirement 2).

What is being asserted: that the envelope is a *contract*, not a dict with
optimistic naming. A malformed payload must be rejected at construction, an
unknown schema must not be transportable, and a sealed message must not survive
being re-addressed.
"""

import pytest
from pydantic import ValidationError

from analyst.protocol.crypto import IntegrityError, SaltContext
from analyst.protocol.envelope import (
    PROTOCOL_VERSION,
    AgentID,
    AgentMessage,
    DecisionPayload,
    FallbackNotice,
    MessageType,
    NegotiationRequest,
    NegotiationResponse,
    RuleRecheckRequest,
    RuleRecheckResponse,
    StateHandoffPayload,
    registered_payload_schemas,
)


def _msg(ctx, **overrides):
    kwargs = dict(
        run_id=ctx.run_id,
        sender=AgentID.DETECT,
        receiver=AgentID.REASON,
        message_type=MessageType.DECISION,
        payload=DecisionPayload(decision="WORTH_ESCALATING", reason="3 candidates"),
    )
    kwargs.update(overrides)
    return AgentMessage.build(**kwargs)


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------
def test_envelope_carries_the_mandated_fields():
    ctx = SaltContext.generate()
    msg = _msg(ctx).seal(ctx)

    assert msg.protocol_version == PROTOCOL_VERSION
    assert msg.sender == AgentID.DETECT
    assert msg.receiver == AgentID.REASON
    assert msg.message_type == MessageType.DECISION
    assert msg.correlation_id
    assert msg.payload["decision"] == "WORTH_ESCALATING"
    assert msg.integrity is not None
    assert msg.integrity.signature
    assert msg.integrity.salt_fingerprint == ctx.fingerprint()


def test_payload_is_validated_against_its_declared_schema():
    """A payload that does not match its schema_name must not become a
    message — catching it at the receiver is already too late."""
    ctx = SaltContext.generate()
    with pytest.raises(ValidationError):
        AgentMessage(
            run_id=ctx.run_id,
            sender=AgentID.DETECT,
            receiver=AgentID.REASON,
            message_type=MessageType.DECISION,
            payload_type=DecisionPayload.schema_name,
            payload={"decision": "OK"},  # missing the required `reason`
        )


def test_unknown_payload_types_are_not_transportable():
    ctx = SaltContext.generate()
    with pytest.raises(ValidationError):
        AgentMessage(
            run_id=ctx.run_id,
            sender=AgentID.DETECT,
            receiver=AgentID.REASON,
            message_type=MessageType.DECISION,
            payload_type="attacker.invented.schema.v1",
            payload={"anything": True},
        )


def test_payload_models_forbid_extra_fields():
    """A field the receiver ignores is a field an attacker can smuggle state
    in — so unknown fields are a protocol violation, not a curiosity."""
    with pytest.raises(ValidationError):
        DecisionPayload(decision="OK", reason="fine", injected="rm -rf /")


def test_broadcast_is_a_receiver_only_address():
    ctx = SaltContext.generate()
    with pytest.raises(ValueError):
        _msg(ctx, sender=AgentID.BROADCAST)


def test_payload_as_rejects_a_mismatched_schema():
    ctx = SaltContext.generate()
    msg = _msg(ctx)
    with pytest.raises(ValueError):
        msg.payload_as(RuleRecheckResponse)


def test_parse_payload_returns_the_typed_model():
    ctx = SaltContext.generate()
    msg = _msg(ctx)
    parsed = msg.parse_payload()
    assert isinstance(parsed, DecisionPayload)
    assert parsed.decision == "WORTH_ESCALATING"


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------
def test_sealed_message_verifies():
    ctx = SaltContext.generate()
    assert _msg(ctx).seal(ctx).verify(ctx) is True


def test_payload_tampering_invalidates_the_signature():
    ctx = SaltContext.generate()
    msg = _msg(ctx).seal(ctx)
    msg.payload["decision"] = "NONE_FOUND"  # attacker suppresses the findings
    assert msg.verify(ctx) is False


def test_re_addressing_a_sealed_message_invalidates_it():
    """The signature covers addressing, not just the body — otherwise a valid
    message could be redirected to a different agent unchanged."""
    ctx = SaltContext.generate()
    msg = _msg(ctx).seal(ctx)
    msg.receiver = AgentID.REPORT
    assert msg.verify(ctx) is False


def test_unsealed_messages_are_refused():
    ctx = SaltContext.generate()
    msg = _msg(ctx)
    assert msg.verify(ctx) is False
    with pytest.raises(IntegrityError):
        msg.verify_or_raise(ctx)


def test_double_sealing_is_refused():
    """Sealing twice would mean the message was mutated after sealing."""
    ctx = SaltContext.generate()
    msg = _msg(ctx).seal(ctx)
    with pytest.raises(IntegrityError):
        msg.seal(ctx)


def test_message_sealed_under_another_run_fails_here():
    ctx_a, ctx_b = SaltContext.generate(), SaltContext.generate()
    msg = _msg(ctx_a).seal(ctx_a)
    assert msg.verify(ctx_b) is False


def test_expiry_is_computed_from_created_at():
    ctx = SaltContext.generate()
    msg = _msg(ctx)
    assert msg.is_expired() is False
    msg.created_at -= msg.ttl_seconds + 10
    assert msg.is_expired() is True


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
def test_reply_preserves_correlation_and_records_causation():
    ctx = SaltContext.generate()
    request = AgentMessage.build(
        run_id=ctx.run_id,
        sender=AgentID.REASON,
        receiver=AgentID.DETECT,
        message_type=MessageType.PEER_VALIDATION_REQUEST,
        payload=RuleRecheckRequest(rule_id="SQLI-001", file="app.py", sandbox_root="/tmp/x"),
    )
    response = request.reply(
        MessageType.PEER_VALIDATION_RESPONSE,
        RuleRecheckResponse(
            rule_id="SQLI-001", file="app.py", still_fires=False, verdict="RESOLVED"
        ),
    )

    assert response.correlation_id == request.correlation_id  # same conversation
    assert response.causation_id == request.message_id        # caused by the request
    assert response.sender == AgentID.DETECT
    assert response.receiver == AgentID.REASON
    assert response.message_id != request.message_id


# ---------------------------------------------------------------------------
# Interop
# ---------------------------------------------------------------------------
def test_legacy_projection_keeps_the_pre_protocol_shape():
    """The dashboard, CLI and existing tests read agent/decision/reason —
    those keys must survive the protocol upgrade."""
    ctx = SaltContext.generate()
    legacy = _msg(ctx).seal(ctx).to_legacy_dict()

    assert legacy["agent"] == "DETECT"
    assert legacy["decision"] == "WORTH_ESCALATING"
    assert legacy["reason"] == "3 candidates"
    assert isinstance(legacy["timestamp"], float)
    # additive protocol fields
    assert legacy["receiver"] == "REASON"
    assert legacy["message_type"] == "DECISION"
    assert legacy["signature"]


def test_every_protocol_payload_is_introspectable():
    schemas = registered_payload_schemas()
    for model in (
        DecisionPayload,
        StateHandoffPayload,
        RuleRecheckRequest,
        RuleRecheckResponse,
        NegotiationRequest,
        NegotiationResponse,
        FallbackNotice,
    ):
        assert model.schema_name in schemas
        assert schemas[model.schema_name]["type"] == "object"
