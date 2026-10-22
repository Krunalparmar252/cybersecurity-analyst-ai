"""
A2A message bus tests (requirement 1).

The claim under test is specifically that agents are DECOUPLED: a caller names
a capability, not a module, and the bus resolves it. The second claim is that
the bus is a security boundary — it refuses tampered, replayed, expired and
cross-run messages rather than trusting anything that shows up.
"""

import pytest

from analyst.protocol.bus import MessageBus, NoRouteError, ReplayError
from analyst.protocol.crypto import IntegrityError, SaltContext
from analyst.protocol.envelope import (
    AgentID,
    AgentMessage,
    DecisionPayload,
    MessageType,
    NegotiationRequest,
    NegotiationResponse,
    RuleRecheckRequest,
    RuleRecheckResponse,
)

CAP_RECHECK = "rule.recheck"


@pytest.fixture
def ctx():
    return SaltContext.generate(run_id="bus-test")


@pytest.fixture
def bus(ctx):
    return MessageBus(ctx)


def _validator(verdict_still_fires: bool, as_agent: AgentID = AgentID.DETECT):
    """A stand-in Detection endpoint. The point of the test is that the caller
    never learns which implementation answered."""

    def handler(msg: AgentMessage):
        if msg.message_type != MessageType.PEER_VALIDATION_REQUEST:
            return None
        request = msg.payload_as(RuleRecheckRequest)
        return msg.reply(
            MessageType.PEER_VALIDATION_RESPONSE,
            RuleRecheckResponse(
                rule_id=request.rule_id,
                file=request.file,
                still_fires=verdict_still_fires,
                verdict="STILL_VULNERABLE" if verdict_still_fires else "RESOLVED",
                evidence="stub validator",
            ),
            sender=as_agent,
        )

    return handler


# ---------------------------------------------------------------------------
# Capability routing = decoupling
# ---------------------------------------------------------------------------
def test_caller_resolves_a_capability_not_a_module(bus):
    bus.register(AgentID.DETECT, _validator(False), capabilities=(CAP_RECHECK,))
    assert bus.resolve(CAP_RECHECK) == AgentID.DETECT
    assert bus.capabilities()[CAP_RECHECK] == "DETECT"


def test_unknown_capability_fails_loudly(bus):
    with pytest.raises(NoRouteError):
        bus.resolve("nonexistent.capability")


def test_swapping_the_provider_requires_no_caller_change(bus):
    """Register a different agent for the same capability and the identical
    request routes elsewhere — that is what 'not hardcoded' means."""
    bus.register(AgentID.DETECT, _validator(True), capabilities=(CAP_RECHECK,))
    bus.register(
        AgentID.REPORT, _validator(False, as_agent=AgentID.REPORT), capabilities=(CAP_RECHECK,)
    )

    response = bus.request_capability(
        sender=AgentID.REASON,
        capability=CAP_RECHECK,
        message_type=MessageType.PEER_VALIDATION_REQUEST,
        payload=RuleRecheckRequest(rule_id="XSS-002", file="a.py", sandbox_root="/tmp/s"),
        expect=MessageType.PEER_VALIDATION_RESPONSE,
    )
    assert response.sender == AgentID.REPORT
    assert response.payload_as(RuleRecheckResponse).still_fires is False


# ---------------------------------------------------------------------------
# Peer validation round trip
# ---------------------------------------------------------------------------
def test_peer_validation_round_trip_is_correlated(bus):
    bus.register(AgentID.DETECT, _validator(True), capabilities=(CAP_RECHECK,))

    response = bus.request_capability(
        sender=AgentID.REASON,
        capability=CAP_RECHECK,
        message_type=MessageType.PEER_VALIDATION_REQUEST,
        payload=RuleRecheckRequest(
            rule_id="SQLI-001", file="app.py", sandbox_root="/tmp/sbx", attempt=2
        ),
        expect=MessageType.PEER_VALIDATION_RESPONSE,
    )

    body = response.payload_as(RuleRecheckResponse)
    assert body.still_fires is True
    assert body.verdict == "STILL_VULNERABLE"

    request = next(
        m for m in bus.transcript if m.message_type == MessageType.PEER_VALIDATION_REQUEST
    )
    assert response.correlation_id == request.correlation_id
    assert response.causation_id == request.message_id


def test_silent_peer_is_an_error_not_an_all_clear(bus):
    """If the validator does not answer, the loop must NOT read that as
    'the vulnerability is resolved'."""
    bus.register(AgentID.DETECT, lambda msg: None, capabilities=(CAP_RECHECK,))
    with pytest.raises(NoRouteError):
        bus.request_capability(
            sender=AgentID.REASON,
            capability=CAP_RECHECK,
            message_type=MessageType.PEER_VALIDATION_REQUEST,
            payload=RuleRecheckRequest(rule_id="X", file="a.py", sandbox_root="/tmp"),
            expect=MessageType.PEER_VALIDATION_RESPONSE,
        )


# ---------------------------------------------------------------------------
# Negotiation
# ---------------------------------------------------------------------------
def test_negotiation_lets_a_peer_decline_work(bus):
    """Routing depends on a peer's answer, which is only known at runtime."""

    def reasoning(msg: AgentMessage):
        if msg.message_type != MessageType.NEGOTIATION_REQUEST:
            return None
        request = msg.payload_as(NegotiationRequest)
        cheap = request.context.get("candidate_count", 0) <= 1
        return msg.reply(
            MessageType.NEGOTIATION_RESPONSE,
            NegotiationResponse(
                accepted=not cheap,
                rationale="not worth the budget" if cheap else "accepted",
                counter_proposal="REPORT_AS_LOW_SIGNAL" if cheap else None,
            ),
            sender=AgentID.REASON,
        )

    bus.register(AgentID.REASON, reasoning, capabilities=("patch.reasoning",))

    declined = bus.request(
        sender=AgentID.ORCHESTRATOR,
        receiver=AgentID.REASON,
        message_type=MessageType.NEGOTIATION_REQUEST,
        payload=NegotiationRequest(
            proposal="ANALYSE_LOW_SIGNAL_SET", rationale="1 low-confidence hit",
            context={"candidate_count": 1},
        ),
        expect=MessageType.NEGOTIATION_RESPONSE,
    ).payload_as(NegotiationResponse)
    assert declined.accepted is False
    assert declined.counter_proposal == "REPORT_AS_LOW_SIGNAL"

    accepted = bus.request(
        sender=AgentID.ORCHESTRATOR,
        receiver=AgentID.REASON,
        message_type=MessageType.NEGOTIATION_REQUEST,
        payload=NegotiationRequest(
            proposal="ANALYSE_LOW_SIGNAL_SET", rationale="9 hits",
            context={"candidate_count": 9},
        ),
        expect=MessageType.NEGOTIATION_RESPONSE,
    ).payload_as(NegotiationResponse)
    assert accepted.accepted is True


# ---------------------------------------------------------------------------
# Bus as a security boundary
# ---------------------------------------------------------------------------
def test_tampered_message_is_refused_on_delivery(bus, ctx):
    delivered = []
    bus.register(AgentID.REPORT, lambda m: delivered.append(m) or None)

    msg = AgentMessage.build(
        run_id=ctx.run_id,
        sender=AgentID.DETECT,
        receiver=AgentID.REPORT,
        message_type=MessageType.DECISION,
        payload=DecisionPayload(decision="NONE_FOUND", reason="clean"),
    ).seal(ctx)
    msg.payload["reason"] = "definitely clean, ship it"

    with pytest.raises(IntegrityError):
        bus.publish(msg)
    assert delivered == []
    assert bus.rejected


def test_replayed_message_is_refused(bus, ctx):
    bus.register(AgentID.REPORT, lambda m: None)
    msg = AgentMessage.build(
        run_id=ctx.run_id,
        sender=AgentID.DETECT,
        receiver=AgentID.REPORT,
        message_type=MessageType.DECISION,
        payload=DecisionPayload(decision="WORTH_ESCALATING", reason="once"),
    ).seal(ctx)

    bus.publish(msg)
    with pytest.raises(ReplayError):
        bus.publish(msg)  # perfectly valid signature, already used


def test_expired_message_is_refused(bus, ctx):
    bus.register(AgentID.REPORT, lambda m: None)
    msg = AgentMessage.build(
        run_id=ctx.run_id,
        sender=AgentID.DETECT,
        receiver=AgentID.REPORT,
        message_type=MessageType.DECISION,
        payload=DecisionPayload(decision="OK", reason="stale"),
        ttl_seconds=1.0,
    )
    msg.created_at -= 60
    msg.seal(ctx)

    with pytest.raises(ReplayError):
        bus.publish(msg)


def test_cross_run_injection_is_refused(bus, ctx):
    other = SaltContext.generate(run_id="some-other-run")
    msg = AgentMessage.build(
        run_id=other.run_id,
        sender=AgentID.DETECT,
        receiver=AgentID.REPORT,
        message_type=MessageType.DECISION,
        payload=DecisionPayload(decision="OK", reason="from another run"),
    ).seal(other)

    with pytest.raises(IntegrityError):
        bus.publish(msg)


def test_unrouted_message_is_dead_lettered_not_lost(bus, ctx):
    bus.send(
        sender=AgentID.DETECT,
        receiver=AgentID.REPORT,  # never registered
        message_type=MessageType.DECISION,
        payload=DecisionPayload(decision="OK", reason="nobody home"),
    )
    assert len(bus.dead_letters) == 1


def test_transcript_verification_covers_every_message(bus, ctx):
    bus.register(AgentID.ORCHESTRATOR, lambda m: None)
    for i in range(3):
        bus.send(
            sender=AgentID.DETECT,
            receiver=AgentID.ORCHESTRATOR,
            message_type=MessageType.DECISION,
            payload=DecisionPayload(decision=f"D{i}", reason="r"),
        )

    ok, _ = bus.verify_transcript()
    assert ok is True

    # Retroactively edit a recorded message, as an attacker with memory access
    # or a buggy agent would.
    bus.transcript[-1].payload["decision"] = "TAMPERED"
    ok, note = bus.verify_transcript()
    assert ok is False
    assert "failed verification" in note


def test_registration_is_audited_but_not_pushed_to_the_live_feed(ctx):
    """Capability announcements belong in the transcript and audit chain, not
    in the operator's live decision feed."""
    seen = []
    bus = MessageBus(ctx, on_message=seen.append)
    bus.register(AgentID.DETECT, _validator(False), capabilities=(CAP_RECHECK,))

    assert seen == []
    assert any(m.message_type == MessageType.CAPABILITY_ANNOUNCE for m in bus.transcript)
    assert any(e.action == "REGISTER" for e in bus.audit.entries)
