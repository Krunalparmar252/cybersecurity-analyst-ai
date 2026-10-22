"""
Inter-Agent Communication Protocol — strict Pydantic message envelopes.

WHAT CHANGED AND WHY
--------------------
The previous message bus was a list of bare dicts:

    {"agent": "DETECT", "decision": "...", "reason": "...", "timestamp": 1.0}

That is a logging format, not a protocol. It has no addressing (nobody is the
receiver), no message type (everything is a "decision"), no correlation (you
cannot tie a response back to a request), and no integrity (any component can
append anything, and nothing detects an edit).

This module defines the real thing. An `AgentMessage` is:

    sender -> receiver, typed, correlated, sealed.

DESIGN DECISIONS WORTH DEFENDING
--------------------------------
1. `payload` travels as a plain dict on the wire, tagged with `payload_type`,
   and is validated against a registered Pydantic model at construction time.
   The alternative — typing `payload` as a Union of every payload model — makes
   Pydantic guess which member to coerce into, and smart-union resolution
   silently picks the wrong model when two payloads share field names. An
   explicit schema-id + registry is how versioned wire protocols actually work
   (cf. Avro/Protobuf schema registries), and it keeps the envelope stable when
   a new payload type is added.

2. Every payload model sets `extra="forbid"`. An unexpected field is a protocol
   violation, not something to silently carry along: in a security tool, a
   field the receiver ignores is a field an attacker can use to smuggle state.

3. `integrity` is computed over the canonical form of the *entire semantic
   content* of the message (sender, receiver, type, payload, correlation ids,
   run id, timestamp) — not just the payload. Sealing only the payload would
   leave an attacker free to re-address a validly-sealed message to a different
   receiver, which is exactly the state-spoofing case we care about.

4. Messages are immutable once sealed (`model_config frozen` is deliberately
   NOT used, because sealing itself must write a field — instead `seal()`
   refuses to run twice and `verify()` is the only trusted read path).
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, ClassVar, Literal, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, field_validator

from analyst.protocol.crypto import IntegrityError, SaltContext

PROTOCOL_VERSION = "1.0"

# A message older than this is refused by the bus. Bounds how long a captured
# message stays replayable even if the salt has not rotated.
DEFAULT_TTL_SECONDS = 900.0


class AgentID(str, Enum):
    """Addressable participants. `BROADCAST` is a reserved receiver, never a
    sender."""

    ORCHESTRATOR = "ORCHESTRATOR"
    INGEST = "INGEST"
    DETECT = "DETECT"
    REASON = "REASON"
    REPORT = "REPORT"
    TRIAGE = "TRIAGE"
    EXPLOIT = "EXPLOIT"
    BROADCAST = "BROADCAST"


class MessageType(str, Enum):
    """The verbs of the protocol.

    STATE_HANDOFF / DECISION carry the pipeline forward. The three REQUEST /
    RESPONSE pairs are what make this A2A rather than a pipeline: an agent can
    ask a *peer* a question mid-run and change its own behaviour based on the
    answer.
    """

    STATE_HANDOFF = "STATE_HANDOFF"
    DECISION = "DECISION"
    PEER_VALIDATION_REQUEST = "PEER_VALIDATION_REQUEST"
    PEER_VALIDATION_RESPONSE = "PEER_VALIDATION_RESPONSE"
    NEGOTIATION_REQUEST = "NEGOTIATION_REQUEST"
    NEGOTIATION_RESPONSE = "NEGOTIATION_RESPONSE"
    TRIAGE_REQUEST = "TRIAGE_REQUEST"
    TRIAGE_RESPONSE = "TRIAGE_RESPONSE"
    CAPABILITY_QUERY = "CAPABILITY_QUERY"
    CAPABILITY_ANNOUNCE = "CAPABILITY_ANNOUNCE"
    FALLBACK_NOTICE = "FALLBACK_NOTICE"
    ERROR = "ERROR"
    EXPLOIT_VERIFY_REQUEST = "EXPLOIT_VERIFY_REQUEST"
    EXPLOIT_VERIFY_RESPONSE = "EXPLOIT_VERIFY_RESPONSE"


# ---------------------------------------------------------------------------
# Payload schemas
# ---------------------------------------------------------------------------
_PAYLOAD_REGISTRY: dict[str, Type["BasePayload"]] = {}


class BasePayload(BaseModel):
    """Base for every payload body. Subclasses declare `schema_name` and are
    auto-registered so the envelope can validate by tag."""

    model_config = ConfigDict(extra="forbid")

    schema_name: ClassVar[str] = "base"

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        name = getattr(cls, "schema_name", None)
        if name and name != "base":
            _PAYLOAD_REGISTRY[name] = cls


class DecisionPayload(BasePayload):
    """An agent's own OBSERVE -> DECIDE output. Replaces the old bare dict."""

    schema_name: ClassVar[str] = "agent.decision.v1"

    decision: str
    reason: str
    metrics: dict[str, Any] = Field(default_factory=dict)
    artifact_digests: dict[str, str] = Field(default_factory=dict)


class StateHandoffPayload(BasePayload):
    """Hands an agent's sealed output to the next agent. Carries digests, not
    the data itself — the data stays in-process; the digest is what the
    receiver checks so it can detect a swapped or replayed state object."""

    schema_name: ClassVar[str] = "agent.state_handoff.v1"

    stage: str
    summary: str
    item_count: int = 0
    state_digest: str
    manifest_digest: Optional[str] = None


class RuleRecheckRequest(BasePayload):
    """REASON -> DETECT: 'I applied a patch in this sandbox; does your rule
    still fire?' This is the call that used to be a hardcoded import of
    run_detection() inside patch_loop.py."""

    schema_name: ClassVar[str] = "validation.rule_recheck.request.v1"

    rule_id: str
    file: str
    sandbox_root: str
    attempt: int = 1
    patched_source_digest: Optional[str] = None


class TriageItem(BaseModel):
    """One confirmed finding as TRIAGE sees it (no source code, no patch text)."""

    model_config = ConfigDict(extra="forbid")

    index: int
    rule_id: str
    vuln_class: str
    file: str
    line: int
    severity: Optional[str] = None
    loop_status: Optional[str] = None  # ACCEPTED | MANUAL_REVIEW_REQUIRED | SKIPPED_NO_PATCH | ...
    analysis_tier: str = "T0_LLM"


class TriageVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: int
    priority: str  # "P1" (fix first) .. "P4"
    rank: int  # 1 = fix first, unique per response
    rationale: str


class TriageRequest(BasePayload):
    """ORCHESTRATOR -> whoever provides `finding.triage`."""

    schema_name: ClassVar[str] = "triage.request.v1"

    items: list[TriageItem]


class TriageResponse(BasePayload):
    """TRIAGE -> ORCHESTRATOR: a priority and rank per finding."""

    schema_name: ClassVar[str] = "triage.response.v1"

    verdicts: list[TriageVerdict]
    method: str  # "deterministic" | "scorer" | "deterministic_fallback"
    fallback_reason: Optional[str] = None
    summary: str = ""


class RuleRecheckResponse(BasePayload):
    """DETECT -> REASON: the peer's verdict, with evidence."""

    schema_name: ClassVar[str] = "validation.rule_recheck.response.v1"

    rule_id: str
    file: str
    still_fires: bool
    verdict: str  # "RESOLVED" | "STILL_VULNERABLE" | "INDETERMINATE"
    evidence: str = ""
    candidates_seen: int = 0


class ExploitVerifyRequestPayload(BasePayload):
    """Request to verify an exploit against a sandbox environment."""

    schema_name: ClassVar[str] = "exploitation.verify.request.v1"

    finding_id: str
    rule_id: str
    file: str
    sandbox_root: str
    patched_source_digest: Optional[str] = None
    attempt: int = 1


class ExploitVerifyResultPayload(BasePayload):
    """Result of an exploit verification attempt."""

    schema_name: ClassVar[str] = "exploitation.verify.result.v1"

    finding_id: str
    rule_id: str
    file: str
    verdict: Literal["CONFIRMED_VULNERABLE_THEN_FIXED", "BYPASS_FOUND", "INCONCLUSIVE", "STATIC_CHECK_ONLY"]
    payload_used: Optional[str] = None
    evidence: str
    tool_calls_used: int
    elapsed_seconds: float


class NegotiationRequest(BasePayload):
    """One agent proposes; the peer may accept, decline or counter. Used when
    DETECT reports LOW_SIGNAL and the orchestrator needs REASON to decide
    whether spending LLM budget on a thin candidate set is worth it."""

    schema_name: ClassVar[str] = "negotiation.request.v1"

    proposal: str
    rationale: str
    context: dict[str, Any] = Field(default_factory=dict)


class NegotiationResponse(BasePayload):
    schema_name: ClassVar[str] = "negotiation.response.v1"

    accepted: bool
    rationale: str
    counter_proposal: Optional[str] = None
    conditions: list[str] = Field(default_factory=list)


class CapabilityAnnounce(BasePayload):
    schema_name: ClassVar[str] = "capability.announce.v1"

    agent: AgentID
    capabilities: list[str]


class FallbackNotice(BasePayload):
    """Emitted whenever the system degrades from one tier to a lower one. This
    is what makes fallbacks auditable instead of invisible."""

    schema_name: ClassVar[str] = "resilience.fallback_notice.v1"

    tier_from: str
    tier_to: str
    trigger: str
    detail: str
    recoverable: bool = True


class ErrorPayload(BasePayload):
    schema_name: ClassVar[str] = "error.v1"

    error_class: str
    detail: str
    fatal: bool = False


# ---------------------------------------------------------------------------
# Integrity block
# ---------------------------------------------------------------------------
class MessageIntegrity(BaseModel):
    """The tamper-proofing attached to a sealed message."""

    model_config = ConfigDict(extra="forbid")

    algorithm: str
    salt_fingerprint: str
    payload_digest: str  # seal over the payload alone (cheap partial check)
    signature: str  # seal over the full semantic content (authoritative)
    sealed_at: float


# ---------------------------------------------------------------------------
# The envelope
# ---------------------------------------------------------------------------
class AgentMessage(BaseModel):
    """A single addressed, typed, correlated, tamper-evident message."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    protocol_version: str = PROTOCOL_VERSION
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    causation_id: Optional[str] = None

    run_id: str
    sender: AgentID
    receiver: AgentID
    message_type: MessageType

    payload_type: str
    payload: dict[str, Any]

    created_at: float = Field(default_factory=time.time)
    ttl_seconds: float = DEFAULT_TTL_SECONDS

    integrity: Optional[MessageIntegrity] = None

    # -- validation ----------------------------------------------------
    @field_validator("payload_type")
    @classmethod
    def _known_payload_type(cls, v: str) -> str:
        if v not in _PAYLOAD_REGISTRY:
            raise ValueError(
                f"Unknown payload_type {v!r}. Register a BasePayload subclass "
                f"with that schema_name before sending it."
            )
        return v

    def model_post_init(self, __context: Any) -> None:
        # Validate the body against its declared schema at construction time,
        # so a malformed payload can never reach a handler.
        model = _PAYLOAD_REGISTRY[self.payload_type]
        model.model_validate(self.payload)
        if self.sender == AgentID.BROADCAST:
            raise ValueError("BROADCAST is a receiver-only address.")

    # -- construction --------------------------------------------------
    @classmethod
    def build(
        cls,
        run_id: str,
        sender: AgentID,
        receiver: AgentID,
        message_type: MessageType,
        payload: BasePayload,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ) -> "AgentMessage":
        kwargs: dict[str, Any] = {
            "run_id": run_id,
            "sender": sender,
            "receiver": receiver,
            "message_type": message_type,
            "payload_type": payload.schema_name,
            "payload": payload.model_dump(mode="json"),
            "causation_id": causation_id,
            "ttl_seconds": ttl_seconds,
        }
        if correlation_id:
            kwargs["correlation_id"] = correlation_id
        return cls(**kwargs)

    def reply(
        self,
        message_type: MessageType,
        payload: BasePayload,
        sender: Optional[AgentID] = None,
    ) -> "AgentMessage":
        """Build a correlated response. Keeps `correlation_id` (same
        conversation) and sets `causation_id` to this message (what caused
        the reply) — the two together give a full request/response trace."""
        return AgentMessage.build(
            run_id=self.run_id,
            sender=sender or self.receiver,
            receiver=self.sender,
            message_type=message_type,
            payload=payload,
            correlation_id=self.correlation_id,
            causation_id=self.message_id,
        )

    # -- typed payload access ------------------------------------------
    def parse_payload(self) -> BasePayload:
        """Return the payload as its registered Pydantic model."""
        return _PAYLOAD_REGISTRY[self.payload_type].model_validate(self.payload)

    def payload_as(self, model: Type[BasePayload]) -> BasePayload:
        """Parse, asserting the expected schema. Use this in handlers so a
        mis-routed message fails loudly instead of duck-typing its way
        through."""
        if self.payload_type != model.schema_name:
            raise ValueError(
                f"Expected payload {model.schema_name!r} but message carries "
                f"{self.payload_type!r}"
            )
        return model.model_validate(self.payload)

    # -- integrity -----------------------------------------------------
    def _signing_content(self) -> dict:
        """The exact semantic content covered by the signature. Note this
        includes addressing and correlation fields — re-addressing a sealed
        message invalidates it."""
        return {
            "protocol_version": self.protocol_version,
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "run_id": self.run_id,
            "sender": self.sender.value,
            "receiver": self.receiver.value,
            "message_type": self.message_type.value,
            "payload_type": self.payload_type,
            "payload": self.payload,
            "created_at": self.created_at,
            "ttl_seconds": self.ttl_seconds,
        }

    def seal(self, ctx: SaltContext) -> "AgentMessage":
        """Attach the integrity block. Idempotent-by-refusal: sealing twice is
        a bug (it would mean the message was mutated after sealing)."""
        if self.integrity is not None:
            raise IntegrityError(
                f"Message {self.message_id} is already sealed; mutating a sealed "
                f"message is forbidden — build a new message instead."
            )
        self.integrity = MessageIntegrity(
            algorithm=ctx.mode,
            salt_fingerprint=ctx.fingerprint(),
            payload_digest=ctx.seal(self.payload),
            signature=ctx.seal(self._signing_content()),
            sealed_at=time.time(),
        )
        return self

    def verify(self, ctx: SaltContext) -> bool:
        if self.integrity is None:
            return False
        if not ctx.verify(self.payload, self.integrity.payload_digest):
            return False
        return ctx.verify(self._signing_content(), self.integrity.signature)

    def verify_or_raise(self, ctx: SaltContext) -> None:
        if self.integrity is None:
            raise IntegrityError(
                f"Message {self.message_id} from {self.sender.value} is unsealed — "
                f"refusing to deliver."
            )
        if not self.verify(ctx):
            raise IntegrityError(
                f"Message {self.message_id} ({self.sender.value} -> "
                f"{self.receiver.value}, {self.message_type.value}) failed its "
                f"signature check: content was altered after sealing, or it was "
                f"sealed under a different run salt (spoof/replay)."
            )

    def is_expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) - self.created_at > self.ttl_seconds

    # -- interop -------------------------------------------------------
    def to_legacy_dict(self) -> dict:
        """Back-compatible projection for the existing CLI, dashboard and
        tests, which consume {"agent", "decision", "reason", "timestamp"}.
        Extra protocol fields are additive — old consumers ignore them, new
        ones (the dashboard's A2A view) read them."""
        body = self.payload
        decision = body.get("decision") or body.get("verdict") or self.message_type.value
        reason = (
            body.get("reason")
            or body.get("rationale")
            or body.get("summary")
            or body.get("detail")
            or body.get("evidence")
            or body.get("proposal")
            or (
                # Requests carry no prose field; synthesise one so the CLI and
                # dashboard show something meaningful instead of a blank line.
                f"{body.get('rule_id')} in {body.get('file')} (attempt {body.get('attempt')})"
                if "rule_id" in body
                else ""
            )
        )
        return {
            "agent": self.sender.value,
            "decision": decision,
            "reason": reason,
            "timestamp": self.created_at,
            # --- protocol fields (additive) ---
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "receiver": self.receiver.value,
            "message_type": self.message_type.value,
            "payload_type": self.payload_type,
            "payload": body,
            "signature": self.integrity.signature if self.integrity else None,
            "salt_fingerprint": self.integrity.salt_fingerprint if self.integrity else None,
        }


def registered_payload_schemas() -> dict[str, dict]:
    """Machine-readable protocol spec: schema name -> JSON Schema. Used by the
    docs generator and by the /protocol endpoint so clients can introspect the
    contract instead of reading source."""
    return {name: model.model_json_schema() for name, model in sorted(_PAYLOAD_REGISTRY.items())}
