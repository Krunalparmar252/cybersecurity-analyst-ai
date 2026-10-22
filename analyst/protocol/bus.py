"""
A2A Message Bus — the decoupling layer.

WHAT THIS REPLACES
------------------
Before: `pipeline.py` imported every agent directly and called them in a fixed
order, and `patch_loop.py` imported `run_detection` to check its own work. Every
edge in the system was a hardcoded Python import. "Agentic" routing amounted to
reading a returned string and choosing which hardcoded call to make next.

After: agents register with the bus under an address and a set of *capabilities*.
Anything that needs work done asks the bus for a capability ("rule.recheck") and
the bus resolves it to whichever agent announced it. The caller never imports the
callee. Swapping the detection agent for a different implementation, or adding a
second validator that votes, is a registration change — not a code change in the
caller.

WHY SYNCHRONOUS AND IN-PROCESS
------------------------------
`request()` blocks until the peer handler returns. The pipeline is a bounded,
four-agent system running in one process; an async broker (Redis/NATS) would add
deployment surface and failure modes with no behavioural gain at this scale. The
envelope format is deliberately transport-agnostic (pure JSON, addressed,
correlated, sealed), so moving to a real broker later is a bus swap, not a
protocol redesign. Say this plainly if asked why there is no queue.

SECURITY PROPERTIES ENFORCED HERE
---------------------------------
1. Integrity  — every message is verified against the run salt before delivery.
                A message whose payload was mutated after sealing is dropped.
2. Anti-replay— message_ids are single-use per run. Re-submitting a captured
                message (the classic replay) is rejected even though its
                signature is perfectly valid.
3. Freshness  — messages past their TTL are rejected.
4. Provenance — `run_id` on the envelope must match the bus's run. A message
                from an earlier run cannot be injected into this one.
5. Audit      — every accepted or rejected delivery is appended to the salted
                hash chain, so the transcript itself is tamper-evident.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from analyst.protocol.crypto import AuditLog, IntegrityError, SaltContext
from analyst.protocol.envelope import (
    AgentID,
    AgentMessage,
    BasePayload,
    CapabilityAnnounce,
    ErrorPayload,
    MessageType,
)

Handler = Callable[[AgentMessage], Optional[AgentMessage]]


class BusError(Exception):
    """Base for routing failures."""


class NoRouteError(BusError):
    """No agent is registered for the requested address or capability."""


class ReplayError(BusError):
    """A message_id was delivered twice, or a message outlived its TTL."""


@dataclass
class AgentEndpoint:
    agent: AgentID
    handler: Handler
    capabilities: frozenset[str] = field(default_factory=frozenset)


class MessageBus:
    """In-process, capability-routed, integrity-enforcing message bus."""

    def __init__(
        self,
        ctx: SaltContext,
        audit: Optional[AuditLog] = None,
        on_message: Optional[Callable[[dict], None]] = None,
        strict: bool = True,
    ):
        self.ctx = ctx
        self.run_id = ctx.run_id
        self.audit = audit or AuditLog(ctx, stream_id="a2a")
        self.on_message = on_message
        # strict=True drops messages that fail verification. strict=False logs
        # the violation and delivers anyway — only ever useful for debugging a
        # salt-rotation bug; never enable it in a scanning run.
        self.strict = strict

        self._endpoints: dict[AgentID, AgentEndpoint] = {}
        self._capabilities: dict[str, AgentID] = {}
        self._seen_ids: set[str] = set()
        self._lock = threading.RLock()

        self.transcript: list[AgentMessage] = []
        self.dead_letters: list[tuple[AgentMessage, str]] = []
        self.rejected: list[tuple[str, str]] = []  # (message_id, reason)

    # -- registration --------------------------------------------------
    def register(
        self,
        agent: AgentID,
        handler: Handler,
        capabilities: tuple[str, ...] = (),
    ) -> None:
        """Register an agent endpoint and announce its capabilities."""
        with self._lock:
            self._endpoints[agent] = AgentEndpoint(
                agent=agent, handler=handler, capabilities=frozenset(capabilities)
            )
            for cap in capabilities:
                # Last registration wins; a real deployment would keep a list
                # and load-balance, which is why resolve() is a separate method.
                self._capabilities[cap] = agent
        self.audit.append(
            actor=agent.value,
            action="REGISTER",
            capabilities=sorted(capabilities),
        )
        self._record(
            AgentMessage.build(
                run_id=self.run_id,
                sender=agent,
                receiver=AgentID.BROADCAST,
                message_type=MessageType.CAPABILITY_ANNOUNCE,
                payload=CapabilityAnnounce(agent=agent, capabilities=sorted(capabilities)),
            ).seal(self.ctx),
            # Registration is wiring, not agent activity: it belongs in the
            # transcript and audit chain, but pushing it to on_message would
            # spam the live CLI/dashboard feed before any work has happened.
            notify=False,
        )

    def resolve(self, capability: str) -> AgentID:
        with self._lock:
            agent = self._capabilities.get(capability)
        if agent is None:
            raise NoRouteError(
                f"No agent provides capability {capability!r}. Registered: "
                f"{sorted(self._capabilities)}"
            )
        return agent

    def capabilities(self) -> dict[str, str]:
        with self._lock:
            return {cap: agent.value for cap, agent in sorted(self._capabilities.items())}

    # -- internal ------------------------------------------------------
    def _record(self, msg: AgentMessage, notify: bool = True) -> None:
        self.transcript.append(msg)
        if notify and self.on_message:
            # Legacy projection keeps the existing CLI/dashboard/test consumers
            # working unchanged while carrying the new protocol fields.
            self.on_message(msg.to_legacy_dict())

    def _admit(self, msg: AgentMessage) -> None:
        """Gatekeeping applied to every message before it is recorded or
        delivered. Raises on violation; the caller decides fatal vs. logged."""
        if msg.run_id != self.run_id:
            raise IntegrityError(
                f"Message {msg.message_id} carries run_id {msg.run_id!r} but this "
                f"bus is serving run {self.run_id!r} — cross-run injection refused."
            )
        if msg.is_expired():
            raise ReplayError(
                f"Message {msg.message_id} expired "
                f"({time.time() - msg.created_at:.0f}s > TTL {msg.ttl_seconds:.0f}s)."
            )
        with self._lock:
            if msg.message_id in self._seen_ids:
                raise ReplayError(
                    f"Message {msg.message_id} has already been delivered in this "
                    f"run — replay refused."
                )
        msg.verify_or_raise(self.ctx)
        with self._lock:
            self._seen_ids.add(msg.message_id)

    def _reject(self, msg: AgentMessage, exc: Exception) -> None:
        self.rejected.append((msg.message_id, str(exc)))
        self.audit.append(
            actor="BUS",
            action="REJECT",
            message_id=msg.message_id,
            sender=msg.sender.value,
            receiver=msg.receiver.value,
            reason=str(exc),
        )

    # -- send / request ------------------------------------------------
    def publish(self, msg: AgentMessage) -> Optional[AgentMessage]:
        """Seal (if needed), admit, record, deliver. Returns the handler's
        response message if it produced one."""
        if msg.integrity is None:
            msg.seal(self.ctx)

        try:
            self._admit(msg)
        except (IntegrityError, ReplayError) as exc:
            self._reject(msg, exc)
            if self.strict:
                raise
        self._record(msg)
        self.audit.append(
            actor=msg.sender.value,
            action=f"SEND:{msg.message_type.value}",
            receiver=msg.receiver.value,
            message_id=msg.message_id,
            correlation_id=msg.correlation_id,
            payload_type=msg.payload_type,
            signature=msg.integrity.signature if msg.integrity else None,
        )

        if msg.receiver == AgentID.BROADCAST:
            with self._lock:
                endpoints = list(self._endpoints.values())
            for ep in endpoints:
                if ep.agent != msg.sender:
                    ep.handler(msg)
            return None

        with self._lock:
            endpoint = self._endpoints.get(msg.receiver)
        if endpoint is None:
            # Not fatal: the orchestrator legitimately posts DECISION messages
            # addressed to itself as the run's observable record before all
            # agents have registered.
            self.dead_letters.append((msg, f"no endpoint registered for {msg.receiver.value}"))
            return None

        response = endpoint.handler(msg)
        if response is not None:
            if response.integrity is None:
                response.seal(self.ctx)
            try:
                self._admit(response)
            except (IntegrityError, ReplayError) as exc:
                self._reject(response, exc)
                if self.strict:
                    raise
            self._record(response)
            self.audit.append(
                actor=response.sender.value,
                action=f"REPLY:{response.message_type.value}",
                receiver=response.receiver.value,
                message_id=response.message_id,
                correlation_id=response.correlation_id,
                causation_id=response.causation_id,
            )
        return response

    def send(
        self,
        sender: AgentID,
        receiver: AgentID,
        message_type: MessageType,
        payload: BasePayload,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
    ) -> Optional[AgentMessage]:
        msg = AgentMessage.build(
            run_id=self.run_id,
            sender=sender,
            receiver=receiver,
            message_type=message_type,
            payload=payload,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )
        return self.publish(msg)

    def request(
        self,
        sender: AgentID,
        receiver: AgentID,
        message_type: MessageType,
        payload: BasePayload,
        expect: Optional[MessageType] = None,
        correlation_id: Optional[str] = None,
    ) -> AgentMessage:
        """Synchronous request/response. Raises NoRouteError if the peer does
        not answer — an unanswered validation request must never be silently
        read as 'all clear'."""
        response = self.send(
            sender=sender,
            receiver=receiver,
            message_type=message_type,
            payload=payload,
            correlation_id=correlation_id,
        )
        if response is None:
            raise NoRouteError(
                f"{receiver.value} did not respond to {message_type.value} from "
                f"{sender.value}."
            )
        if expect is not None and response.message_type != expect:
            raise BusError(
                f"Expected {expect.value} from {receiver.value}, got "
                f"{response.message_type.value}."
            )
        if response.correlation_id != (correlation_id or response.correlation_id):
            raise BusError("Response correlation_id does not match the request.")
        return response

    def request_capability(
        self,
        sender: AgentID,
        capability: str,
        message_type: MessageType,
        payload: BasePayload,
        expect: Optional[MessageType] = None,
    ) -> AgentMessage:
        """Capability-routed request — the caller names the *service* it needs,
        not the agent. This is the decoupling that requirement 1 asks for."""
        receiver = self.resolve(capability)
        return self.request(
            sender=sender,
            receiver=receiver,
            message_type=message_type,
            payload=payload,
            expect=expect,
        )

    def report_error(self, sender: AgentID, error_class: str, detail: str, fatal: bool = False) -> None:
        self.send(
            sender=sender,
            receiver=AgentID.ORCHESTRATOR,
            message_type=MessageType.ERROR,
            payload=ErrorPayload(error_class=error_class, detail=detail, fatal=fatal),
        )

    # -- inspection ----------------------------------------------------
    def legacy_messages(self) -> list[dict]:
        """Whole transcript in the pre-protocol dict shape."""
        return [m.to_legacy_dict() for m in self.transcript]

    def routing_log(self) -> list[str]:
        """Human-readable lines for the CLI, now showing real addressing."""
        lines = []
        for m in self.transcript:
            legacy = m.to_legacy_dict()
            lines.append(
                f"{m.sender.value} -> {m.receiver.value} "
                f"[{m.message_type.value}] {legacy['decision']} — {legacy['reason']}"
            )
        return lines

    def verify_transcript(self) -> tuple[bool, str]:
        """Re-verify every recorded message plus the audit chain. Called at the
        end of a run: if this fails, the run's conclusions cannot be trusted."""
        for msg in self.transcript:
            if not msg.verify(self.ctx):
                return False, (
                    f"Message {msg.message_id} ({msg.sender.value} -> "
                    f"{msg.receiver.value}) failed verification."
                )
        return self.audit.verify()

    def stats(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "messages": len(self.transcript),
            "rejected": len(self.rejected),
            "dead_letters": len(self.dead_letters),
            "capabilities": self.capabilities(),
            "salt": self.ctx.descriptor(),
            "audit_head": self.audit.head(),
        }
