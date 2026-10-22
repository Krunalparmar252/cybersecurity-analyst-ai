"""
analyst.protocol — the formal inter-agent communication layer.

Three concerns, deliberately kept in three modules:

    crypto.py    salting, sealing, salt rotation, audit hash chain
    envelope.py  the Pydantic AgentMessage envelope + payload schema registry
    bus.py       capability-routed A2A delivery with integrity enforcement

Import from this package, not from the submodules, in agent code — it keeps the
public surface small and lets the internals move.
"""

from analyst.protocol.crypto import (
    HASH_VERSION,
    MODE_HMAC,
    MODE_SALT_PREFIX,
    AuditEntry,
    AuditLog,
    IntegrityError,
    SaltContext,
    canonical_bytes,
    hmac_sha256,
    manifest_digest,
    salted_file_digest,
    salted_sha256,
    verify_report,
    write_verification_sidecar,
)
from analyst.protocol.envelope import (
    PROTOCOL_VERSION,
    AgentID,
    AgentMessage,
    BasePayload,
    CapabilityAnnounce,
    DecisionPayload,
    ErrorPayload,
    ExploitVerifyRequestPayload,
    ExploitVerifyResultPayload,
    FallbackNotice,
    MessageIntegrity,
    MessageType,
    NegotiationRequest,
    NegotiationResponse,
    RuleRecheckRequest,
    RuleRecheckResponse,
    StateHandoffPayload,
    TriageItem,
    TriageRequest,
    TriageResponse,
    TriageVerdict,
    registered_payload_schemas,
)
from analyst.protocol.bus import (
    AgentEndpoint,
    BusError,
    MessageBus,
    NoRouteError,
    ReplayError,
)

# Capability names used for bus routing. Constants, not string literals at call
# sites, so a typo is an ImportError instead of a silent NoRouteError.
CAP_REPO_INGEST = "repo.ingest"
CAP_RULE_SCAN = "rule.scan"
CAP_RULE_RECHECK = "rule.recheck"
CAP_PATCH_REASONING = "patch.reasoning"
CAP_REPORT_RENDER = "report.render"
CAP_FINDING_TRIAGE = "finding.triage"
CAP_EXPLOIT_VERIFY = "exploit.verify"

__all__ = [
    "HASH_VERSION",
    "MODE_HMAC",
    "MODE_SALT_PREFIX",
    "PROTOCOL_VERSION",
    "AgentEndpoint",
    "AgentID",
    "AgentMessage",
    "AuditEntry",
    "AuditLog",
    "BasePayload",
    "BusError",
    "CAP_EXPLOIT_VERIFY",
    "CAP_PATCH_REASONING",
    "CAP_REPORT_RENDER",
    "CAP_REPO_INGEST",
    "CAP_RULE_RECHECK",
    "CAP_RULE_SCAN",
    "CapabilityAnnounce",
    "DecisionPayload",
    "ErrorPayload",
    "ExploitVerifyRequestPayload",
    "ExploitVerifyResultPayload",
    "FallbackNotice",
    "IntegrityError",
    "MessageBus",
    "MessageIntegrity",
    "MessageType",
    "NegotiationRequest",
    "NegotiationResponse",
    "NoRouteError",
    "ReplayError",
    "TriageItem",
    "TriageRequest",
    "TriageResponse",
    "TriageVerdict",
    "CAP_FINDING_TRIAGE",
    "RuleRecheckRequest",
    "RuleRecheckResponse",
    "SaltContext",
    "StateHandoffPayload",
    "canonical_bytes",
    "hmac_sha256",
    "manifest_digest",
    "registered_payload_schemas",
    "salted_file_digest",
    "salted_sha256",
    "verify_report",
    "write_verification_sidecar",
]
