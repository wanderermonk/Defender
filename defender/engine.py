"""Core detection engine: alert model, severity scoring, mitigation knowledge
base, and the orchestrator that fans an input out to every detector.

The engine is deliberately dependency-free (standard library only) so it can
run anywhere. Detectors are heuristic/rule based; an optional LLM hook can be
wired in by any detector via `defender.llm_hook`.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Callable, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Map a 0..100 confidence/risk score to a severity band."""
        if score >= 85:
            return cls.CRITICAL
        if score >= 65:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.INFO


@dataclass
class Alert:
    """A single detection. `mitigations` are concrete remediation steps."""

    detector: str                       # which module raised it
    category: str                       # e.g. "credential_stuffing"
    title: str
    description: str
    severity: Severity
    score: float                        # 0..100 confidence/risk
    indicators: list[str] = field(default_factory=list)   # evidence
    mitigations: list[str] = field(default_factory=list)
    source: Optional[str] = None        # IP / sender / host / etc.
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["severity_level"] = int(self.severity)
        return d


# --------------------------------------------------------------------------
# Mitigation knowledge base — maps a detection category to remediation advice.
# Detectors reference these by key so guidance stays consistent and auditable.
# --------------------------------------------------------------------------

MITIGATIONS: dict[str, list[str]] = {
    "credential_stuffing": [
        "Enforce rate limiting and exponential backoff on the auth endpoint.",
        "Require MFA for all accounts; block logins from the offending IP/ASN.",
        "Enable breached-password screening and lock accounts after N failures.",
    ],
    "automated_recon": [
        "Deploy a WAF rule to block known scanner user-agents and 404 sweeps.",
        "Tarpit or null-route the source IP; alert the SOC for correlation.",
        "Remove verbose error pages and directory listings that aid mapping.",
    ],
    "injection_payload": [
        "Use parameterized queries / prepared statements; never concatenate input.",
        "Add a WAF signature for the observed payload class (SQLi/XSS/SSTI).",
        "Validate and canonicalize input server-side; apply output encoding.",
    ],
    "traffic_anomaly": [
        "Rate-limit by IP and token; enable adaptive throttling.",
        "Front the service with a CDN / DDoS scrubbing layer.",
        "Correlate the burst with auth and recon signals before blocking broadly.",
    ],
    "ai_phishing": [
        "Quarantine the message and warn the recipient; do not click links.",
        "Verify the sender out-of-band; check SPF/DKIM/DMARC alignment.",
        "Block the sending domain and any look-alike (homograph) domains.",
    ],
    "social_engineering": [
        "Treat urgency + payment/credential requests as high risk; verify by phone.",
        "Report to the security team; add sender to the blocklist.",
    ],
    "endpoint_anomaly": [
        "Isolate the host from the network pending triage.",
        "Capture volatile memory and the process tree before remediation.",
        "Kill the suspicious process and block its outbound destinations.",
    ],
    "data_exfiltration": [
        "Block the destination endpoint; revoke any exposed tokens/keys.",
        "Audit what data left and over which channel; notify incident response.",
    ],
    "prompt_injection": [
        "Strip/neutralize instruction-like text in untrusted inputs before the model.",
        "Enforce a strict system prompt and tool-use allowlist; sandbox tool calls.",
        "Add an output filter that blocks system-prompt leakage and secret patterns.",
    ],
    "jailbreak": [
        "Reject the request; log the pattern and add it to the input classifier.",
        "Rate-limit the session and require re-authentication for sensitive actions.",
    ],
    "llm_data_leak": [
        "Redact secrets/PII from model outputs with a DLP filter.",
        "Rotate any credential that appeared in output; review logging retention.",
    ],
}


def mitigations_for(category: str) -> list[str]:
    return MITIGATIONS.get(category, ["Review manually and escalate to the SOC."])


# --------------------------------------------------------------------------
# Optional LLM hook. Set defender.engine.llm_hook = callable(prompt)->str to
# let detectors request a second-opinion classification. Never required.
# --------------------------------------------------------------------------

llm_hook: Optional[Callable[[str], str]] = None


class Engine:
    """Registers detectors and dispatches inputs to the matching ones."""

    def __init__(self) -> None:
        self._detectors: dict[str, Any] = {}
        self.history: list[Alert] = []

    def register(self, detector: Any) -> None:
        self._detectors[detector.name] = detector

    @property
    def detectors(self) -> dict[str, Any]:
        return self._detectors

    def analyze(self, kind: str, payload: Any) -> list[Alert]:
        """Run a payload through the detector whose `kind` matches.

        kind is one of: "log", "content", "endpoint", "llm".
        """
        alerts: list[Alert] = []
        for det in self._detectors.values():
            if det.kind == kind:
                alerts.extend(det.analyze(payload) or [])
        alerts.sort(key=lambda a: (a.severity, a.score), reverse=True)
        self.history.extend(alerts)
        # keep history bounded
        if len(self.history) > 2000:
            self.history = self.history[-2000:]
        return alerts

    def reset(self) -> None:
        """Clear alert history and any detector state (e.g. the network
        baseline), so stats/gauge reflect a fresh picture."""
        self.history.clear()
        for det in self._detectors.values():
            reset = getattr(det, "reset", None)
            if callable(reset):
                reset()

    def stats(self) -> dict[str, Any]:
        counts = {s.label: 0 for s in Severity}
        by_detector: dict[str, int] = {}
        for a in self.history:
            counts[a.severity.label] += 1
            by_detector[a.detector] = by_detector.get(a.detector, 0) + 1
        return {
            "total": len(self.history),
            "by_severity": counts,
            "by_detector": by_detector,
        }
