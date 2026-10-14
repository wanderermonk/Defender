"""Outbound-connection behavioral baseline — merged from sentinel-desktop's
"AI anomaly detection": learn each app's normal set of destinations, then flag
a new/unusual destination once the learning window has passed.

Also screens destinations against IP reputation (blocklist / bogon / optional
geo) and flags C2-style ports and programs running from Temp/Downloads.

The baseline persists in memory for the engine's lifetime via a module-level
store; swap in a file/SQLite backend for production.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .base import Detector
from ..engine import Alert, Severity
from ..enrichment import IPReputation

_C2_PORTS = {4444, 1337, 31337, 5555, 6666, 9001, 8081, 50050}  # incl. Cobalt Strike default


class BaselineStore:
    """Per-app set of seen destinations + observation counts."""

    def __init__(self, learn_after: int = 20):
        self.seen: dict[str, set[str]] = defaultdict(set)
        self.obs: dict[str, int] = defaultdict(int)
        self.learn_after = learn_after   # observations before we trust the baseline

    def record(self, app: str, dest: str) -> bool:
        """Return True if `dest` is NEW for `app` after the learning window."""
        key = app or "unknown"
        is_new = dest not in self.seen[key]
        trusted = self.obs[key] >= self.learn_after
        self.seen[key].add(dest)
        self.obs[key] += 1
        return is_new and trusted


_STORE = BaselineStore()


class NetworkBaseline(Detector):
    name = "network"
    kind = "network"
    title = "Outbound Connection Monitor"
    description = "Learns each app's normal destinations and flags new or malicious outbound connections."

    def __init__(self, reputation: IPReputation | None = None):
        self.rep = reputation or IPReputation()

    def analyze(self, payload: Any) -> list[Alert]:
        """payload: {
             "host": str,
             "connections": [ {app, path, raddr, rport} ]
           }"""
        if not isinstance(payload, dict):
            return []
        host = str(payload.get("host", "this-host"))
        alerts: list[Alert] = []

        for c in payload.get("connections") or []:
            app = str(c.get("app", "unknown"))
            path = str(c.get("path", ""))
            raddr = str(c.get("raddr", ""))
            try:
                rport = int(c.get("rport")) if c.get("rport") is not None else None
            except (ValueError, TypeError):
                rport = None
            dest = f"{raddr}:{rport}" if rport else raddr

            indicators: list[str] = [f"app={app}", f"dest={dest}"]
            score = 0.0
            reasons: list[str] = []

            rep = self.rep.classify(raddr)
            if "on-blocklist" in rep["flags"]:
                score = max(score, 90); reasons.append("destination on threat blocklist")
            if "bogon/reserved" in rep["flags"]:
                score = max(score, 55); reasons.append("destination is a bogon/reserved address")
            if rep.get("geo") and (rep["geo"].get("proxy") or rep["geo"].get("hosting")):
                score = max(score, 50); reasons.append("destination is a proxy/hosting/VPN endpoint")

            if rport in _C2_PORTS:
                score = max(score, 80); reasons.append(f"C2-style port {rport}")

            low = path.lower()
            if any(seg in low for seg in ("\\temp\\", "/tmp/", "\\downloads\\", "/downloads/", "appdata\\local\\temp")):
                score = max(score, 70); reasons.append("process runs from Temp/Downloads")

            if self.record(app, dest) if False else _STORE.record(app, dest):
                score = max(score, 45); reasons.append("new destination vs. learned baseline")

            if score <= 0:
                continue
            cat = "data_exfiltration" if score >= 70 else "endpoint_anomaly"
            alerts.append(Alert(
                detector=self.name, category=cat,
                title=f"Anomalous outbound: {app} → {dest}",
                description=f"{app} on {host} connected to {dest}. " + "; ".join(reasons) + ".",
                severity=Severity.from_score(score), score=round(score, 1),
                indicators=indicators + reasons,
                mitigations=[
                    f"Block the destination (reversible): firewall deny to {raddr}.",
                    "Verify the process is legitimate; if not, kill it and isolate the host.",
                    "If the app is trusted, mark the destination as trusted to refine the baseline.",
                ],
                source=host,
            ))
        alerts.sort(key=lambda a: (a.severity, a.score), reverse=True)
        return alerts
