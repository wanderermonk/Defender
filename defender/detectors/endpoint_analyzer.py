"""Endpoint / host behaviour analyzer.

Takes a snapshot of a host's state and flags behaviour consistent with an
automated / AI-orchestrated intrusion:

  * suspicious processes      — LOLBins, encoded PowerShell, reverse-shell tooling
  * anomalous outbound        — connections to odd ports / known-bad destinations
  * persistence & tampering   — cron/launchd/registry writes, disabled defenses
  * mass file activity        — rapid create/modify (ransomware-like) counts

Input: a dict snapshot. All keys optional:
  {
    "processes":   [ {"name","cmdline","user"}... ]  or  ["name cmdline", ...],
    "connections": [ {"raddr","rport","state"}... ]  or  ["1.2.3.4:4444", ...],
    "file_events": int (count of file create/modify in the window),
    "host": "hostname"
  }
"""

from __future__ import annotations

import re
from typing import Any

from .base import Detector

_SUSPICIOUS_PROC = re.compile(
    r"(powershell.*-enc|powershell.*-e[nc]* [A-Za-z0-9+/=]{40,}|"
    r"certutil.*-urlcache|bitsadmin|mshta|regsvr32.*scrobj|"
    r"nc\b|ncat|/dev/tcp/|bash -i|sh -i|socat|"
    r"mimikatz|lazagne|rundll32.*javascript|wmic.*process call create|"
    r"base64 -d|curl.*\|\s*sh|wget.*\|\s*sh|python -c .*socket)",
    re.I,
)
_SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555, 6666, 6667, 8081, 9001, 9002}
_PERSISTENCE = re.compile(
    r"(crontab|launchctl|/Library/LaunchAgents|/etc/cron|"
    r"HKLM\\.*\\Run|schtasks.*/create|systemctl enable|"
    r"defaults write .*LoginItems)", re.I)
_DEFENSE_EVASION = re.compile(
    r"(defender.*disable|set-mppreference.*disable|ufw disable|"
    r"iptables -F|csrutil disable|spctl --master-disable|"
    r"eventlog.*clear|wevtutil cl|history -c|unset HISTFILE)", re.I)


def _as_strings(items: Any) -> list[str]:
    out: list[str] = []
    for it in items or []:
        if isinstance(it, dict):
            out.append(" ".join(str(v) for v in it.values()))
        else:
            out.append(str(it))
    return out


class EndpointAnalyzer(Detector):
    name = "endpoint"
    kind = "endpoint"
    title = "Endpoint Behaviour Analyzer"
    description = "Flags suspicious processes, outbound connections, persistence and mass-file activity on a host."

    FILE_EVENT_THRESHOLD = 300   # files touched in the window => possible ransomware

    def analyze(self, payload: Any) -> list[Alert]:
        if not isinstance(payload, dict):
            return []
        host = str(payload.get("host", "unknown-host"))
        alerts: list[Alert] = []

        procs = _as_strings(payload.get("processes"))
        for p in procs:
            if _SUSPICIOUS_PROC.search(p):
                alerts.append(self.alert(
                    "endpoint_anomaly",
                    "Suspicious process / LOLBin execution",
                    f"Process on {host} matches a known offensive technique "
                    "(encoded command, living-off-the-land binary, or reverse shell).",
                    82,
                    indicators=[f"proc={p[:140]}", f"host={host}"],
                    source=host,
                ))
            if _PERSISTENCE.search(p):
                alerts.append(self.alert(
                    "endpoint_anomaly",
                    "Persistence mechanism created",
                    f"A persistence action (scheduled task / autostart) was observed on {host}.",
                    68,
                    indicators=[f"proc={p[:140]}", f"host={host}"],
                    source=host,
                ))
            if _DEFENSE_EVASION.search(p):
                alerts.append(self.alert(
                    "endpoint_anomaly",
                    "Security control tampering",
                    f"An attempt to disable a security control or clear logs on {host}.",
                    88,
                    indicators=[f"proc={p[:140]}", f"host={host}"],
                    source=host,
                ))

        # outbound connections
        for c in payload.get("connections") or []:
            rport = None
            raddr = None
            if isinstance(c, dict):
                rport = c.get("rport")
                raddr = c.get("raddr")
            else:
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", str(c))
                if m:
                    raddr, rport = m.group(1), int(m.group(2))
            try:
                rport = int(rport) if rport is not None else None
            except (ValueError, TypeError):
                rport = None
            if rport in _SUSPICIOUS_PORTS:
                alerts.append(self.alert(
                    "data_exfiltration",
                    "Outbound connection to suspicious port",
                    f"{host} connected to {raddr}:{rport} — a port commonly used by "
                    "C2 frameworks and reverse shells.",
                    75,
                    indicators=[f"dest={raddr}:{rport}", f"host={host}"],
                    source=host,
                ))

        # mass file activity
        fe = payload.get("file_events")
        try:
            fe = int(fe) if fe is not None else 0
        except (ValueError, TypeError):
            fe = 0
        if fe >= self.FILE_EVENT_THRESHOLD:
            score = min(100, 55 + (fe - self.FILE_EVENT_THRESHOLD) // 20)
            alerts.append(self.alert(
                "endpoint_anomaly",
                "Mass file modification (possible ransomware)",
                f"{fe} file create/modify events on {host} in the analyzed window — "
                "a rate consistent with bulk encryption or automated staging.",
                score,
                indicators=[f"{fe} file events", f"host={host}"],
                source=host,
            ))

        return alerts
