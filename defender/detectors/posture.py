"""Host posture detectors — merged (reimplemented) from sentinel-desktop.

Three analyzers that score a host's *defensive posture* rather than live
attacks. All are read-only and advisory; the "one-click close / apply fix"
actions from sentinel are represented here as explicit, reversible command
playbooks in each alert's mitigations (the engine never executes them).

  PortExposure  — listening sockets → exposure + risk score + close advice
  VulnAudit     — OS/security-control audit + installed-software CVE match
  (A behavioral outbound baseline lives in endpoint_analyzer via BaselineStore.)

Inputs are plain dicts so you can feed them from `netstat`, `ss`, `lsof`,
your MDM, or sentinel's own engine output.
"""

from __future__ import annotations

from typing import Any

from .base import Detector
from ..engine import Alert, Severity, mitigations_for
from ..enrichment import CVEIndex

# port -> (label, base_risk 0..100, advice)
_PORT_INTEL: dict[int, tuple[str, int, str]] = {
    21: ("FTP", 70, "Cleartext auth; replace with SFTP/FTPS or close."),
    23: ("Telnet", 95, "Cleartext remote shell — close immediately."),
    135: ("MSRPC", 75, "Restrict to LAN; common lateral-movement vector."),
    139: ("NetBIOS", 80, "Legacy SMB; disable if not required."),
    445: ("SMB", 85, "Restrict to trusted subnets; patch and disable SMBv1."),
    1433: ("MSSQL", 80, "Never expose to the internet; firewall to app tier."),
    3306: ("MySQL", 80, "Bind to localhost or app subnet only."),
    3389: ("RDP", 90, "Put behind VPN/MFA gateway; do not expose publicly."),
    5432: ("PostgreSQL", 78, "Bind to localhost / private network only."),
    5900: ("VNC", 88, "Tunnel over SSH/VPN; never expose directly."),
    6379: ("Redis", 85, "Enable auth + bind localhost; unauth Redis = RCE risk."),
    27017: ("MongoDB", 85, "Enable auth; bind to private interface."),
    9200: ("Elasticsearch", 82, "Enable security; never expose publicly."),
    11434: ("Ollama", 55, "Local LLM API — keep bound to localhost."),
}

_EXPOSURE_WEIGHT = {"localhost": 0.2, "lan": 0.6, "all": 1.0}


def _exposure(addr: str) -> str:
    addr = (addr or "").strip()
    if addr in ("127.0.0.1", "::1", "localhost"):
        return "localhost"
    if addr in ("0.0.0.0", "::", "*", ""):
        return "all"
    if addr.startswith(("10.", "192.168.", "172.")):
        return "lan"
    return "all"


class PortExposure(Detector):
    name = "ports"
    kind = "ports"
    title = "Port Exposure Scanner"
    description = "Scores listening TCP/UDP sockets by exposure and risk, with reversible close playbooks."

    def analyze(self, payload: Any) -> list[Alert]:
        """payload: {"host": str, "listening": [ {port, proto, addr, process} ]}"""
        if not isinstance(payload, dict):
            return []
        host = str(payload.get("host", "this-host"))
        alerts: list[Alert] = []
        for sock in payload.get("listening") or []:
            try:
                port = int(sock.get("port"))
            except (ValueError, TypeError):
                continue
            proto = str(sock.get("proto", "tcp")).lower()
            addr = str(sock.get("addr", "0.0.0.0"))
            proc = str(sock.get("process", "unknown"))
            exposure = _exposure(addr)
            label, base, advice = _PORT_INTEL.get(port, (f"port {port}", 35, "Review whether this service must listen."))
            score = min(100, base * _EXPOSURE_WEIGHT[exposure])
            if exposure == "localhost" and score < 15:
                continue  # local-only low-risk: not worth an alert
            verdict = "CLOSE" if score >= 65 else ("REVIEW" if score >= 40 else "KEEP")
            mits = [
                f"Recommendation: {verdict}. {advice}",
                f"Windows (reversible): New-NetFirewallRule -DisplayName 'Defender-block-{port}' "
                f"-Direction Inbound -Action Block -Protocol {proto.upper()} -LocalPort {port}",
                f"Linux (reversible): sudo ufw deny {port}/{proto}   # undo: sudo ufw delete deny {port}/{proto}",
                f"macOS: add 'block drop in proto {proto} from any to any port {port}' to a pf anchor.",
            ]
            alerts.append(Alert(
                detector=self.name, category="port_exposure",
                title=f"{label} listening ({exposure}) — {verdict}",
                description=f"{proc} on {host} is listening on {proto}/{port} bound to {addr} "
                            f"({exposure} exposure). Risk {round(score)}/100.",
                severity=Severity.from_score(score), score=round(score, 1),
                indicators=[f"{proto}/{port}", f"bind={addr}", f"exposure={exposure}", f"process={proc}"],
                mitigations=mits, source=host,
            ))
        return alerts


class VulnAudit(Detector):
    name = "vuln"
    kind = "vuln"
    title = "Vulnerability & Posture Audit"
    description = "Audits OS security controls and matches installed software against a CVE list, with fix playbooks."

    # control -> (points_if_bad, title, fix)
    _CONTROLS = {
        "firewall_enabled":   (22, "Host firewall disabled", "Enable the OS firewall (Windows Defender Firewall / ufw / pf)."),
        "disk_encryption":    (18, "Disk encryption off", "Enable BitLocker (Win) / FileVault (mac) / LUKS (Linux)."),
        "auto_update":        (15, "Automatic updates off", "Turn on automatic OS + app updates."),
        "av_enabled":         (18, "Endpoint protection disabled", "Re-enable Defender / your EDR agent."),
        "smbv1_enabled":      (20, "SMBv1 enabled", "Disable SMBv1 (Remove-WindowsFeature FS-SMB1)."),
        "rdp_exposed":        (22, "RDP reachable from the network", "Place RDP behind VPN + MFA; disable if unused."),
        "secure_boot":        (10, "Secure Boot off", "Enable Secure Boot in firmware."),
        "guest_account":      (8,  "Guest/auto-login enabled", "Disable guest and auto-login accounts."),
        "os_supported":       (30, "OS past end-of-support", "Upgrade to a supported OS release."),
    }

    def __init__(self):
        self.cve_index = CVEIndex()

    def analyze(self, payload: Any) -> list[Alert]:
        """payload: {
             "host": str,
             "controls": {control_name: bool_is_ok, ...},
             "patch_age_days": int,
             "software": [ {name, version} ]
           }"""
        if not isinstance(payload, dict):
            return []
        host = str(payload.get("host", "this-host"))
        alerts: list[Alert] = []

        controls = payload.get("controls") or {}
        bad: list[tuple[int, str, str]] = []
        for key, (pts, title, fix) in self._CONTROLS.items():
            if key in controls and controls[key] is False:
                bad.append((pts, title, fix))
        if bad:
            total = min(100, sum(p for p, _, _ in bad))
            alerts.append(Alert(
                detector=self.name, category="misconfiguration",
                title=f"{len(bad)} security control(s) weak on {host}",
                description="Host hardening audit found controls that increase exposure to "
                            "automated and AI-assisted intrusion.",
                severity=Severity.from_score(total), score=round(total, 1),
                indicators=[t for _, t, _ in bad],
                mitigations=[f"{t}: {f}" for _, t, f in bad], source=host,
            ))

        age = payload.get("patch_age_days")
        try:
            age = int(age) if age is not None else None
        except (ValueError, TypeError):
            age = None
        if age is not None and age > 30:
            score = min(100, 30 + (age - 30) // 3)
            alerts.append(Alert(
                detector=self.name, category="missing_patches",
                title=f"Patches {age} days behind on {host}",
                description="A large patch gap leaves known-exploited vulnerabilities open; "
                            "automated exploit kits target these first.",
                severity=Severity.from_score(score), score=round(score, 1),
                indicators=[f"patch_age={age}d"],
                mitigations=["Apply pending OS updates.", "Enable automatic updates.",
                             "Prioritise CISA KEV-listed CVEs."], source=host,
            ))

        for sw in payload.get("software") or []:
            name = str(sw.get("name", ""))
            ver = str(sw.get("version", ""))
            for cve in self.cve_index.match(name, ver):
                score = min(100, 40 + cve.get("cvss", 5) * 6)
                alerts.append(Alert(
                    detector=self.name, category="known_cve",
                    title=f"{cve['cve']} affects {name} {ver}",
                    description=cve["summary"],
                    severity=Severity.from_score(score), score=round(score, 1),
                    indicators=[cve["cve"], f"CVSS {cve.get('cvss')}", f"{name} {ver}"],
                    mitigations=[f"Update {name} to {cve.get('lt','the fixed version')} or later.",
                                 "Check vendor advisory; apply mitigations if patch unavailable.",
                                 "If internet-exposed, treat as urgent."],
                    source=host,
                ))

        alerts.sort(key=lambda a: (a.severity, a.score), reverse=True)
        return alerts
