"""Log / traffic analyzer.

Parses common web-access and auth log lines and detects AI-driven attack
patterns by correlating behaviour across a batch of lines:

  * credential stuffing   — many failed auths from one source, fast
  * automated recon       — rapid 404 sweeps, scanner user-agents, path fuzzing
  * injection payloads    — SQLi / XSS / SSTI / path-traversal signatures
  * traffic anomaly       — request bursts far above a per-source baseline

Input: a string blob of log lines (one request per line) OR a list of lines.
It is format-tolerant: it extracts an IP, a path, a status code and a
user-agent with regexes and degrades gracefully when fields are missing.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .base import Detector

_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_STATUS = re.compile(r'"\s(\d{3})\s')                      # "... " 401 123
_STATUS_ALT = re.compile(r"\b(\d{3})\b(?=\s+\d+\s*$)")      # trailing code
_PATH = re.compile(r'"(?:GET|POST|PUT|HEAD|DELETE|OPTIONS)\s+(\S+)')
_UA = re.compile(r'"([^"]*)"\s*$')                          # last quoted field
_FAIL_WORDS = re.compile(r"(failed password|authentication failure|401|403|invalid user|login failed)", re.I)

_SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nuclei|"
    r"curl/|python-requests|go-http-client|scrapy|httpx|feroxbuster|ffuf)",
    re.I,
)

# Payload signatures. Grouped so we can name the class in the alert.
_PAYLOADS = {
    "SQLi": re.compile(r"(\bunion\s+select\b|\bor\s+1=1\b|';--|\bsleep\(\d|benchmark\(|information_schema|\bwaitfor\s+delay\b)", re.I),
    "XSS": re.compile(r"(<script|onerror\s*=|javascript:|onload\s*=|document\.cookie|<img[^>]+src=)", re.I),
    "Path traversal": re.compile(r"(\.\./\.\.|%2e%2e%2f|/etc/passwd|\\windows\\win\.ini)", re.I),
    "SSTI/Template": re.compile(r"(\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>)", re.I),
    "Command injection": re.compile(r"(;\s*cat\s|\|\s*nc\s|\$\(.*\)|`.*`|&&\s*whoami)", re.I),
}


def _lines(payload: Any) -> list[str]:
    if isinstance(payload, (list, tuple)):
        return [str(x) for x in payload]
    return [ln for ln in str(payload).splitlines() if ln.strip()]


class LogAnalyzer(Detector):
    name = "log"
    kind = "log"
    title = "Log & Traffic Analyzer"
    description = "Detects credential stuffing, automated recon, injection payloads and traffic bursts."

    # thresholds (tunable)
    FAIL_THRESHOLD = 5          # failed auths from one source => stuffing
    RECON_404_THRESHOLD = 8     # 404s from one source => recon sweep
    BURST_THRESHOLD = 40        # requests from one source in the batch => burst

    def analyze(self, payload: Any) -> list[Alert]:
        lines = _lines(payload)
        if not lines:
            return []

        fails: dict[str, int] = defaultdict(int)
        notfound: dict[str, int] = defaultdict(int)
        hits: dict[str, int] = defaultdict(int)
        scanner_ua: dict[str, set] = defaultdict(set)
        payload_hits: list[tuple[str, str, str]] = []   # (ip, cls, snippet)

        for ln in lines:
            ip_m = _IP.search(ln)
            ip = ip_m.group(1) if ip_m else "unknown"
            hits[ip] += 1

            status_m = _STATUS.search(ln) or _STATUS_ALT.search(ln)
            status = status_m.group(1) if status_m else ""

            if status in ("401", "403") or _FAIL_WORDS.search(ln):
                fails[ip] += 1
            if status == "404":
                notfound[ip] += 1

            ua_m = _UA.search(ln)
            if ua_m and _SCANNER_UA.search(ua_m.group(1)):
                scanner_ua[ip].add(_SCANNER_UA.search(ua_m.group(1)).group(1).lower())

            path_m = _PATH.search(ln)
            probe = path_m.group(1) if path_m else ln
            for cls, rx in _PAYLOADS.items():
                if rx.search(probe):
                    payload_hits.append((ip, cls, probe[:120]))
                    break

        alerts: list[Alert] = []

        # credential stuffing
        for ip, n in fails.items():
            if n >= self.FAIL_THRESHOLD:
                score = min(100, 45 + n * 4)
                alerts.append(self.alert(
                    "credential_stuffing",
                    "Credential stuffing / brute force",
                    f"{n} failed authentications from {ip} within the analyzed window — "
                    "consistent with automated (often AI-orchestrated) credential stuffing.",
                    score,
                    indicators=[f"{n} failed auth events", f"source={ip}"],
                    source=ip,
                ))

        # automated recon
        for ip, n in notfound.items():
            uas = scanner_ua.get(ip, set())
            if n >= self.RECON_404_THRESHOLD or uas:
                score = min(100, 35 + n * 3 + (25 if uas else 0))
                ind = [f"{n} 404 responses", f"source={ip}"]
                if uas:
                    ind.append("scanner UA: " + ", ".join(sorted(uas)))
                alerts.append(self.alert(
                    "automated_recon",
                    "Automated reconnaissance / scanning",
                    f"Rapid path enumeration from {ip}"
                    + (" using a known scanner tool." if uas else " (404 sweep)."),
                    score,
                    indicators=ind,
                    source=ip,
                ))

        # injection payloads
        seen: set = set()
        for ip, cls, snippet in payload_hits:
            key = (ip, cls)
            if key in seen:
                continue
            seen.add(key)
            count = sum(1 for h in payload_hits if h[0] == ip and h[1] == cls)
            score = min(100, 60 + count * 6)
            alerts.append(self.alert(
                "injection_payload",
                f"{cls} injection attempt",
                f"{cls} payload signature observed in request(s) from {ip}. "
                "Automated tooling and LLM-generated payloads commonly probe these.",
                score,
                indicators=[f"class={cls}", f"example={snippet}", f"source={ip}"],
                source=ip,
            ))

        # traffic burst
        for ip, n in hits.items():
            if ip == "unknown":
                continue
            if n >= self.BURST_THRESHOLD:
                score = min(100, 30 + (n - self.BURST_THRESHOLD))
                alerts.append(self.alert(
                    "traffic_anomaly",
                    "Request burst / volumetric anomaly",
                    f"{n} requests from {ip} in the analyzed window — well above typical "
                    "per-source volume; possible automated flood.",
                    score,
                    indicators=[f"{n} requests", f"source={ip}"],
                    source=ip,
                ))

        return alerts
