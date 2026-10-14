"""Enrichment layer — adds context to detections.

Merged from SystemAnalyzer's defensive pieces, reimplemented cleanly:

  * CVE matching     — match installed software against a bundled CVE list
                       (importable / extensible, same idea as sentinel's cve_db).
  * IP reputation    — offline heuristics (private/reserved, bogon, known-bad
                       seed list) + optional online geo/ASN lookup via ip-api.
  * LLM advisor hook — optional second opinion from a LOCAL Ollama model or a
                       hosted API; disabled by default so everything runs offline.

Nothing here performs scanning or tracking — it only annotates data the user
already has.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any, Optional

# --------------------------------------------------------------------------
# CVE matching
# --------------------------------------------------------------------------

# Seed list (starter set — extend via load_cve_db / import your own JSON).
# schema: {product, versions_affected(regex or "<x.y"), cve, cvss, summary}
_SEED_CVES: list[dict[str, Any]] = [
    {"product": "openssh", "lt": "9.6", "cve": "CVE-2024-6387", "cvss": 8.1,
     "summary": "regreSSHion: unauthenticated RCE in sshd via signal handler race."},
    {"product": "7-zip", "lt": "24.09", "cve": "CVE-2024-11477", "cvss": 7.8,
     "summary": "Heap overflow in 7-Zip Zstandard decompression."},
    {"product": "winrar", "lt": "7.10", "cve": "CVE-2025-6218", "cvss": 7.8,
     "summary": "Directory traversal allowing code execution from crafted archive."},
    {"product": "docker desktop", "lt": "4.34", "cve": "CVE-2024-8695", "cvss": 8.8,
     "summary": "RCE via crafted extension description."},
    {"product": "chrome", "lt": "116.0.5845.187", "cve": "CVE-2023-4863", "cvss": 8.8,
     "summary": "libwebp heap overflow (0-day, widely exploited)."},
    {"product": "putty", "lt": "0.81", "cve": "CVE-2024-31497", "cvss": 5.9,
     "summary": "Recoverable NIST P-521 private key from signatures."},
    {"product": "curl", "lt": "8.4.0", "cve": "CVE-2023-38545", "cvss": 7.5,
     "summary": "SOCKS5 heap buffer overflow."},
]


def _ver_tuple(v: str) -> tuple:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4]) if parts else (0,)


class CVEIndex:
    def __init__(self, cves: Optional[list[dict]] = None):
        self.cves = list(cves if cves is not None else _SEED_CVES)

    def load_file(self, path: str) -> int:
        """Import an external CVE JSON (same schema). Returns count added."""
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        before = len(self.cves)
        self.cves.extend(data if isinstance(data, list) else data.get("cves", []))
        return len(self.cves) - before

    def match(self, product: str, version: str = "") -> list[dict]:
        p = product.strip().lower()
        hits = []
        for c in self.cves:
            if c["product"].lower() not in p and p not in c["product"].lower():
                continue
            lt = c.get("lt")
            if lt and version and _ver_tuple(version) >= _ver_tuple(lt):
                continue   # patched
            hits.append(c)
        return sorted(hits, key=lambda c: c.get("cvss", 0), reverse=True)


# --------------------------------------------------------------------------
# IP reputation
# --------------------------------------------------------------------------

# Small seed blocklist concept (mining pools / tunnels / known-bad ranges).
# Extend by importing a feed (FireHOL level1, URLhaus, etc.).
_BOGON_NETS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
]
_BOGON = [ipaddress.ip_network(n) for n in _BOGON_NETS]


class IPReputation:
    def __init__(self, blocklist: Optional[set[str]] = None, online: bool = False):
        self.blocklist = set(blocklist or set())
        self.online = online   # only hits the network if explicitly enabled

    def load_blocklist(self, path: str) -> int:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.blocklist.add(line)
        return len(self.blocklist)

    def classify(self, ip: str) -> dict[str, Any]:
        info: dict[str, Any] = {"ip": ip, "flags": [], "private": False, "geo": None}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            info["flags"].append("not-an-ip")
            return info
        if addr.is_private:
            info["private"] = True
            info["flags"].append("private/internal")
        for net in _BOGON:
            if addr in net and not addr.is_private:
                info["flags"].append("bogon/reserved")
                break
        if ip in self.blocklist:
            info["flags"].append("on-blocklist")
        if self.online and not addr.is_private:
            info["geo"] = self._geo(ip)
        return info

    def _geo(self, ip: str) -> Optional[dict]:
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=country,city,isp,as,proxy,hosting"
            with urllib.request.urlopen(url, timeout=4) as r:   # noqa: S310
                d = json.loads(r.read().decode())
            return d
        except Exception:
            return None


# --------------------------------------------------------------------------
# LLM advisor hook (optional, local-first)
# --------------------------------------------------------------------------

def make_ollama_hook(model: str = "llama3.1", host: Optional[str] = None):
    """Return a callable(prompt)->str that queries a LOCAL Ollama server.

    Entirely optional — only used if you assign it to defender.engine.llm_hook.
    Keeps analysis on-device; nothing is sent to a third party.
    """
    host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def hook(prompt: str) -> str:
        import urllib.request
        body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(f"{host}/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:   # noqa: S310
            return json.loads(r.read().decode()).get("response", "")

    return hook
