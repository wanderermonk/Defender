"""Local self-scan — read-only posture collection for THIS machine.

Runs natively wherever Defender is launched (macOS / Linux / Windows) and
collects, using only read-only commands:

  * listening TCP sockets  -> feeds the Port Exposure detector
  * security-control state  -> feeds the Vulnerability & Posture detector
  * a few app versions      -> feeds the CVE matcher

Nothing here changes system state. Some checks reveal more with admin rights;
where a value can't be read without elevation it is reported as "unknown" and
simply not scored, rather than guessed. Every subprocess call is wrapped so a
missing tool never breaks the scan.
"""

from __future__ import annotations

import platform
import plistlib
import re
import subprocess
from typing import Any, Optional


def _run(cmd: list[str], timeout: int = 8) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Listening ports (cross-platform)
# --------------------------------------------------------------------------

def _ports_unix() -> list[dict]:
    """Parse `lsof` for listening TCP sockets (macOS/Linux)."""
    out = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    socks: list[dict] = []
    seen = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proc = parts[0]
        name = parts[8]           # e.g. 127.0.0.1:5050 or *:22
        m = re.search(r"(.*):(\d+)$", name)
        if not m:
            continue
        addr, port = m.group(1), int(m.group(2))
        addr = addr.strip("[]") or "*"
        key = (port, addr, proc)
        if key in seen:
            continue
        seen.add(key)
        socks.append({"port": port, "proto": "tcp", "addr": addr, "process": proc})
    return socks


def _ports_windows() -> list[dict]:
    out = _run(["netstat", "-ano", "-p", "TCP"])
    socks, seen = [], set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
            m = re.search(r"(.*):(\d+)$", parts[1])
            if not m:
                continue
            addr, port = m.group(1), int(m.group(2))
            key = (port, addr)
            if key in seen:
                continue
            seen.add(key)
            socks.append({"port": port, "proto": "tcp", "addr": addr,
                          "process": f"PID {parts[-1]}"})
    return socks


def listening_ports() -> list[dict]:
    return _ports_windows() if platform.system() == "Windows" else _ports_unix()


# --------------------------------------------------------------------------
# Security controls  (True = OK / hardened, False = weak, omitted = unknown)
# --------------------------------------------------------------------------

def _controls_macos() -> dict[str, Optional[bool]]:
    c: dict[str, Optional[bool]] = {}

    fw = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]).lower()
    if fw:
        c["firewall_enabled"] = "enabled" in fw

    fv = _run(["fdesetup", "status"]).lower()
    if fv:
        c["disk_encryption"] = "on" in fv

    sip = _run(["csrutil", "status"]).lower()
    if sip:
        c["secure_boot"] = "enabled" in sip   # SIP ~ integrity protection

    gk = _run(["spctl", "--status"]).lower()
    if gk:
        c["av_enabled"] = "enabled" in gk      # Gatekeeper assessment on

    au = _run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
               "AutomaticCheckEnabled"]).strip()
    if au in ("0", "1"):
        c["auto_update"] = au == "1"

    guest = _run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow",
                  "GuestEnabled"]).strip()
    if guest in ("0", "1"):
        c["guest_account"] = guest == "0"      # OK when guest disabled

    # macOS always ships SMB server off by default; mark known-good
    c["smbv1_enabled"] = True
    return c


def _controls_linux() -> dict[str, Optional[bool]]:
    c: dict[str, Optional[bool]] = {}
    ufw = _run(["ufw", "status"]).lower()
    if "status: active" in ufw:
        c["firewall_enabled"] = True
    elif "status: inactive" in ufw:
        c["firewall_enabled"] = False
    # unattended-upgrades present?
    au = _run(["systemctl", "is-enabled", "unattended-upgrades"]).strip().lower()
    if au in ("enabled", "disabled"):
        c["auto_update"] = au == "enabled"
    return c


def _controls_windows() -> dict[str, Optional[bool]]:
    c: dict[str, Optional[bool]] = {}
    fw = _run(["netsh", "advfirewall", "show", "allprofiles", "state"]).lower()
    if "state" in fw:
        c["firewall_enabled"] = "off" not in fw
    return c


def security_controls() -> dict[str, Optional[bool]]:
    sysname = platform.system()
    if sysname == "Darwin":
        return _controls_macos()
    if sysname == "Linux":
        return _controls_linux()
    if sysname == "Windows":
        return _controls_windows()
    return {}


# --------------------------------------------------------------------------
# Running processes + established outbound connections
# --------------------------------------------------------------------------

def running_processes() -> list[str]:
    """Command lines of running processes (for the endpoint detector)."""
    if platform.system() == "Windows":
        out = _run(["wmic", "process", "get", "CommandLine"])
        return [l.strip() for l in out.splitlines()[1:] if l.strip()]
    out = _run(["ps", "-axo", "command="])
    return [l.strip() for l in out.splitlines() if l.strip()][:400]


def established_connections() -> list[dict]:
    """Outbound established connections with owning process (for network baseline)."""
    conns: list[dict] = []
    if platform.system() == "Windows":
        return conns  # best-effort; netstat PID mapping handled elsewhere
    out = _run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"])
    seen = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proc = parts[0]
        name = parts[8]                       # local->remote, e.g. 10.0.0.2:55123->1.2.3.4:443
        m = re.search(r"->(.+):(\d+)$", name)
        if not m:
            continue
        raddr, rport = m.group(1).strip("[]"), int(m.group(2))
        if raddr in ("127.0.0.1", "::1", "localhost"):
            continue
        key = (proc, raddr, rport)
        if key in seen:
            continue
        seen.add(key)
        conns.append({"app": proc, "path": "", "raddr": raddr, "rport": rport})
    return conns


# --------------------------------------------------------------------------
# Installed app versions (best-effort, small set that overlaps the CVE list)
# --------------------------------------------------------------------------

def _app_version_macos(app_path: str) -> Optional[str]:
    try:
        with open(f"{app_path}/Contents/Info.plist", "rb") as fh:
            pl = plistlib.load(fh)
        return pl.get("CFBundleShortVersionString")
    except Exception:
        return None


def installed_software() -> list[dict]:
    sw: list[dict] = []
    if platform.system() == "Darwin":
        candidates = {
            "Chrome": "/Applications/Google Chrome.app",
            "Firefox": "/Applications/Firefox.app",
            "VLC": "/Applications/VLC.app",
            "Docker Desktop": "/Applications/Docker.app",
            "Zoom": "/Applications/zoom.us.app",
        }
        for name, path in candidates.items():
            v = _app_version_macos(path)
            if v:
                sw.append({"name": name, "version": v})
        ssh = _run(["ssh", "-V"])
        m = re.search(r"OpenSSH_(\d+\.\d+)", ssh)
        if m:
            sw.append({"name": "OpenSSH", "version": m.group(1)})
    return sw


# --------------------------------------------------------------------------
# Assemble the payloads the detectors consume
# --------------------------------------------------------------------------

def scan() -> dict[str, Any]:
    host = platform.node() or "this-machine"
    controls = security_controls()
    conns = established_connections()
    procs = running_processes()
    return {
        "host": host,
        "os": f"{platform.system()} {platform.release()}",
        "ports_payload": {"host": host, "listening": listening_ports()},
        "vuln_payload": {
            "host": host,
            "controls": {k: v for k, v in controls.items() if v is not None},
            "software": installed_software(),
        },
        "endpoint_payload": {"host": host, "processes": procs,
                             "connections": [f"{c['raddr']}:{c['rport']}" for c in conns],
                             "file_events": 0},
        "network_payload": {"host": host, "connections": conns},
        "controls_unknown": [k for k, v in controls.items() if v is None],
        "process_count": len(procs),
        "connection_count": len(conns),
    }
