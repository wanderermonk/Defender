# DEFENDER — AI-Powered Attack Detection & Mitigation

A defensive security console that detects AI-driven attacks and gives you
concrete, prioritized mitigations. Runs **fully offline** (standard library +
Flask); an optional **local** Ollama hook adds AI-rewritten advice without any
data leaving the machine. Matrix-themed dashboard.

> Built in response to the wave of AI-powered attacks (e.g. Japan's 2026
> cyber-emergency). The premise: use AI/heuristic analysis to catch the
> automated, LLM-assisted attack patterns that signature-only tools miss.

## What it detects (7 modules)

| Module | Kind | Catches |
|---|---|---|
| **Log & Traffic Analyzer** | `log` | Credential stuffing, automated recon/scanning, SQLi/XSS/SSTI/traversal payloads, volumetric bursts |
| **Content & Phishing Analyzer** | `content` | AI-generated phishing, urgency/credential/payment lures, look-alike (punycode) domains, display-vs-href mismatch |
| **Endpoint Behaviour Analyzer** | `endpoint` | Encoded PowerShell / LOLBins, reverse shells, persistence, defense tampering, mass-file (ransomware) activity |
| **Prompt-Injection & LLM Defense** | `llm` | Prompt injection, jailbreaks, system-prompt extraction, secrets leaking in model output |
| **Port Exposure Scanner** | `ports` | Risky listening sockets scored by exposure, with reversible close playbooks |
| **Vulnerability & Posture Audit** | `vuln` | Weak OS controls, patch-gap, installed-software CVE matches with fix playbooks |
| **Outbound Connection Monitor** | `network` | Per-app behavioral baseline → new/malicious destinations, C2 ports, Temp/Downloads execution |

Every detection carries a **severity**, a 0–100 **score**, the **indicators**
(evidence) behind it, and concrete **mitigations**. The **AI Advisor** turns the
full alert history into a prioritized action plan (impact ÷ effort) and answers
questions grounded only in real detections.

## Run

```bash
cd Defender
./run.sh            # or:  pip install -r requirements.txt && python app.py
# open http://localhost:5050  →  click "RUN FULL DEMO"
```

Optional local AI advisor (needs [Ollama](https://ollama.com) running):

```bash
export DEFENDER_OLLAMA=1
export DEFENDER_OLLAMA_MODEL=llama3.1
python app.py
```

## API

```
GET  /api/scan                                -> read-only self-scan of THIS machine, scored
POST /api/analyze/<kind>   {"payload": ...}   -> detections   (kind: log|content|endpoint|llm|ports|vuln|network)
GET  /api/stats                               -> severity + detector counts
GET  /api/plan                                -> prioritized action plan
POST /api/ask              {"question": ...}  -> grounded advisor answer
GET  /api/demo                                -> run all bundled samples
GET  /api/history?limit=N                     -> recent detections
```

## Scan this machine & resolve

Click **⬡ SCAN THIS MACHINE** on the dashboard (or `GET /api/scan`). Defender
detects the host OS at runtime (macOS / Linux / Windows) and runs **read-only**
checks for that platform — listening ports, security-control state (firewall,
disk encryption, auto-update, Gatekeeper/SIP, etc.), and a few app versions for
CVE matching — then scores and prioritizes the findings. Nothing is changed;
controls that need admin to read are reported as "needs admin", not guessed.

Every finding carries a **RESOLVE** block: concrete, reversible fix steps with a
**COPY** button that copies the exact command for your OS. Defender never
executes those changes itself — you review and run them.

## Use as a library

```python
from defender.engine import Engine
from defender.detectors import ALL_DETECTORS

e = Engine()
for d in ALL_DETECTORS:
    e.register(d())

for alert in e.analyze("log", open("/var/log/nginx/access.log").read()):
    print(alert.severity.label, alert.title, "->", alert.mitigations[0])
```

## Layout

```
app.py                     Flask API + dashboard
defender/
  engine.py                Alert model, severity, mitigation KB, orchestrator
  enrichment.py            CVE index, IP reputation/geo, local-LLM hook
  advisor.py               prioritized action plan + grounded Q&A
  detectors/
    log_analyzer.py        traffic / auth-log detection
    content_analyzer.py    phishing / social engineering
    endpoint_analyzer.py   host process/connection/file behaviour
    llm_defense.py         prompt injection / jailbreak / exfil
    posture.py             port exposure + vuln & posture audit
    network_baseline.py    outbound behavioral baseline
templates/dashboard.html   Matrix-themed UI
sample_data/               demo log + phishing email
test_defender.py           17-check smoke test
```

## What was merged in — and what wasn't

This project consolidates the **defensive** capabilities from two sibling
projects:

- **sentinel-desktop** → port-exposure scoring + reversible close playbooks,
  the per-app outbound behavioral baseline ("AI anomaly detection"),
  OS/posture auditing with fix playbooks, CVE matching, and the offline AI
  advisor (action plan + grounded Q&A).
- **SystemAnalyzer** → CVE intelligence, IP reputation/geo enrichment, and the
  optional local-LLM analysis hook.

Deliberately **not** included: the passive browser-fingerprinting / tracking-
pixel payload from SystemAnalyzer, and the `phantom-trace-recon` OSINT
face-finder (mass social-media scraping + facial recognition). Those are
surveillance/reconnaissance capabilities, not defensive ones, and don't belong
in a protective tool.

## Scope & honesty

Defender is **detection and advisory**. It never executes firewall/kill/patch
actions itself — mitigations are given as explicit, reversible commands you run
after review. The CVE list, blocklist, and port intel are **starter sets** meant
to be extended (import FireHOL/URLhaus feeds, a fuller CVE DB, etc.). Heuristic
detectors are a strong first layer, not a replacement for a full EDR/SIEM — use
them to triage and prioritize. Only use it on systems you own or administer.
