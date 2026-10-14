"""Prompt-injection / LLM application defense.

Guards your own AI systems. Scans an untrusted input (and optionally the
model's output) for:

  * prompt injection       — "ignore previous instructions", role overrides,
                             tool/system-prompt manipulation, delimiter breaking
  * jailbreak attempts     — DAN-style role-play, "developer mode", obfuscation
  * data exfiltration      — requests to reveal the system prompt / secrets, and
                             secret patterns (API keys, private keys) in OUTPUT

Input: a dict {"input": str, "output": str} OR a plain string (treated as the
untrusted input). Returns one alert per distinct finding.
"""

from __future__ import annotations

import re
from typing import Any

from .base import Detector

_INJECTION = [
    (re.compile(r"ignore (all |the )?(previous|prior|above) (instructions|prompts|rules)", re.I),
     "override: 'ignore previous instructions'"),
    (re.compile(r"disregard (your|the|all) (system prompt|instructions|guidelines)", re.I),
     "override: disregard system prompt"),
    (re.compile(r"you are (now|actually) (a|an|no longer)", re.I),
     "role reassignment"),
    (re.compile(r"(new|updated) (instructions|system prompt)\s*:", re.I),
     "injected new instruction block"),
    (re.compile(r"(reveal|print|repeat|show|output) (your|the) (system prompt|instructions|rules|initial prompt)", re.I),
     "system-prompt extraction attempt"),
    (re.compile(r"(begin|end)\s*(of)?\s*(system|assistant|user)\s*(message|prompt)", re.I),
     "fake role/delimiter injection"),
    (re.compile(r"</?(system|assistant|user)>", re.I),
     "role-tag injection"),
    (re.compile(r"\bpretend\b.*\b(you|there are) no (rules|restrictions|guidelines)\b", re.I),
     "constraint removal"),
]
_JAILBREAK = [
    (re.compile(r"\bDAN\b|do anything now", re.I), "DAN-style jailbreak"),
    (re.compile(r"developer mode|dev mode enabled|jailbreak", re.I), "'developer mode' jailbreak"),
    (re.compile(r"hypothetically|for (educational|research) purposes only.*(bomb|malware|exploit|weapon)", re.I),
     "harm-framing bypass"),
    (re.compile(r"respond (only )?with (the )?(uncensored|unfiltered|unrestricted)", re.I),
     "filter-bypass request"),
    (re.compile(r"(base64|rot13|hex)\s*(decode|encode).*(then|and) (execute|follow|do)", re.I),
     "obfuscation-wrapped instruction"),
]
# patterns that are dangerous if they appear in the MODEL OUTPUT
_SECRETS_IN_OUTPUT = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI-style API key in output"),
    (re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"), "Anthropic API key in output"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id in output"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub token in output"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key in output"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token in output"),
]
_SYS_LEAK = re.compile(r"(you are a helpful|system prompt|my instructions are|as an ai (language )?model i (was|am) (told|instructed))", re.I)


def _normalize(payload: Any) -> dict[str, str]:
    if isinstance(payload, dict):
        return {"input": str(payload.get("input", "")), "output": str(payload.get("output", ""))}
    return {"input": str(payload), "output": ""}


class LLMDefense(Detector):
    name = "llm"
    kind = "llm"
    title = "Prompt-Injection & LLM Defense"
    description = "Detects prompt injection, jailbreaks and data exfiltration against your own AI systems."

    def analyze(self, payload: Any) -> list[Alert]:
        data = _normalize(payload)
        text_in = data["input"]
        text_out = data["output"]
        alerts: list[Alert] = []

        inj_hits = [label for rx, label in _INJECTION if rx.search(text_in)]
        if inj_hits:
            score = min(100, 55 + 12 * len(inj_hits))
            alerts.append(self.alert(
                "prompt_injection",
                "Prompt injection attempt",
                "Untrusted input contains instructions aimed at overriding the system "
                "prompt or hijacking tool use. Neutralize before it reaches the model.",
                score,
                indicators=inj_hits,
            ))

        jb_hits = [label for rx, label in _JAILBREAK if rx.search(text_in)]
        if jb_hits:
            score = min(100, 50 + 12 * len(jb_hits))
            alerts.append(self.alert(
                "jailbreak",
                "Jailbreak attempt",
                "Input tries to make the model shed its safety constraints via role-play, "
                "'developer mode', or obfuscation.",
                score,
                indicators=jb_hits,
            ))

        # exfiltration — requests in input + secret patterns / leakage in output
        leak_ind: list[str] = []
        if re.search(r"(reveal|show|print|repeat).*(system prompt|api key|secret|token|password)", text_in, re.I):
            leak_ind.append("input requests secrets / system prompt")
        for rx, label in _SECRETS_IN_OUTPUT:
            if text_out and rx.search(text_out):
                leak_ind.append(label)
        if text_out and _SYS_LEAK.search(text_out):
            leak_ind.append("output appears to leak system-prompt text")
        if leak_ind:
            # much higher severity when a secret actually appears in output
            has_secret = any("output" in i for i in leak_ind)
            score = 90 if has_secret else 55
            alerts.append(self.alert(
                "llm_data_leak" if has_secret else "data_exfiltration",
                "Data exfiltration via the model",
                "Potential leakage of secrets or system-prompt content through the LLM "
                "input/output channel.",
                score,
                indicators=leak_ind,
            ))

        return alerts
