"""AI advisor — merged from sentinel-desktop.

Works with NO model: it turns the engine's alert history into a prioritized
action plan (impact ÷ effort) and answers questions with a lightweight
TF-IDF retrieval over the alerts + their mitigations. If an LLM hook is
configured (local Ollama preferred), the grounded answer is rewritten by the
model — but the facts always come from the engine, never invented.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from .engine import Engine, Alert

# rough effort weights per category (1 = trivial, 5 = heavy)
_EFFORT = {
    "credential_stuffing": 2, "automated_recon": 2, "injection_payload": 3,
    "traffic_anomaly": 2, "ai_phishing": 1, "social_engineering": 1,
    "endpoint_anomaly": 3, "data_exfiltration": 3, "prompt_injection": 2,
    "jailbreak": 2, "llm_data_leak": 2, "port_exposure": 1,
    "misconfiguration": 2, "missing_patches": 2, "known_cve": 3,
}


def action_plan(engine: Engine, top: int = 10) -> list[dict[str, Any]]:
    """Prioritized remediation list: impact (severity×score) ÷ effort."""
    items = []
    for a in engine.history:
        effort = _EFFORT.get(a.category, 3)
        impact = (int(a.severity) + 1) * a.score
        items.append({
            "priority": round(impact / effort, 1),
            "severity": a.severity.label,
            "title": a.title,
            "category": a.category,
            "source": a.source,
            "first_step": a.mitigations[0] if a.mitigations else "Review manually.",
        })
    items.sort(key=lambda x: x["priority"], reverse=True)
    # de-dup by (title, source)
    seen, out = set(), []
    for it in items:
        k = (it["title"], it["source"])
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
        if len(out) >= top:
            break
    return out


# --------------------------------------------------------------------------
# TF-IDF Q&A over alerts + mitigations (offline, explainable)
# --------------------------------------------------------------------------

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(s: str) -> list[str]:
    return _WORD.findall(s.lower())


def _doc_text(a: Alert) -> str:
    return " ".join([a.title, a.description, a.category, " ".join(a.indicators),
                     " ".join(a.mitigations)])


def answer(engine: Engine, question: str, llm_hook=None) -> dict[str, Any]:
    docs = [(a, _doc_text(a)) for a in engine.history]
    if not docs:
        return {"answer": "No detections recorded yet — run some analysis first.",
                "grounded_on": [], "used_llm": False}

    # build idf
    df: Counter = Counter()
    tokenized = []
    for _, text in docs:
        toks = set(_tokens(text))
        tokenized.append(toks)
        df.update(toks)
    N = len(docs)
    idf = {t: math.log(1 + N / (1 + df[t])) for t in df}

    q = _tokens(question)
    scored = []
    for (alert, _), toks in zip(docs, tokenized):
        s = sum(idf.get(t, 0) for t in q if t in toks)
        if s > 0:
            scored.append((s, alert))
    scored.sort(key=lambda x: x[0], reverse=True)
    hits = [a for _, a in scored[:4]]

    if not hits:
        return {"answer": "Nothing in the current detections matches that question.",
                "grounded_on": [], "used_llm": False}

    facts = []
    for a in hits:
        facts.append(f"- [{a.severity.label}] {a.title} ({a.category}) → {a.mitigations[0] if a.mitigations else 'review'}")
    grounded = "\n".join(facts)

    if llm_hook:
        prompt = (
            "You are a security advisor. Answer the question using ONLY these verified "
            "findings from the local detection engine. Do not invent anything.\n\n"
            f"FINDINGS:\n{grounded}\n\nQUESTION: {question}\n\nAnswer concisely:"
        )
        try:
            text = llm_hook(prompt).strip()
            return {"answer": text, "grounded_on": [a.id for a in hits], "used_llm": True}
        except Exception:
            pass  # fall back to the deterministic summary

    return {
        "answer": f"Based on {len(hits)} relevant detection(s):\n{grounded}",
        "grounded_on": [a.id for a in hits],
        "used_llm": False,
    }
