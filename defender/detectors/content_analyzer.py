"""Content / phishing analyzer.

Scores a piece of text (an email, a message, a chat transcript) for signals of
AI-generated phishing and social engineering. Heuristic and explainable: every
point added comes with a named indicator so an analyst can audit the verdict.

Signals:
  * urgency / pressure language
  * credential / payment / gift-card requests
  * suspicious or look-alike (homograph / punycode) links, URL shorteners,
    raw-IP URLs, mismatched display vs. href
  * "too-clean" AI-generated register (very low typo rate + boilerplate openings)
  * authority impersonation (CEO / IT / bank / government)

Input: a dict {"subject": str, "body": str, "sender": str} OR a plain string
(treated as the body).
"""

from __future__ import annotations

import re
from typing import Any

from .base import Detector

_URL = re.compile(r"https?://[^\s<>\"')]+", re.I)
_SHORTENERS = re.compile(r"(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rb\.gy|cutt\.ly)", re.I)
_RAW_IP_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.I)
_PUNYCODE = re.compile(r"https?://[^\s/]*xn--", re.I)
_HTML_LINK = re.compile(r'<a[^>]+href=["\'](.*?)["\'][^>]*>(.*?)</a>', re.I | re.S)

_URGENCY = re.compile(
    r"\b(urgent|immediately|right away|as soon as possible|asap|within \d+ (hours|minutes)|"
    r"final (notice|warning)|account (will be )?(suspended|locked|closed|terminated)|"
    r"action required|verify (your|now)|expire[sd]?|last chance)\b", re.I)
_CREDS = re.compile(
    r"\b(password|one.?time code|otp|2fa code|verify your (account|identity)|"
    r"confirm your (login|credentials)|update your (payment|billing)|ssn|social security)\b", re.I)
_PAYMENT = re.compile(
    r"\b(wire transfer|gift ?cards?|bitcoin|btc|crypto|invoice attached|"
    r"payment is overdue|bank details|routing number|iban)\b", re.I)
_AUTHORITY = re.compile(
    r"\b(ceo|cfo|chief executive|it (support|department|helpdesk)|help ?desk|"
    r"microsoft|apple|google|amazon|paypal|irs|hmrc|tax (office|refund)|"
    r"your bank|security team|hr department)\b", re.I)
_AI_OPENINGS = re.compile(
    r"\b(i hope this (email|message) finds you well|i am reaching out to|"
    r"i wanted to bring to your attention|please do not hesitate|"
    r"kindly be informed|as per our records)\b", re.I)


def _normalize(payload: Any) -> dict[str, str]:
    if isinstance(payload, dict):
        return {
            "subject": str(payload.get("subject", "")),
            "body": str(payload.get("body", "")),
            "sender": str(payload.get("sender", "")),
        }
    return {"subject": "", "body": str(payload), "sender": ""}


class ContentAnalyzer(Detector):
    name = "content"
    kind = "content"
    title = "Content & Phishing Analyzer"
    description = "Scores email/message text for AI-generated phishing and social-engineering signals."

    def analyze(self, payload: Any) -> list[Alert]:
        msg = _normalize(payload)
        text = f"{msg['subject']}\n{msg['body']}"
        if not text.strip():
            return []

        score = 0.0
        indicators: list[str] = []

        def add(points: float, label: str):
            nonlocal score
            score += points
            indicators.append(label)

        if _URGENCY.search(text):
            add(20, "urgency / pressure language")
        if _CREDS.search(text):
            add(25, "requests credentials / verification")
        if _PAYMENT.search(text):
            add(25, "requests payment / wire / gift cards")
        if _AUTHORITY.search(text):
            add(12, "impersonates an authority / known brand")
        if _AI_OPENINGS.search(text):
            add(10, "AI-style boilerplate phrasing")

        # link analysis
        urls = _URL.findall(text)
        if _SHORTENERS.search(text):
            add(15, "URL shortener hides destination")
        if _RAW_IP_URL.search(text):
            add(20, "link points to a raw IP address")
        if _PUNYCODE.search(text):
            add(25, "punycode / homograph domain (look-alike)")
        for href, label in _HTML_LINK.findall(text):
            label_url = _URL.findall(label)
            if label_url and href and label_url[0].split("/")[2] not in href:
                add(22, "display text and real link domain differ")
                break
        if len(urls) >= 5:
            add(8, f"{len(urls)} links in one message")

        # sender vs. claimed brand mismatch (very light check)
        sender = msg["sender"].lower()
        if sender and _AUTHORITY.search(text):
            freemail = re.search(r"@(gmail|outlook|hotmail|yahoo|proton|mail)\.", sender)
            if freemail:
                add(18, "brand claim sent from a free-mail address")

        if score <= 0:
            return []

        score = min(100, score)
        return [self.alert(
            "ai_phishing" if score >= 40 else "social_engineering",
            "Likely AI-generated phishing" if score >= 65 else "Suspicious / social-engineering content",
            "Message exhibits multiple phishing indicators. Modern campaigns use LLMs to "
            "produce fluent, personalized lures — treat fluency as neutral and weigh the "
            "behavioural signals below.",
            score,
            indicators=indicators,
            source=msg["sender"] or None,
        )]
