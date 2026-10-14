"""Detector modules. Each exposes a class with .name, .kind, and
.analyze(payload) -> list[Alert]."""

from .base import Detector
from .log_analyzer import LogAnalyzer
from .content_analyzer import ContentAnalyzer
from .endpoint_analyzer import EndpointAnalyzer
from .llm_defense import LLMDefense
from .posture import PortExposure, VulnAudit
from .network_baseline import NetworkBaseline

ALL_DETECTORS = [
    LogAnalyzer,
    ContentAnalyzer,
    EndpointAnalyzer,
    LLMDefense,
    PortExposure,
    VulnAudit,
    NetworkBaseline,
]

__all__ = [
    "Detector", "LogAnalyzer", "ContentAnalyzer", "EndpointAnalyzer",
    "LLMDefense", "PortExposure", "VulnAudit", "NetworkBaseline", "ALL_DETECTORS",
]
