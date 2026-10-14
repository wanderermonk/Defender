from __future__ import annotations

from typing import Any

from ..engine import Alert, Severity, mitigations_for


class Detector:
    """Base class. Subclasses set `name` and `kind` and implement analyze()."""

    name: str = "base"
    kind: str = "generic"
    title: str = "Detector"
    description: str = ""

    def analyze(self, payload: Any) -> list[Alert]:
        raise NotImplementedError

    # convenience factory so subclasses don't repeat boilerplate
    def alert(
        self,
        category: str,
        title: str,
        description: str,
        score: float,
        indicators: list[str] | None = None,
        source: str | None = None,
    ) -> Alert:
        return Alert(
            detector=self.name,
            category=category,
            title=title,
            description=description,
            severity=Severity.from_score(score),
            score=round(float(score), 1),
            indicators=indicators or [],
            mitigations=mitigations_for(category),
            source=source,
        )
