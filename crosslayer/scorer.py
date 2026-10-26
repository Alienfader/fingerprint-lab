"""Explainable cross-layer scorer. The verdict is derived from contradictions only."""
from dataclasses import asdict, dataclass

from crosslayer.checks import Contradiction, run_checks
from crosslayer.features import js_present

_LAYERS = ("tls", "http2", "http", "js")


@dataclass
class Verdict:
    label: str  # "automated" | "real" | "inconclusive"
    confidence: str  # "high" | "medium" | "low"
    contradictions: list[Contradiction]
    observed: dict

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "confidence": self.confidence,
            "contradictions": [asdict(c) for c in self.contradictions],
            "observed": dict(self.observed),
        }


def score(rec) -> Verdict:
    contradictions = run_checks(rec)
    observed = {layer: getattr(rec, layer, None) is not None for layer in _LAYERS}
    strong_layers = {c.layer for c in contradictions if c.severity == "strong"}

    if strong_layers:
        label = "automated"
        confidence = "high" if len(strong_layers) >= 2 else "medium"
    elif js_present(rec) and not contradictions:
        label = "real"
        confidence = "high" if all(observed.values()) else "low"
    else:
        label, confidence = "inconclusive", "low"
    return Verdict(label, confidence, contradictions, observed)
