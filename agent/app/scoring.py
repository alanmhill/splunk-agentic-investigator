"""
scoring.py

Deterministic scoring for detections.

- Uses detection pack scoring.base_risk when present
- Optionally applies simple boosts
- Maps risk score -> severity tier
"""

from __future__ import annotations

from typing import Any, Dict, Tuple


def severity_from_score(score: int) -> str:
    if score >= 100:
        return "critical"
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def score_finding(detection_def: Dict[str, Any], result_rows: int) -> Tuple[int, str]:
    """
    Returns (risk_score, severity)
    """
    scoring = detection_def.get("scoring", {}) or {}
    base = int(scoring.get("base_risk", 50))

    # Simple boost: more rows -> higher risk (cap at +20)
    boost = min(20, max(0, result_rows - 1) * 2)

    total = base + boost
    return total, severity_from_score(total)