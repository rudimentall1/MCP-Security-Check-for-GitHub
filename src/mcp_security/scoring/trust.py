"""Optional, explainable trust/provenance score (v0.1: informational only).

Deliberately NOT combined into the risk score -- security risk and trust/
provenance are different concepts (see analyzers/provenance.py) and must
not be conflated. This score is 0-100 where higher means "more provenance
signals present", not "more trustworthy" in any absolute sense.
"""

from __future__ import annotations

from typing import Iterable

from mcp_security.analyzers.provenance import ProvenanceSignal

SIGNAL_WEIGHT = 34  # 3 signals * ~34 ~= 100 max


def compute_trust_score(signals: Iterable[ProvenanceSignal]) -> int:
    signals = list(signals)
    if not signals:
        return 0
    present = sum(1 for s in signals if s.present)
    return min(100, present * SIGNAL_WEIGHT)
