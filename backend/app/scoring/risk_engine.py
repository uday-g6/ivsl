from typing import List
from app.analyzers.ios.base import RawFinding

SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
CONFIDENCE_MULT = {"high": 1.0, "medium": 0.7, "low": 0.4}


def compute_score(findings: List[RawFinding]) -> dict:
    seen = set()
    penalty = 0.0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = (f.rule_id, f.file_path, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        counts[f.severity] = counts.get(f.severity, 0) + 1
        penalty += SEVERITY_WEIGHT.get(f.severity, 0) * CONFIDENCE_MULT.get(f.confidence, 0.5)

    normalized = 100 * (1 - pow(0.5, penalty / 60.0)) if penalty > 0 else 0.0
    score = max(0.0, min(100.0, 100.0 - normalized))
    return {
        "score": round(score, 1),
        "penalty": round(penalty, 2),
        "counts": counts,
        "deduplicated_total": len(seen),
    }
