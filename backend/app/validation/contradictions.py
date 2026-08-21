"""
Contradiction analysis module for NetForensics (Phase 5).
Classifies and evaluates contradicting evidence for diagnostic validation.
"""

from backend.app.reconstruction.models import Hypothesis
from .models import ContradictionSummary


def evaluate_contradictions(hypothesis: Hypothesis) -> ContradictionSummary:
    """
    Evaluates contradiction severity and penalty for the leading hypothesis.
    """
    sb = hypothesis.score_breakdown
    penalty = sb.contradiction_penalty if sb else 0.0
    contradicting_ids = sorted(list(set(hypothesis.contradicting_evidence)))
    count = len(contradicting_ids)

    if penalty == 0.0 and count == 0:
        severity = "NONE"
    elif penalty < 0.30:
        severity = "WEAK"
    elif penalty < 0.60:
        severity = "MODERATE"
    else:
        severity = "STRONG"

    return ContradictionSummary(
        contradiction_count=count,
        contradicting_event_ids=contradicting_ids,
        severity_level=severity,
        contradiction_penalty=penalty,
    )
