"""
Diagnostic confidence calculation and confidence band mapping module for NetForensics (Phase 5).
"""

from typing import List, Optional, Tuple
from backend.app.reconstruction.models import Hypothesis
from .models import (
    ContradictionSummary,
    DiagnosticConfidence,
    DiagnosticValidationConfig,
    EvidenceCompleteness,
    EvidenceCoverage,
    HypothesisSeparation,
    SourceDiversity,
)


def evaluate_hypothesis_separation(
    ranked_hypotheses: List[Hypothesis],
) -> HypothesisSeparation:
    """
    Calculates score margin between leading hypothesis and runner-up candidate.
    """
    if not ranked_hypotheses:
        return HypothesisSeparation(0.0, 0.0, 0.0, True, 0.0)

    h1 = ranked_hypotheses[0]
    s1 = h1.score_breakdown.final_score if h1.score_breakdown else 0.0

    s2 = 0.0
    if len(ranked_hypotheses) >= 2:
        h2 = ranked_hypotheses[1]
        s2 = h2.score_breakdown.final_score if h2.score_breakdown else 0.0

    margin = s1 - s2
    is_ambiguous = (margin < 0.10)
    separation_score = max(0.0, min(1.0, margin / 0.30))

    return HypothesisSeparation(
        leading_score=s1,
        runner_up_score=s2,
        score_margin=margin,
        is_ambiguous=is_ambiguous,
        separation_score=separation_score,
    )


def calculate_diagnostic_confidence(
    hypothesis: Hypothesis,
    coverage: EvidenceCoverage,
    diversity: SourceDiversity,
    completeness: EvidenceCompleteness,
    separation: HypothesisSeparation,
    contradiction: ContradictionSummary,
    config: Optional[DiagnosticValidationConfig] = None,
) -> DiagnosticConfidence:
    """
    Calculates deterministic diagnostic confidence score and maps to qualitative confidence band.
    """
    if config is None:
        config = DiagnosticValidationConfig()

    sb = hypothesis.score_breakdown
    h_score = sb.final_score if sb else 0.0

    c_score = coverage.coverage_score
    d_score = diversity.diversity_score
    m_score = completeness.completeness_score
    s_score = separation.separation_score
    penalty = contradiction.contradiction_penalty * config.contradiction_penalty_multiplier

    raw_conf = (
        config.weight_hypothesis_score * h_score
        + config.weight_evidence_coverage * c_score
        + config.weight_source_diversity * d_score
        + config.weight_evidence_completeness * m_score
        + config.weight_hypothesis_separation * s_score
        - penalty
    )

    conf_score = max(0.0, min(1.0, raw_conf))

    # Map to qualitative confidence band
    if conf_score >= config.threshold_high:
        band = "HIGH"
    elif conf_score >= config.threshold_moderate:
        band = "MODERATE"
    elif conf_score >= config.threshold_low:
        band = "LOW"
    else:
        band = "INSUFFICIENT"

    breakdown = {
        "hypothesis_score": h_score,
        "evidence_coverage": c_score,
        "source_diversity": d_score,
        "evidence_completeness": m_score,
        "hypothesis_separation": s_score,
        "contradiction_penalty_deduction": penalty,
    }

    return DiagnosticConfidence(
        confidence_score=conf_score,
        confidence_band=band,
        breakdown=breakdown,
    )
