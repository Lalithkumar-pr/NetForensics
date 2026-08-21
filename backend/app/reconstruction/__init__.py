"""
NetForensics Evidence Reconstruction Package.
Provides deterministic root-cause hypothesis generation, propagation consistency scoring, and ranking.
"""

from .explanations import generate_auditable_explanation
from .hypotheses import generate_candidate_hypotheses
from .models import (
    FailureSignature,
    Hypothesis,
    IncidentContext,
    ReconstructionConfig,
    ReconstructionResult,
    ScoreBreakdown,
)
from .propagation import evaluate_propagation_consistency
from .reconstructor import reconstruct_incidents
from .scoring import evaluate_hypothesis_score
from .signatures import FAILURE_SIGNATURE_CATALOG

__all__ = [
    "ReconstructionConfig",
    "FailureSignature",
    "IncidentContext",
    "ScoreBreakdown",
    "Hypothesis",
    "ReconstructionResult",
    "FAILURE_SIGNATURE_CATALOG",
    "generate_candidate_hypotheses",
    "evaluate_hypothesis_score",
    "evaluate_propagation_consistency",
    "generate_auditable_explanation",
    "reconstruct_incidents",
]
