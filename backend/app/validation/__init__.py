"""
NetForensics Evidence Validation & Diagnostic Confidence Package (Phase 5).
Evaluates coverage, source diversity, completeness, contradictions, separation, confidence, and recommended next steps.
"""

from .completeness import evaluate_evidence_completeness
from .confidence import calculate_diagnostic_confidence, evaluate_hypothesis_separation
from .contradictions import evaluate_contradictions
from .coverage import evaluate_evidence_coverage, evaluate_source_diversity
from .investigation import generate_investigation_recommendations
from .models import (
    ContradictionSummary,
    DiagnosticConfidence,
    DiagnosticReport,
    DiagnosticValidationConfig,
    EvidenceCompleteness,
    EvidenceCoverage,
    HypothesisSeparation,
    InvestigationRecommendation,
    SourceDiversity,
)
from .validator import validate_reconstruction

__all__ = [
    "DiagnosticValidationConfig",
    "EvidenceCoverage",
    "SourceDiversity",
    "ContradictionSummary",
    "EvidenceCompleteness",
    "HypothesisSeparation",
    "DiagnosticConfidence",
    "InvestigationRecommendation",
    "DiagnosticReport",
    "validate_reconstruction",
    "evaluate_evidence_coverage",
    "evaluate_source_diversity",
    "evaluate_evidence_completeness",
    "evaluate_contradictions",
    "evaluate_hypothesis_separation",
    "calculate_diagnostic_confidence",
    "generate_investigation_recommendations",
]
