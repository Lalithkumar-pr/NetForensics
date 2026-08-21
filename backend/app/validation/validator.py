"""
Main validator orchestrator for NetForensics Evidence Validation & Diagnostic Confidence Layer (Phase 5).
"""

from typing import List, Optional
from backend.app.correlation.models import CorrelationResult
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset
from backend.app.reconstruction.models import ReconstructionResult
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
    HypothesisSeparation,
)


def validate_reconstruction(
    dataset: NormalizedDataset,
    correlation_result: Optional[CorrelationResult],
    reconstruction_result: ReconstructionResult,
    config: Optional[DiagnosticValidationConfig] = None,
) -> DiagnosticReport:
    """
    Evaluates evidence coverage, source diversity, completeness, contradictions,
    hypothesis separation, and calculates diagnostic confidence.

    Args:
        dataset: NormalizedDataset containing evidence events and topology.
        correlation_result: CorrelationResult from Phase 3.
        reconstruction_result: ReconstructionResult from Phase 4.
        config: Optional DiagnosticValidationConfig.

    Returns:
        Structured DiagnosticReport.
    """
    if config is None:
        config = DiagnosticValidationConfig()

    primary = reconstruction_result.primary_hypothesis
    ranked = reconstruction_result.ranked_hypotheses

    if primary is None or not ranked:
        empty_cov = evaluate_evidence_coverage(None, dataset, [])
        empty_div = evaluate_source_diversity([])
        empty_comp = EvidenceCompleteness([], [], [], 0.0)
        empty_sep = evaluate_hypothesis_separation([])
        empty_contra = ContradictionSummary(0, [], "NONE", 0.0)

        return DiagnosticReport(
            incident_id=getattr(dataset.topology, "scenario_id", "incident_unknown") or "incident_unknown",
            leading_hypothesis_type="none",
            leading_hypothesis_title="No candidate hypothesis generated",
            target_entity="none",
            hypothesis_score=0.0,
            diagnostic_confidence=0.0,
            confidence_band="INSUFFICIENT",
            evidence_coverage=empty_cov,
            source_diversity=empty_div,
            evidence_completeness=empty_comp,
            hypothesis_separation=empty_sep,
            contradiction_summary=empty_contra,
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
            missing_evidence=["Insufficient evidence events to validate hypothesis."],
            recommended_next_steps=[],
            explanation="No candidate hypothesis was generated from the provided evidence.",
        )

    # 1. Match supporting events for primary hypothesis
    supporting_events: List[EvidenceEvent] = [
        e for e in dataset.evidence_events if e.id in primary.supporting_evidence
    ]

    # 2. Evaluate Evidence Coverage & Source Diversity
    coverage = evaluate_evidence_coverage(primary, dataset, supporting_events)
    diversity = evaluate_source_diversity(coverage.independent_sources)

    # 3. Evaluate Contradictions
    contradiction = evaluate_contradictions(primary)

    # 4. Evaluate Evidence Completeness & Missing Evidence
    completeness, missing_evidence = evaluate_evidence_completeness(primary, dataset, supporting_events)

    # 5. Evaluate Hypothesis Separation / Margin
    separation = evaluate_hypothesis_separation(ranked)

    # 6. Calculate Diagnostic Confidence & Band
    confidence = calculate_diagnostic_confidence(
        hypothesis=primary,
        coverage=coverage,
        diversity=diversity,
        completeness=completeness,
        separation=separation,
        contradiction=contradiction,
        config=config,
    )

    # 7. Generate Investigation Recommendations
    recommendations = generate_investigation_recommendations(primary, completeness, separation)

    # 8. Construct Auditable Explanation
    explanation_lines = [
        f"Incident Diagnostic Validation Report for '{primary.title}' [{primary.hypothesis_type}].",
        f"Phase 4 Hypothesis Score: {primary.score_breakdown.final_score:.4f} | Diagnostic Confidence: {confidence.confidence_score:.4f} (Band: {confidence.confidence_band}).",
        f"Evidence Coverage: {coverage.coverage_score:.2f} across {len(coverage.independent_sources)} source(s) ({', '.join(coverage.independent_sources)}).",
        f"Source Diversity: {diversity.diversity_score:.2f} | Evidence Completeness: {completeness.completeness_score:.2f}.",
        f"Hypothesis Separation Margin: {separation.score_margin:.4f} vs runner-up.",
        f"Contradictions: Severity {contradiction.severity_level} (Penalty deduction: -{contradiction.contradiction_penalty:.2f}).",
    ]
    if missing_evidence:
        explanation_lines.append(f"Missing Evidence: {len(missing_evidence)} signal(s) unconfirmed.")

    report = DiagnosticReport(
        incident_id=getattr(dataset.topology, "scenario_id", "incident_001") or "incident_001",
        leading_hypothesis_type=primary.hypothesis_type,
        leading_hypothesis_title=primary.title,
        target_entity=primary.target_entity or "unspecified",
        hypothesis_score=primary.score_breakdown.final_score if primary.score_breakdown else 0.0,
        diagnostic_confidence=confidence.confidence_score,
        confidence_band=confidence.confidence_band,
        evidence_coverage=coverage,
        source_diversity=diversity,
        evidence_completeness=completeness,
        hypothesis_separation=separation,
        contradiction_summary=contradiction,
        supporting_evidence_ids=sorted(primary.supporting_evidence),
        contradicting_evidence_ids=sorted(contradiction.contradicting_event_ids),
        missing_evidence=missing_evidence,
        recommended_next_steps=recommendations,
        explanation="\n".join(explanation_lines),
    )

    return report
