"""
Typed data models for the NetForensics Evidence Validation & Diagnostic Confidence Layer (Phase 5).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DiagnosticValidationConfig:
    """
    Configuration parameters and weights for Phase 5 diagnostic confidence calculation.
    """
    weight_hypothesis_score: float = 0.25
    weight_evidence_coverage: float = 0.25
    weight_source_diversity: float = 0.20
    weight_evidence_completeness: float = 0.15
    weight_hypothesis_separation: float = 0.15
    contradiction_penalty_multiplier: float = 0.40

    threshold_high: float = 0.80
    threshold_moderate: float = 0.60
    threshold_low: float = 0.40


@dataclass
class EvidenceCoverage:
    """
    Evaluation of evidence coverage breadth across categories and sources.
    """
    event_count: int
    independent_sources: List[str]
    has_event_log_support: bool
    has_pcap_support: bool
    has_topology_support: bool
    has_temporal_support: bool
    has_propagation_support: bool
    coverage_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_count": self.event_count,
            "independent_sources": sorted(self.independent_sources),
            "has_event_log_support": self.has_event_log_support,
            "has_pcap_support": self.has_pcap_support,
            "has_topology_support": self.has_topology_support,
            "has_temporal_support": self.has_temporal_support,
            "has_propagation_support": self.has_propagation_support,
            "coverage_score": round(self.coverage_score, 4),
        }


@dataclass
class SourceDiversity:
    """
    Assessment of independent evidence sources supporting the leading hypothesis.
    """
    sources_present: List[str]
    diversity_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sources_present": sorted(self.sources_present),
            "diversity_score": round(self.diversity_score, 4),
        }


@dataclass
class ContradictionSummary:
    """
    Detailed evaluation of contradicting evidence for the leading hypothesis.
    """
    contradiction_count: int
    contradicting_event_ids: List[str]
    severity_level: str  # "NONE", "WEAK", "MODERATE", "STRONG"
    contradiction_penalty: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contradiction_count": self.contradiction_count,
            "contradicting_event_ids": sorted(self.contradicting_event_ids),
            "severity_level": self.severity_level,
            "contradiction_penalty": round(self.contradiction_penalty, 4),
        }


@dataclass
class EvidenceCompleteness:
    """
    Check of required vs observed evidence signals for a failure class.
    """
    required_signals: List[str]
    present_signals: List[str]
    missing_signals: List[str]
    completeness_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "required_signals": self.required_signals,
            "present_signals": self.present_signals,
            "missing_signals": self.missing_signals,
            "completeness_score": round(self.completeness_score, 4),
        }


@dataclass
class HypothesisSeparation:
    """
    Separation margin between the leading hypothesis and the runner-up.
    """
    leading_score: float
    runner_up_score: float
    score_margin: float
    is_ambiguous: bool
    separation_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leading_score": round(self.leading_score, 4),
            "runner_up_score": round(self.runner_up_score, 4),
            "score_margin": round(self.score_margin, 4),
            "is_ambiguous": self.is_ambiguous,
            "separation_score": round(self.separation_score, 4),
        }


@dataclass
class DiagnosticConfidence:
    """
    Diagnostic confidence score and band assignment.
    """
    confidence_score: float
    confidence_band: str  # "HIGH", "MODERATE", "LOW", "INSUFFICIENT"
    breakdown: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confidence_score": round(self.confidence_score, 4),
            "confidence_band": self.confidence_band,
            "breakdown": {k: round(v, 4) for k, v in self.breakdown.items()},
        }


@dataclass
class InvestigationRecommendation:
    """
    Recommended verification step for investigators.
    """
    step_number: int
    action: str
    target_entity: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "action": self.action,
            "target_entity": self.target_entity,
            "rationale": self.rationale,
        }


@dataclass
class DiagnosticReport:
    """
    Comprehensive, auditable forensic diagnostic validation report.
    """
    incident_id: str
    leading_hypothesis_type: str
    leading_hypothesis_title: str
    target_entity: str
    hypothesis_score: float
    diagnostic_confidence: float
    confidence_band: str
    evidence_coverage: EvidenceCoverage
    source_diversity: SourceDiversity
    evidence_completeness: EvidenceCompleteness
    hypothesis_separation: HypothesisSeparation
    contradiction_summary: ContradictionSummary
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    recommended_next_steps: List[InvestigationRecommendation] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert DiagnosticReport to dictionary for deterministic JSON output."""
        return {
            "incident_id": self.incident_id,
            "leading_hypothesis_type": self.leading_hypothesis_type,
            "leading_hypothesis_title": self.leading_hypothesis_title,
            "target_entity": self.target_entity,
            "hypothesis_score": round(self.hypothesis_score, 4),
            "diagnostic_confidence": round(self.diagnostic_confidence, 4),
            "confidence_band": self.confidence_band,
            "evidence_coverage": self.evidence_coverage.to_dict(),
            "source_diversity": self.source_diversity.to_dict(),
            "evidence_completeness": self.evidence_completeness.to_dict(),
            "hypothesis_separation": self.hypothesis_separation.to_dict(),
            "contradiction_summary": self.contradiction_summary.to_dict(),
            "supporting_evidence_ids": sorted(self.supporting_evidence_ids),
            "contradicting_evidence_ids": sorted(self.contradicting_evidence_ids),
            "missing_evidence": self.missing_evidence,
            "recommended_next_steps": [rec.to_dict() for rec in self.recommended_next_steps],
            "explanation": self.explanation,
        }
