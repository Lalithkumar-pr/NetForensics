"""
Data models for the NetForensics evidence reconstruction & root-cause hypothesis engine.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from backend.app.correlation.models import CorrelationResult
from backend.app.normalization.models import NormalizedDataset


@dataclass
class ReconstructionConfig:
    """
    Configurable scoring weights and parameters for hypothesis evaluation.
    Formula: Score = 0.30*Support + 0.15*Temporal + 0.20*Topology + 0.25*Propagation + 0.10*Specificity - ContradictionPenalty
    """
    weight_evidence_support: float = 0.30
    weight_temporal_consistency: float = 0.15
    weight_topology_consistency: float = 0.20
    weight_propagation_consistency: float = 0.25
    weight_specificity: float = 0.10


@dataclass
class FailureSignature:
    """
    Represents an observable failure pattern catalog entry.
    """
    type: str
    description: str
    supporting_categories: List[str] = field(default_factory=list)
    contradicting_categories: List[str] = field(default_factory=list)
    expected_propagation: str = ""


@dataclass
class IncidentContext:
    """
    Unified context containing inputs for incident reconstruction.
    Derived purely from Phase 2 normalized datasets and Phase 3 correlation results.
    """
    dataset: NormalizedDataset
    correlation_result: CorrelationResult
    start_time: Optional[float] = None
    end_time: Optional[float] = None


@dataclass
class ScoreBreakdown:
    """
    Decomposed score components for auditable hypothesis evaluation.
    """
    evidence_support: float
    temporal_consistency: float
    topology_consistency: float
    propagation_consistency: float
    specificity: float
    contradiction_penalty: float
    final_score: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert ScoreBreakdown to dictionary format."""
        return {
            "evidence_support": round(self.evidence_support, 4),
            "temporal_consistency": round(self.temporal_consistency, 4),
            "topology_consistency": round(self.topology_consistency, 4),
            "propagation_consistency": round(self.propagation_consistency, 4),
            "specificity": round(self.specificity, 4),
            "contradiction_penalty": round(self.contradiction_penalty, 4),
            "final_score": round(self.final_score, 4),
        }


@dataclass
class Hypothesis:
    """
    Represents a candidate root-cause hypothesis explanation.
    """
    id: str
    hypothesis_type: str
    title: str
    target_entity: Optional[str]
    involved_entities: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    score_breakdown: Optional[ScoreBreakdown] = None
    confidence_level: str = "LOW"
    explanation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert Hypothesis to dictionary format."""
        return {
            "id": self.id,
            "hypothesis_type": self.hypothesis_type,
            "title": self.title,
            "target_entity": self.target_entity,
            "involved_entities": self.involved_entities,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "score_breakdown": self.score_breakdown.to_dict() if self.score_breakdown else None,
            "confidence_level": self.confidence_level,
            "explanation": self.explanation,
            "details": self.details,
        }


@dataclass
class ReconstructionResult:
    """
    Container holding primary hypothesis and complete ranked candidate list.
    """
    primary_hypothesis: Optional[Hypothesis] = None
    ranked_hypotheses: List[Hypothesis] = field(default_factory=list)
    config: ReconstructionConfig = field(default_factory=ReconstructionConfig)

    def to_dict(self) -> Dict[str, Any]:
        """Convert ReconstructionResult to dictionary format."""
        return {
            "primary_hypothesis": self.primary_hypothesis.to_dict() if self.primary_hypothesis else None,
            "ranked_hypotheses": [h.to_dict() for h in self.ranked_hypotheses],
            "config": {
                "weight_evidence_support": self.config.weight_evidence_support,
                "weight_temporal_consistency": self.config.weight_temporal_consistency,
                "weight_topology_consistency": self.config.weight_topology_consistency,
                "weight_propagation_consistency": self.config.weight_propagation_consistency,
                "weight_specificity": self.config.weight_specificity,
            },
        }
