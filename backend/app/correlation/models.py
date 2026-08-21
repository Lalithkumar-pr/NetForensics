"""
Data models for the NetForensics evidence correlation layer.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CorrelationConfig:
    """
    Configuration parameters for evidence correlation.
    """
    temporal_window_seconds: float = 10.0


@dataclass
class CorrelationRelationship:
    """
    Represents a deterministic relationship between two normalized evidence events.
    """
    source_event_id: str
    target_event_id: str
    relationship_types: List[str]  # e.g., ["temporal", "entity", "topology", "network_flow"]
    time_delta: Optional[float]
    strength: float
    explanation: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert CorrelationRelationship to dictionary format."""
        return {
            "source_event_id": self.source_event_id,
            "target_event_id": self.target_event_id,
            "relationship_types": self.relationship_types,
            "time_delta": self.time_delta,
            "strength": self.strength,
            "explanation": self.explanation,
            "details": self.details,
        }


@dataclass
class CorrelationResult:
    """
    Container holding all identified correlation relationships.
    """
    relationships: List[CorrelationRelationship] = field(default_factory=list)
    config: CorrelationConfig = field(default_factory=CorrelationConfig)

    def to_dict(self) -> Dict[str, Any]:
        """Convert CorrelationResult to dictionary format."""
        return {
            "relationships": [rel.to_dict() for rel in self.relationships],
            "config": {
                "temporal_window_seconds": self.config.temporal_window_seconds,
            },
        }
