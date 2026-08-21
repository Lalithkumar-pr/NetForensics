"""
Data models for the NetForensics evidence normalization layer.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Union


@dataclass
class EvidenceEvent:
    """
    Unified internal representation for a single timestamped evidence record
    originating from events.log or traffic.pcap.
    """
    id: str
    timestamp: Union[str, float, None]
    source: str  # e.g., "event_log" or "pcap"
    category: str  # e.g., "link_state", "routing_event", "connectivity", "packet"
    entity: Union[str, None]  # e.g., device hostname, interface, or IP address
    attributes: Dict[str, Any] = field(default_factory=dict)
    raw_reference: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert EvidenceEvent to a plain dictionary representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source,
            "category": self.category,
            "entity": self.entity,
            "attributes": self.attributes,
            "raw_reference": self.raw_reference,
        }


@dataclass
class NormalizedTopology:
    """
    Normalized representation of network devices, interfaces, and link structures.
    """
    devices: List[Dict[str, Any]] = field(default_factory=list)
    links: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert NormalizedTopology to a plain dictionary representation."""
        return {
            "devices": self.devices,
            "links": self.links,
            "raw": self.raw,
        }


@dataclass
class NormalizedDataset:
    """
    Top-level normalized container holding evidence events and network topology.
    """
    evidence_events: List[EvidenceEvent] = field(default_factory=list)
    topology: NormalizedTopology = field(default_factory=NormalizedTopology)

    def to_dict(self) -> Dict[str, Any]:
        """Convert NormalizedDataset to a plain dictionary representation."""
        return {
            "evidence_events": [evt.to_dict() for evt in self.evidence_events],
            "topology": self.topology.to_dict(),
        }
