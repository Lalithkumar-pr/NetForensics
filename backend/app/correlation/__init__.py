"""
NetForensics Evidence Correlation Package.
Deterministically correlates normalized evidence events using temporal, entity, topology, and network flow rules.
"""

from .correlator import correlate_dataset
from .models import CorrelationConfig, CorrelationRelationship, CorrelationResult
from .rules import (
    check_entity_rule,
    check_network_flow_rule,
    check_temporal_rule,
    check_topology_rule,
    parse_timestamp,
)

__all__ = [
    "CorrelationConfig",
    "CorrelationRelationship",
    "CorrelationResult",
    "correlate_dataset",
    "check_temporal_rule",
    "check_entity_rule",
    "check_topology_rule",
    "check_network_flow_rule",
    "parse_timestamp",
]
