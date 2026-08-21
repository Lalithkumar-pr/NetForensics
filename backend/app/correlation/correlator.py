"""
Core correlation orchestrator module for NetForensics.
Applies deterministic rules over normalized evidence events and network topology.
"""

from typing import List, Optional

from backend.app.normalization.models import NormalizedDataset
from .models import CorrelationConfig, CorrelationRelationship, CorrelationResult
from .rules import (
    check_entity_rule,
    check_network_flow_rule,
    check_temporal_rule,
    check_topology_rule,
)


def correlate_dataset(
    dataset: NormalizedDataset,
    config: Optional[CorrelationConfig] = None,
) -> CorrelationResult:
    """
    Deterministically correlates normalized evidence events and topology.

    Args:
        dataset: NormalizedDataset containing evidence events and topology.
        config: Optional CorrelationConfig instance. Uses default if None.

    Returns:
        CorrelationResult containing identified CorrelationRelationship instances.
    """
    if config is None:
        config = CorrelationConfig()

    events = dataset.evidence_events
    topology = dataset.topology
    relationships: List[CorrelationRelationship] = []

    n_events = len(events)
    for i in range(n_events):
        for j in range(i + 1, n_events):
            event_a = events[i]
            event_b = events[j]

            matched_types: List[str] = []
            explanations: List[str] = []

            # 1. Temporal correlation rule
            is_temp, time_delta, exp_temp = check_temporal_rule(event_a, event_b, config)
            if is_temp:
                matched_types.append("temporal")
                explanations.append(exp_temp)

            # 2. Entity correlation rule
            is_entity, exp_entity = check_entity_rule(event_a, event_b)
            if is_entity:
                matched_types.append("entity")
                explanations.append(exp_entity)

            # 3. Topology correlation rule
            is_topo, exp_topo = check_topology_rule(event_a, event_b, topology)
            if is_topo:
                matched_types.append("topology")
                explanations.append(exp_topo)

            # 4. Network flow correlation rule
            is_flow, exp_flow = check_network_flow_rule(event_a, event_b)
            if is_flow:
                matched_types.append("network_flow")
                explanations.append(exp_flow)

            # If at least one relationship rule matched
            if matched_types:
                num_rules = len(matched_types)
                if num_rules == 1:
                    strength = 0.4
                elif num_rules == 2:
                    strength = 0.7
                elif num_rules == 3:
                    strength = 0.85
                else:
                    strength = 1.0

                combined_explanation = " | ".join(explanations)

                rel = CorrelationRelationship(
                    source_event_id=event_a.id,
                    target_event_id=event_b.id,
                    relationship_types=matched_types,
                    time_delta=time_delta,
                    strength=strength,
                    explanation=combined_explanation,
                    details={
                        "rules_matched": matched_types,
                        "source_category": event_a.category,
                        "target_category": event_b.category,
                    },
                )
                relationships.append(rel)

    return CorrelationResult(
        relationships=relationships,
        config=config,
    )
