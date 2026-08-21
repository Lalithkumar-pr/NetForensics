"""
Deterministic scoring engine for NetForensics reconstruction hypotheses.
Applies frozen weight formula:
Score = 0.30*EvidenceSupport + 0.15*TemporalConsistency + 0.20*TopologyConsistency + 0.25*PropagationConsistency + 0.10*Specificity - ContradictionPenalty
"""

from typing import Dict, List, Optional, Set, Tuple
from backend.app.correlation.rules import parse_timestamp
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset, NormalizedTopology
from .models import Hypothesis, ReconstructionConfig, ScoreBreakdown
from .propagation import evaluate_propagation_consistency


def calculate_evidence_support(
    supporting_events: List[EvidenceEvent],
) -> float:
    """
    Calculates evidence support score (0.0 to 1.0) based on corroborating signals.
    """
    if not supporting_events:
        return 0.0

    sources: Set[str] = {e.source for e in supporting_events}
    count = len(supporting_events)

    if count == 1:
        # Check if single event is strong direct signal
        evt = supporting_events[0]
        event_type = (evt.attributes.get("event_type") or "").upper()
        if "LINK_DOWN" in event_type or "CRITICAL" in (evt.attributes.get("severity") or ""):
            return 0.50
        return 0.25

    if count >= 2:
        if len(sources) >= 2:
            return 1.00  # Strong independent multi-source corroboration
        return 0.75  # Multiple corroborating signals from same source

    return 0.50


def calculate_temporal_consistency(
    supporting_events: List[EvidenceEvent],
    all_events: List[EvidenceEvent],
) -> float:
    """
    Evaluates temporal consistency (0.0 to 1.0) of initiating events vs downstream symptoms.
    """
    if not supporting_events:
        return 0.5

    # Find earliest initiating event timestamp
    initiating_timestamps: List[float] = []
    symptom_timestamps: List[float] = []

    for evt in supporting_events:
        ts = parse_timestamp(evt.timestamp)
        if ts is not None:
            event_type = (evt.attributes.get("event_type") or "").upper()
            if "DOWN" in event_type or "CRITICAL" in (evt.attributes.get("severity") or ""):
                initiating_timestamps.append(ts)

    for evt in all_events:
        ts = parse_timestamp(evt.timestamp)
        if ts is not None:
            details = (evt.attributes.get("details") or "").lower()
            if "timeout" in details or "unreachable" in details:
                symptom_timestamps.append(ts)

    if initiating_timestamps and symptom_timestamps:
        earliest_cause = min(initiating_timestamps)
        earliest_symptom = min(symptom_timestamps)

        if earliest_cause <= earliest_symptom:
            return 1.00  # Initiating event precedes symptoms
        else:
            return 0.00  # Temporal order contradicts causality

    return 0.50  # Timing plausible


def calculate_topology_consistency(
    target_entity: Optional[str],
    involved_entities: List[str],
    topology: NormalizedTopology,
) -> float:
    """
    Determines topology consistency (0.0 to 1.0) based on declared topology links.
    """
    if not target_entity and not involved_entities:
        return 0.5

    primary = target_entity or (involved_entities[0] if involved_entities else "")
    primary_clean = primary.split(":")[0].split("-")[0]

    # Check if primary entity exists in topology devices or links
    device_ids = {d.get("id") for d in topology.devices}
    link_nodes: Set[str] = set()
    for link in topology.links:
        if link.get("a"):
            link_nodes.add(link["a"])
        if link.get("b"):
            link_nodes.add(link["b"])

    if primary_clean in device_ids or primary_clean in link_nodes or "-" in primary:
        if len(involved_entities) >= 2:
            e1 = involved_entities[0].split(":")[0]
            e2 = involved_entities[1].split(":")[0]
            for link in topology.links:
                a, b = link.get("a"), link.get("b")
                if (a == e1 and b == e2) or (a == e2 and b == e1):
                    return 1.00  # Strongly supported direct link
            return 0.75
        return 0.75

    return 0.00  # Contradicts topology


def calculate_specificity(
    target_entity: Optional[str],
    hypothesis_type: str,
) -> float:
    """
    Calculates specificity score (0.0 to 1.0) rewarding precise candidate descriptions.
    """
    if not target_entity:
        return 0.25

    if ":" in target_entity or "-" in target_entity:
        return 1.00  # Specific device + interface/link/port (e.g. SW1:Gi0/1 or SW1-R1)

    if target_entity in ("SW1", "SW2", "R1", "PC1", "PC2", "SERVER"):
        return 0.75  # Specific device name

    return 0.50


def calculate_contradiction_penalty(
    hypothesis_type: str,
    target_entity: Optional[str],
    all_events: List[EvidenceEvent],
    topology: NormalizedTopology,
) -> Tuple[float, List[str]]:
    """
    Calculates contradiction penalty (>= 0.0) and identifies contradicting evidence IDs.
    """
    penalty = 0.0
    contradicting_ids: List[str] = []

    has_link_down = False
    has_link_up = False
    has_packet_loss = False
    has_healthy_traffic = False

    target_clean = (target_entity or "").split(":")[0].split("-")[0]

    for evt in all_events:
        evt_type = (evt.attributes.get("event_type") or "").upper()
        severity = (evt.attributes.get("severity") or "").upper()
        summary = evt.attributes.get("summary", "")

        if "LINK_DOWN" in evt_type or "DOWN" in evt_type:
            has_link_down = True
        if "LINK_UP" in evt_type:
            has_link_up = True
            if target_clean and evt.entity == target_clean:
                contradicting_ids.append(evt.id)

        if "packet_loss" in summary.lower() or "retransmission" in summary.lower() or "error" in summary.lower():
            has_packet_loss = True
        if evt.source == "pcap" and "echo-reply" in summary:
            has_healthy_traffic = True

    # 1. Physical link failure contradicted by link status UP or healthy traffic
    if hypothesis_type == "physical_link_failure":
        if has_healthy_traffic and not has_link_down:
            penalty += 0.6
        if has_packet_loss and not has_link_down:
            penalty += 0.5

    # 2. Degraded link contradicted by explicit link DOWN
    if hypothesis_type == "degraded_link":
        if has_link_down:
            penalty += 0.6
            for evt in all_events:
                if "LINK_DOWN" in (evt.attributes.get("event_type") or "").upper():
                    contradicting_ids.append(evt.id)

    # 3. VLAN / Service failure contradicted by physical link DOWN
    if hypothesis_type in ("vlan_misconfiguration", "service_failure", "addressing_failure"):
        if has_link_down:
            # Physical failure takes precedence over logical
            penalty += 0.5

    # 4. Single endpoint failure contradicted by multiple widespread host outages
    if hypothesis_type == "endpoint_failure":
        affected_hosts = {
            evt.entity for evt in all_events
            if evt.entity and evt.entity.startswith("PC") and "timeout" in (evt.attributes.get("details") or "")
        }
        if len(affected_hosts) > 1:
            penalty += 0.6

    return penalty, contradicting_ids


def evaluate_hypothesis_score(
    hypothesis: Hypothesis,
    dataset: NormalizedDataset,
    supporting_events: List[EvidenceEvent],
    config: ReconstructionConfig,
) -> ScoreBreakdown:
    """
    Evaluates all score components and returns a deterministic ScoreBreakdown.
    """
    e_support = calculate_evidence_support(supporting_events)
    t_consistency = calculate_temporal_consistency(supporting_events, dataset.evidence_events)
    topo_consistency = calculate_topology_consistency(hypothesis.target_entity, hypothesis.involved_entities, dataset.topology)
    prop_consistency = evaluate_propagation_consistency(hypothesis.hypothesis_type, hypothesis.target_entity, hypothesis.involved_entities, dataset)
    specificity = calculate_specificity(hypothesis.target_entity, hypothesis.hypothesis_type)
    penalty, contradiction_ids = calculate_contradiction_penalty(hypothesis.hypothesis_type, hypothesis.target_entity, dataset.evidence_events, dataset.topology)

    if contradiction_ids:
        hypothesis.contradicting_evidence = list(set(hypothesis.contradicting_evidence + contradiction_ids))

    # Frozen Formula:
    # 0.30*Support + 0.15*Temporal + 0.20*Topology + 0.25*Propagation + 0.10*Specificity - ContradictionPenalty
    raw_score = (
        config.weight_evidence_support * e_support
        + config.weight_temporal_consistency * t_consistency
        + config.weight_topology_consistency * topo_consistency
        + config.weight_propagation_consistency * prop_consistency
        + config.weight_specificity * specificity
        - penalty
    )

    final_score = max(0.0, min(1.0, raw_score))

    return ScoreBreakdown(
        evidence_support=e_support,
        temporal_consistency=t_consistency,
        topology_consistency=topo_consistency,
        propagation_consistency=prop_consistency,
        specificity=specificity,
        contradiction_penalty=penalty,
        final_score=final_score,
    )
