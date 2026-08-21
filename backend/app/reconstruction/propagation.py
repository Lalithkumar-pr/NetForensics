"""
Propagation analysis module for NetForensics.
Evaluates propagation consistency by matching candidate expected impact against observed evidence.
"""

from typing import Dict, List, Optional, Set, Tuple
from backend.app.normalization.models import NormalizedDataset, EvidenceEvent, NormalizedTopology


def identify_observed_impact(dataset: NormalizedDataset) -> Tuple[Set[str], Set[str]]:
    """
    Derives observed affected and unaffected entities strictly from evidence events.
    """
    observed_affected: Set[str] = set()
    observed_unaffected: Set[str] = set()

    for event in dataset.evidence_events:
        entity = event.entity
        if not entity:
            continue

        if event.source == "event_log":
            severity = (event.attributes.get("severity") or "").upper()
            event_type = (event.attributes.get("event_type") or "").upper()
            details = (event.attributes.get("details") or "").lower()

            if (
                severity in ("CRITICAL", "ERROR", "WARN")
                or "DOWN" in event_type
                or "FAILURE" in event_type
                or "TIMEOUT" in event_type
                or "unreachable" in details
                or "timeout" in details
            ):
                observed_affected.add(entity)

            if severity == "INFO" and ("success" in details or "LINK_UP" in event_type):
                observed_unaffected.add(entity)

        elif event.source == "pcap":
            protocol = event.attributes.get("protocol")
            summary = event.attributes.get("summary", "")
            src_ip = event.attributes.get("src_ip")

            if src_ip:
                if "retransmission" in summary.lower() or "unreachable" in summary.lower():
                    observed_affected.add(src_ip)
                elif protocol in ("ICMP", "TCP", "UDP") and "echo-reply" in summary:
                    observed_unaffected.add(src_ip)

    # Clean overlap: if an entity has explicit affected signals, remove from unaffected
    observed_unaffected -= observed_affected

    return observed_affected, observed_unaffected


def get_downstream_dependents(topology: NormalizedTopology, target: str) -> Set[str]:
    """
    Traverses topology links to identify downstream end-hosts dependent on target device or link.
    """
    dependents: Set[str] = set()
    if not target:
        return dependents

    # Target could be device ID (e.g. "SW1"), interface (e.g. "SW1:Gi0/1"), or link ("SW1-R1")
    target_clean = target.split(":")[0].split("-")[0]

    # Find devices connected to target
    connected: Set[str] = set()
    for link in topology.links:
        node_a = link.get("a")
        node_b = link.get("b")
        if node_a == target_clean and node_b:
            connected.add(node_b)
        elif node_b == target_clean and node_a:
            connected.add(node_a)

    # Check which devices are end-hosts
    for dev in topology.devices:
        dev_id = dev.get("id")
        dev_type = dev.get("type")
        if dev_id in connected:
            if dev_type in ("host", "end_device", "workstation"):
                dependents.add(dev_id)
                ip = dev.get("ip")
                if ip:
                    dependents.add(ip)

    return dependents


def evaluate_propagation_consistency(
    hypothesis_type: str,
    target_entity: Optional[str],
    involved_entities: List[str],
    dataset: NormalizedDataset,
) -> float:
    """
    Calculates propagation consistency score (0.0 to 1.0) by matching expected vs observed scope.
    """
    observed_affected, observed_unaffected = identify_observed_impact(dataset)

    if not observed_affected and not observed_unaffected:
        return 0.5

    # Determine candidate target primary device
    primary_target = target_entity or (involved_entities[0] if involved_entities else "")
    primary_device = primary_target.split(":")[0].split("-")[0]

    # 1. Endpoint / Single Access Port Failure
    if hypothesis_type in ("endpoint_failure", "interface_failure", "vlan_misconfiguration", "arp_resolution_failure"):
        # Expects single host/entity affected
        target_hosts = [e for e in involved_entities if e.startswith("PC") or e.startswith("10.0.0.")]
        if target_hosts:
            expected_affected = set(target_hosts)
            # All other observed hosts expected unaffected
            expected_unaffected = observed_unaffected

            affected_match = len(expected_affected & observed_affected) / max(len(expected_affected), 1)
            # Check if unaffected hosts are indeed healthy
            other_affected = observed_affected - expected_affected
            if other_affected:
                return max(0.2, affected_match * 0.5)
            return min(1.0, 0.5 + 0.5 * affected_match)

    # 2. Upstream Switch / Physical Link / Routing Failure
    if hypothesis_type in ("physical_link_failure", "routing_failure"):
        dependents = get_downstream_dependents(dataset.topology, primary_device)
        if dependents:
            # Expected all dependents affected
            matched_affected = dependents & observed_affected
            if matched_affected:
                score = len(matched_affected) / max(len(dependents), 1)
                # Penalty if dependents expected affected are observed healthy
                healthy_dependents = dependents & observed_unaffected
                if healthy_dependents:
                    score -= 0.3 * (len(healthy_dependents) / len(dependents))
                return max(0.0, min(1.0, score))

    # 3. Degraded Link
    if hypothesis_type == "degraded_link":
        # Expects intermittent loss on traversed endpoints
        if observed_affected and len(observed_affected) >= 1:
            return 0.85
        return 0.4

    # 4. Service Failure (DNS / DHCP)
    if hypothesis_type in ("service_failure", "addressing_failure"):
        # Affects hosts querying service
        if observed_affected:
            return 0.80
        return 0.5

    # Default fallback calculation
    return 0.5
