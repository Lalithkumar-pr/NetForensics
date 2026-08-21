"""
Evidence completeness and missing evidence detection module for NetForensics (Phase 5).
"""

from typing import Dict, List, Tuple
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset
from backend.app.reconstruction.models import Hypothesis
from .models import EvidenceCompleteness

# Generic failure-class evidence requirements catalog
FAILURE_REQUIREMENTS_CATALOG: Dict[str, List[Tuple[str, str]]] = {
    "physical_link_failure": [
        ("LINK_DOWN_event", "Explicit link state DOWN event in log"),
        ("topology_relationship", "Topological link connection between endpoints"),
        ("downstream_impact", "Observed connectivity loss on downstream dependents"),
        ("pcap_corroboration", "Packet-level traffic interruption or timeout"),
    ],
    "interface_failure": [
        ("interface_state_event", "Interface error or state change event in log"),
        ("device_log_error", "Hardware error counter or port exception log"),
        ("topology_relationship", "Declared device interface in topology"),
    ],
    "degraded_link": [
        ("link_remains_UP", "Physical layer status confirmed operational/UP"),
        ("interface_error_counters", "Interface CRC, frame, or input error logs"),
        ("packet_loss_signal", "Observed packet loss in traffic capture"),
        ("tcp_retransmission", "TCP retransmission or out-of-order packets"),
    ],
    "routing_failure": [
        ("routing_protocol_event", "Routing protocol change or neighbor state event"),
        ("destination_unreachable", "ICMP destination unreachable or route drop"),
        ("topology_path_exist", "Topological routing path existence"),
    ],
    "vlan_misconfiguration": [
        ("vlan_event_or_isolation", "VLAN tag mismatch or isolation event"),
        ("access_port_log", "Access/trunk port configuration log"),
        ("broadcast_isolation", "Broadcast/ARP isolation between subnets"),
    ],
    "arp_resolution_failure": [
        ("unanswered_arp_requests", "Unanswered ARP request broadcasts in traffic"),
        ("ip_ping_timeout", "IP ping/connectivity timeout"),
        ("local_subnet_adjacency", "Local L2 subnet adjacency in topology"),
    ],
    "service_failure": [
        ("service_timeout_event", "Application or service-specific timeout event"),
        ("healthy_lower_layer_ping", "Healthy IP lower-layer ICMP ping reachability"),
        ("service_port_traffic", "Service port traffic capture (e.g. DNS port 53)"),
    ],
    "addressing_failure": [
        ("dhcp_timeout_event", "DHCP lease or address allocation timeout event"),
        ("address_allocation_failure", "Failed IP address assignment log"),
        ("dhcp_port_traffic", "DHCP discovery/request traffic capture (port 67/68)"),
    ],
    "endpoint_failure": [
        ("isolated_endpoint_timeout", "Connectivity timeout isolated to single endpoint"),
        ("healthy_neighbor_nodes", "Confirmed healthy operation of neighboring nodes"),
    ],
}


def evaluate_evidence_completeness(
    hypothesis: Hypothesis,
    dataset: NormalizedDataset,
    supporting_events: List[EvidenceEvent],
) -> Tuple[EvidenceCompleteness, List[str]]:
    """
    Evaluates evidence completeness against expected signals and identifies missing evidence.
    """
    htype = hypothesis.hypothesis_type
    req_items = FAILURE_REQUIREMENTS_CATALOG.get(
        htype,
        [
            ("log_evidence", "Log evidence supporting hypothesis"),
            ("topology_evidence", "Topology structural relationship"),
        ]
    )

    required_signals = [item[0] for item in req_items]
    present_signals: List[str] = []
    missing_signals: List[str] = []
    missing_descriptions: List[str] = []

    sb = hypothesis.score_breakdown
    has_pcap = any(e.source == "pcap" for e in supporting_events)
    has_log = any(e.source == "event_log" for e in supporting_events)

    for sig_id, desc in req_items:
        is_present = False

        if sig_id in ("LINK_DOWN_event", "interface_state_event", "device_log_error", "routing_protocol_event", "vlan_event_or_isolation", "service_timeout_event", "dhcp_timeout_event", "isolated_endpoint_timeout", "log_evidence"):
            if has_log:
                is_present = True

        elif sig_id in ("topology_relationship", "topology_path_exist", "local_subnet_adjacency", "topology_evidence"):
            if sb and sb.topology_consistency >= 0.60:
                is_present = True

        elif sig_id in ("downstream_impact", "healthy_neighbor_nodes"):
            if sb and sb.propagation_consistency >= 0.60:
                is_present = True

        elif sig_id in ("pcap_corroboration", "packet_loss_signal", "tcp_retransmission", "unanswered_arp_requests", "service_port_traffic", "dhcp_port_traffic"):
            if has_pcap:
                is_present = True

        elif sig_id in ("link_remains_UP", "healthy_lower_layer_ping"):
            if sb and sb.contradiction_penalty < 0.30:
                is_present = True

        if is_present:
            present_signals.append(sig_id)
        else:
            missing_signals.append(sig_id)
            missing_descriptions.append(f"Missing {sig_id.replace('_', ' ')}: {desc}.")

    total = len(required_signals)
    completeness_score = (len(present_signals) / max(total, 1)) if total > 0 else 0.5

    completeness = EvidenceCompleteness(
        required_signals=required_signals,
        present_signals=present_signals,
        missing_signals=missing_signals,
        completeness_score=completeness_score,
    )

    return completeness, missing_descriptions
