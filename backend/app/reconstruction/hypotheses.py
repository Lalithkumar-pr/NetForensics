"""
Candidate hypothesis generation module for NetForensics.
Generates generic root-cause hypothesis candidates from observed evidence without scenario shortcuts.
"""

from typing import List, Set
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset
from .models import Hypothesis, IncidentContext
from .signatures import FAILURE_SIGNATURE_CATALOG


def generate_candidate_hypotheses(context: IncidentContext) -> List[Hypothesis]:
    """
    Generates plausible candidate hypotheses derived from evidence features and topology.
    """
    dataset = context.dataset
    topology = dataset.topology
    events = dataset.evidence_events

    candidates: List[Hypothesis] = []
    seen_ids: Set[str] = set()

    def add_candidate(h: Hypothesis):
        if h.id not in seen_ids:
            seen_ids.add(h.id)
            candidates.append(h)

    # 1. Scan log and pcap events for diagnostic signals
    for evt in events:
        evt_type = (evt.attributes.get("event_type") or "").upper()
        severity = (evt.attributes.get("severity") or "").upper()
        details = (evt.attributes.get("details") or "").lower()
        summary = (evt.attributes.get("summary") or "").lower()
        iface = evt.attributes.get("interface")
        device = evt.entity

        # Physical link down signal
        if "LINK_DOWN" in evt_type or "UPLINK_FAILURE" in evt_type:
            peer = None
            if details and "peer=" in details:
                peer = details.split("peer=")[1].split()[0]

            if device and peer:
                link_id = f"{device}-{peer}"
                # Primary: physical link failure
                add_candidate(
                    Hypothesis(
                        id=f"hyp_physical_link_failure_{link_id}",
                        hypothesis_type="physical_link_failure",
                        title=f"Physical Link Failure between {device} and {peer}",
                        target_entity=link_id,
                        involved_entities=[device, peer],
                    )
                )
            if device and iface:
                # Competing: interface failure
                add_candidate(
                    Hypothesis(
                        id=f"hyp_interface_failure_{device}_{iface}",
                        hypothesis_type="interface_failure",
                        title=f"Interface Failure on {device} ({iface})",
                        target_entity=f"{device}:{iface}",
                        involved_entities=[device],
                    )
                )

        # Degraded link / Packet loss signal
        if "packet_loss" in summary or "retransmission" in summary or "degraded" in details or "crc" in details:
            if device:
                add_candidate(
                    Hypothesis(
                        id=f"hyp_degraded_link_{device}",
                        hypothesis_type="degraded_link",
                        title=f"Degraded Link / Packet Loss involving {device}",
                        target_entity=device,
                        involved_entities=[device],
                    )
                )
                # Competing physical link failure (to be penalized if link is UP)
                add_candidate(
                    Hypothesis(
                        id=f"hyp_physical_link_failure_{device}",
                        hypothesis_type="physical_link_failure",
                        title=f"Physical Link Failure on {device}",
                        target_entity=device,
                        involved_entities=[device],
                    )
                )

        # Routing failure signal
        if "OSPF" in evt_type or "ROUTE" in evt_type or "unreachable" in details or "routing" in details:
            if device:
                add_candidate(
                    Hypothesis(
                        id=f"hyp_routing_failure_{device}",
                        hypothesis_type="routing_failure",
                        title=f"Routing or Forwarding Failure at {device}",
                        target_entity=device,
                        involved_entities=[device],
                    )
                )

        # VLAN misconfiguration signal
        if "vlan" in details or "vlan" in summary or "vlan_misconfiguration" in evt_type.lower():
            if device:
                add_candidate(
                    Hypothesis(
                        id=f"hyp_vlan_misconfiguration_{device}",
                        hypothesis_type="vlan_misconfiguration",
                        title=f"VLAN Misconfiguration on {device}",
                        target_entity=f"{device}:{iface}" if iface else device,
                        involved_entities=[device],
                    )
                )

        # ARP resolution failure signal
        if "arp" in summary or "arp" in details or "arp_resolution_failure" in evt_type.lower():
            if device:
                add_candidate(
                    Hypothesis(
                        id=f"hyp_arp_resolution_failure_{device}",
                        hypothesis_type="arp_resolution_failure",
                        title=f"ARP Resolution Failure at {device}",
                        target_entity=device,
                        involved_entities=[device],
                    )
                )

        # Service / DNS / DHCP failure signal
        if "dns" in summary or "dns" in details or "port 53" in summary or "service" in details:
            target = device if device else "SERVER"
            add_candidate(
                Hypothesis(
                    id=f"hyp_service_failure_dns_{target}",
                    hypothesis_type="service_failure",
                    title=f"DNS Service Failure on {target}",
                    target_entity=f"{target}:DNS",
                    involved_entities=[target],
                )
            )

        if "dhcp" in summary or "dhcp" in details or "port 67" in summary or "addressing" in details:
            target = device if device else "R1"
            add_candidate(
                Hypothesis(
                    id=f"hyp_addressing_failure_dhcp_{target}",
                    hypothesis_type="addressing_failure",
                    title=f"DHCP Addressing Failure on {target}",
                    target_entity=f"{target}:DHCP",
                    involved_entities=[target],
                )
            )

        # Endpoint failure signal
        if "timeout" in details or "connectivity_timeout" in evt_type.lower():
            if device and (device.startswith("PC") or device.startswith("10.0.0.")):
                add_candidate(
                    Hypothesis(
                        id=f"hyp_endpoint_failure_{device}",
                        hypothesis_type="endpoint_failure",
                        title=f"Endpoint Loss at {device}",
                        target_entity=device,
                        involved_entities=[device],
                    )
                )

    # 2. Topology links fallback candidates if no candidates yet
    if not candidates and topology.links:
        for link in topology.links[:3]:
            link_id = link.get("id", "link")
            a = link.get("a", "node_a")
            b = link.get("b", "node_b")
            add_candidate(
                Hypothesis(
                    id=f"hyp_physical_link_failure_{link_id}",
                    hypothesis_type="physical_link_failure",
                    title=f"Physical Link Failure on Link {link_id} ({a}-{b})",
                    target_entity=f"{a}-{b}",
                    involved_entities=[a, b],
                )
            )

    return candidates
