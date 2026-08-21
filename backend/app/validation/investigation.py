"""
Investigation recommendation engine for NetForensics (Phase 5).
Generates an ordered list of investigative verification steps derived from missing evidence signals.
"""

from typing import List, Optional
from backend.app.reconstruction.models import Hypothesis
from .models import EvidenceCompleteness, HypothesisSeparation, InvestigationRecommendation


def generate_investigation_recommendations(
    hypothesis: Hypothesis,
    completeness: EvidenceCompleteness,
    separation: HypothesisSeparation,
) -> List[InvestigationRecommendation]:
    """
    Generates actionable, non-modifying investigative recommendations based on missing evidence.
    """
    recommendations: List[InvestigationRecommendation] = []
    step = 1

    htype = hypothesis.hypothesis_type
    target = hypothesis.target_entity or "affected node"

    # Step 1: Target entity interface / physical check
    if htype in ("physical_link_failure", "interface_failure", "degraded_link"):
        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Verify administrative and physical operational state on {target}.",
                target_entity=target,
                rationale="Confirm link status carrier state and interface speed/duplex settings.",
            )
        )
        step += 1

        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Inspect hardware error statistics (CRC errors, frame drops, input/output errors) on {target}.",
                target_entity=target,
                rationale="Identify potential physical layer degradation or faulty transceiver.",
            )
        )
        step += 1

    elif htype == "routing_failure":
        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Check routing table next-hop entries and OSPF/BGP neighbor adjacencies on {target}.",
                target_entity=target,
                rationale="Verify active routing paths and protocol neighbor state.",
            )
        )
        step += 1

    elif htype == "vlan_misconfiguration":
        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Audit access/trunk VLAN port tagging and native VLAN settings on {target}.",
                target_entity=target,
                rationale="Ensure correct broadcast domain isolation and VLAN membership.",
            )
        )
        step += 1

    elif htype == "service_failure":
        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Check service daemon process status and listening port binding on {target}.",
                target_entity=target,
                rationale="Confirm service application is running and processing queries.",
            )
        )
        step += 1

    elif htype == "addressing_failure":
        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Inspect DHCP server pool status, relay agent configuration, and client IP assignment on {target}.",
                target_entity=target,
                rationale="Verify availability of unallocated IP addresses in subnet scope.",
            )
        )
        step += 1

    else:
        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Perform local network adapter and default gateway diagnostic check on {target}.",
                target_entity=target,
                rationale="Isolate failure to endpoint NIC driver or local firewall rule.",
            )
        )
        step += 1

    # Add step for missing packet corroboration if missing
    if "pcap_corroboration" in completeness.missing_signals or "packet_loss_signal" in completeness.missing_signals:
        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Capture network traffic on {target} to inspect packet-level retransmissions or drops.",
                target_entity=target,
                rationale="Obtain packet-level corroboration for traffic flow validation.",
            )
        )
        step += 1

    # Add step if competing runner-up hypothesis is close
    if separation.is_ambiguous:
        recommendations.append(
            InvestigationRecommendation(
                step_number=step,
                action=f"Perform additional diagnostic isolation to differentiate leading hypothesis from runner-up candidate (score margin {separation.score_margin:.4f}).",
                target_entity=target,
                rationale="Close score margin indicates ambiguous evidence separation between top candidate causes.",
            )
        )
        step += 1

    return recommendations
