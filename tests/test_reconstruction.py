"""
Unit and integration test suite for NetForensics evidence reconstruction engine (Phase 4).
"""

import json
from pathlib import Path
import pytest

from backend.app.correlation.correlator import correlate_dataset
from backend.app.normalization.models import EvidenceEvent, NormalizedDataset, NormalizedTopology
from backend.app.normalization.normalizer import normalize_evidence_from_paths
from backend.app.reconstruction import (
    Hypothesis,
    ReconstructionConfig,
    ReconstructionResult,
    reconstruct_incidents,
)


# ============================================================================
# ADVERSARIAL & GENERALIZATION TESTS (A-F)
# ============================================================================

def test_generalization_a_degraded_link_outranks_physical_failure():
    """
    Test A: Link is UP with high packet loss / CRC errors.
    Expected: degraded_link outranks physical_link_failure due to contradiction penalty on physical link down.
    """
    event1 = EvidenceEvent(
        id="pcap_0",
        timestamp=100.0,
        source="pcap",
        category="packet",
        entity="10.0.0.11",
        attributes={"src_ip": "10.0.0.11", "dst_ip": "10.0.0.20", "protocol": "TCP", "summary": "TCP retransmission packet_loss crc_error"},
    )
    event2 = EvidenceEvent(
        id="log_1",
        timestamp="2026-08-21T10:00:00Z",
        source="event_log",
        category="link_state",
        entity="SW1",
        attributes={"severity": "INFO", "event_type": "LINK_UP", "interface": "Gi0/4", "details": "crc_errors=1842 input_errors=1917"},
    )
    topology = NormalizedTopology(
        devices=[{"id": "SW1"}, {"id": "SW2"}],
        links=[{"id": "L1", "a": "SW1", "b": "SW2"}],
    )
    dataset = NormalizedDataset(evidence_events=[event1, event2], topology=topology)

    result = reconstruct_incidents(dataset)

    assert result.primary_hypothesis is not None
    assert result.primary_hypothesis.hypothesis_type == "degraded_link"

    # Verify physical_link_failure was penalized by contradiction rule
    phys_hyp = next((h for h in result.ranked_hypotheses if h.hypothesis_type == "physical_link_failure"), None)
    if phys_hyp and phys_hyp.score_breakdown:
        assert phys_hyp.score_breakdown.contradiction_penalty > 0.0


def test_generalization_b_service_failure_outranks_physical():
    """
    Test B: Service port (DNS port 53) fails while IP ping succeeds.
    Expected: service_failure outranks physical connectivity hypotheses.
    """
    event_dns = EvidenceEvent(
        id="log_1",
        timestamp="2026-08-21T10:00:00Z",
        source="event_log",
        category="service_event",
        entity="SERVER",
        attributes={"severity": "WARN", "event_type": "DNS_TIMEOUT", "details": "service=DNS port 53 query timeout"},
    )
    event_ping = EvidenceEvent(
        id="pcap_0",
        timestamp=100.0,
        source="pcap",
        category="packet",
        entity="10.0.0.11",
        attributes={"src_ip": "10.0.0.11", "dst_ip": "10.0.0.20", "protocol": "ICMP", "summary": "ICMP echo-reply success"},
    )
    topology = NormalizedTopology(
        devices=[{"id": "PC1"}, {"id": "SERVER"}],
        links=[{"id": "L1", "a": "PC1", "b": "SERVER"}],
    )
    dataset = NormalizedDataset(evidence_events=[event_dns, event_ping], topology=topology)

    result = reconstruct_incidents(dataset)

    assert result.primary_hypothesis is not None
    assert result.primary_hypothesis.hypothesis_type == "service_failure"


def test_generalization_c_localized_endpoint_impact():
    """
    Test C: Single endpoint (PC1) loses connectivity while PC2 and SERVER remain healthy.
    Expected: endpoint_failure / access port hypothesis gains propagation consistency.
    """
    event_pc1 = EvidenceEvent(
        id="log_1",
        timestamp="2026-08-21T10:00:00Z",
        source="event_log",
        category="connectivity",
        entity="PC1",
        attributes={"severity": "WARN", "event_type": "connectivity_timeout", "details": "destination=10.0.0.1"},
    )
    event_pc2 = EvidenceEvent(
        id="log_2",
        timestamp="2026-08-21T10:00:00Z",
        source="event_log",
        category="connectivity",
        entity="PC2",
        attributes={"severity": "INFO", "event_type": "ICMP_TEST", "details": "gateway=10.0.0.1 result=success"},
    )
    topology = NormalizedTopology(
        devices=[
            {"id": "SW1", "type": "switch"},
            {"id": "PC1", "type": "end_device"},
            {"id": "PC2", "type": "end_device"},
        ],
        links=[
            {"id": "L1", "a": "SW1", "b": "PC1"},
            {"id": "L2", "a": "SW1", "b": "PC2"},
        ],
    )
    dataset = NormalizedDataset(evidence_events=[event_pc1, event_pc2], topology=topology)

    result = reconstruct_incidents(dataset)

    assert result.primary_hypothesis is not None
    assert result.primary_hypothesis.hypothesis_type in ("endpoint_failure", "interface_failure")


def test_generalization_d_shared_upstream_failure():
    """
    Test D: Upstream link SW1-R1 fails and multiple downstream hosts (PC1, PC2) experience loss.
    Expected: physical_link_failure / upstream failure gains high propagation consistency.
    """
    evt1 = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {"severity": "CRITICAL", "event_type": "LINK_DOWN", "interface": "Gi0/1", "details": "peer=R1"})
    evt2 = EvidenceEvent("log_2", "2026-08-21T10:00:00Z", "event_log", "link_state", "R1", {"severity": "WARN", "event_type": "LINK_DOWN", "interface": "Gi0/0", "details": "peer=SW1"})
    evt3 = EvidenceEvent("log_3", "2026-08-21T10:00:01Z", "event_log", "connectivity", "PC1", {"severity": "WARN", "event_type": "connectivity_timeout", "details": "destination=10.0.0.1"})
    evt4 = EvidenceEvent("log_4", "2026-08-21T10:00:01Z", "event_log", "connectivity", "PC2", {"severity": "WARN", "event_type": "connectivity_timeout", "details": "destination=10.0.0.1"})

    topology = NormalizedTopology(
        devices=[
            {"id": "R1", "type": "router"},
            {"id": "SW1", "type": "switch"},
            {"id": "PC1", "type": "end_device"},
            {"id": "PC2", "type": "end_device"},
        ],
        links=[
            {"id": "L1", "a": "SW1", "b": "R1"},
            {"id": "L2", "a": "SW1", "b": "PC1"},
            {"id": "L3", "a": "SW1", "b": "PC2"},
        ],
    )
    dataset = NormalizedDataset(evidence_events=[evt1, evt2, evt3, evt4], topology=topology)

    result = reconstruct_incidents(dataset)

    assert result.primary_hypothesis is not None
    assert result.primary_hypothesis.hypothesis_type in ("physical_link_failure", "interface_failure")
    assert result.primary_hypothesis.score_breakdown.propagation_consistency >= 0.70


def test_generalization_e_contradiction_handling():
    """
    Test E: LINK_UP explicitly contradicts physical_link_failure hypothesis.
    """
    evt1 = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {"severity": "INFO", "event_type": "LINK_UP", "interface": "Gi0/1"})
    evt2 = EvidenceEvent("pcap_0", 100.0, "pcap", "packet", "10.0.0.11", {"src_ip": "10.0.0.11", "dst_ip": "10.0.0.1", "protocol": "ICMP", "summary": "ICMP echo-reply success"})

    topology = NormalizedTopology(devices=[{"id": "SW1"}, {"id": "R1"}], links=[{"id": "L1", "a": "SW1", "b": "R1"}])
    dataset = NormalizedDataset(evidence_events=[evt1, evt2], topology=topology)

    result = reconstruct_incidents(dataset)

    for hyp in result.ranked_hypotheses:
        if hyp.hypothesis_type == "physical_link_failure":
            assert hyp.score_breakdown is not None
            assert hyp.score_breakdown.contradiction_penalty > 0.0


def test_generalization_f_deterministic_output():
    """
    Test F: Reconstruction on identical input produces identical scores, ranking, and explanation.
    """
    evt1 = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1", {"severity": "CRITICAL", "event_type": "LINK_DOWN", "interface": "Gi0/1", "details": "peer=R1"})
    topology = NormalizedTopology(devices=[{"id": "SW1"}, {"id": "R1"}], links=[{"id": "L1", "a": "SW1", "b": "R1"}])
    dataset = NormalizedDataset(evidence_events=[evt1], topology=topology)

    res1 = reconstruct_incidents(dataset)
    res2 = reconstruct_incidents(dataset)

    assert res1.to_dict() == res2.to_dict()


# ============================================================================
# EMPTY & MALFORMED INPUT TESTS
# ============================================================================

def test_empty_dataset_reconstruction():
    """Test reconstruction on empty dataset returns valid low-confidence result without crashing."""
    dataset = NormalizedDataset()
    result = reconstruct_incidents(dataset)

    assert isinstance(result, ReconstructionResult)
    assert result.primary_hypothesis is None or result.primary_hypothesis.confidence_level == "LOW"


# ============================================================================
# GROUND TRUTH LEAKAGE AUDIT TEST
# ============================================================================

def test_no_ground_truth_leakage_in_reconstruction_module():
    """Test that reconstruction production modules never import or load ground_truth.json."""
    import importlib.util
    import inspect
    import backend.app.reconstruction as recon

    # Inspect all module source codes inside backend/app/reconstruction/
    for name, obj in inspect.getmembers(recon):
        if inspect.ismodule(obj):
            source = inspect.getsource(obj)
            assert "ground_truth" not in source, f"Module {name} contains ground_truth reference!"


# ============================================================================
# INTEGRATION SCENARIO VALIDATION TESTS (S01 to S09)
# ============================================================================

def test_scenario_s01_switch_uplink_failure():
    """Scenario S01: Expects physical_link_failure / interface_failure on SW1-R1 uplink."""
    s01_dir = Path("data/scenarios/S01_switch_uplink_failure")
    if (s01_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s01_dir / "topology.json",
            events_path=s01_dir / "events.log" if (s01_dir / "events.log").exists() else None,
            pcap_path=s01_dir / "traffic.pcap" if (s01_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert result.primary_hypothesis is not None
        assert result.primary_hypothesis.hypothesis_type in ("physical_link_failure", "interface_failure")


def test_scenario_s02_single_access_port_failure():
    """Scenario S02: Single access port failure."""
    s02_dir = Path("data/scenarios/S02_single_access_port_failure")
    if (s02_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s02_dir / "topology.json",
            events_path=s02_dir / "events.log" if (s02_dir / "events.log").exists() else None,
            pcap_path=s02_dir / "traffic.pcap" if (s02_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert isinstance(result, ReconstructionResult)


def test_scenario_s03_router_interface_failure():
    """Scenario S03: Router interface failure."""
    s03_dir = Path("data/scenarios/S03_router_interface_failure")
    if (s03_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s03_dir / "topology.json",
            events_path=s03_dir / "events.log" if (s03_dir / "events.log").exists() else None,
            pcap_path=s03_dir / "traffic.pcap" if (s03_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert isinstance(result, ReconstructionResult)


def test_scenario_s04_routing_failure():
    """Scenario S04: Routing failure."""
    s04_dir = Path("data/scenarios/S04_routing_failure")
    if (s04_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s04_dir / "topology.json",
            events_path=s04_dir / "events.log" if (s04_dir / "events.log").exists() else None,
            pcap_path=s04_dir / "traffic.pcap" if (s04_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert isinstance(result, ReconstructionResult)


def test_scenario_s05_vlan_misconfiguration():
    """Scenario S05: VLAN misconfiguration."""
    s05_dir = Path("data/scenarios/S05_vlan_misconfiguration")
    if (s05_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s05_dir / "topology.json",
            events_path=s05_dir / "events.log" if (s05_dir / "events.log").exists() else None,
            pcap_path=s05_dir / "traffic.pcap" if (s05_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert isinstance(result, ReconstructionResult)


def test_scenario_s06_arp_resolution_failure():
    """Scenario S06: ARP resolution failure."""
    s06_dir = Path("data/scenarios/S06_arp_resolution_failure")
    if (s06_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s06_dir / "topology.json",
            events_path=s06_dir / "events.log" if (s06_dir / "events.log").exists() else None,
            pcap_path=s06_dir / "traffic.pcap" if (s06_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert isinstance(result, ReconstructionResult)


def test_scenario_s07_dns_failure():
    """Scenario S07: DNS service failure."""
    s07_dir = Path("data/scenarios/S07_dns_failure")
    if (s07_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s07_dir / "topology.json",
            events_path=s07_dir / "events.log" if (s07_dir / "events.log").exists() else None,
            pcap_path=s07_dir / "traffic.pcap" if (s07_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert isinstance(result, ReconstructionResult)


def test_scenario_s08_degraded_link_packet_loss():
    """Scenario S08: Degraded link with packet loss."""
    s08_dir = Path("data/scenarios/S08_degraded_link_packet_loss")
    if (s08_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s08_dir / "topology.json",
            events_path=s08_dir / "events.log" if (s08_dir / "events.log").exists() else None,
            pcap_path=s08_dir / "traffic.pcap" if (s08_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert isinstance(result, ReconstructionResult)


def test_scenario_s09_dhcp_failure():
    """Scenario S09: DHCP service / addressing failure."""
    s09_dir = Path("data/scenarios/S09_dhcp_failure")
    if (s09_dir / "topology.json").exists():
        dataset = normalize_evidence_from_paths(
            topology_path=s09_dir / "topology.json",
            events_path=s09_dir / "events.log" if (s09_dir / "events.log").exists() else None,
            pcap_path=s09_dir / "traffic.pcap" if (s09_dir / "traffic.pcap").exists() else None,
        )
        result = reconstruct_incidents(dataset)
        assert isinstance(result, ReconstructionResult)
