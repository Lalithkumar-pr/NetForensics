"""
Unit test suite for NetForensics evidence correlation layer.
"""

from pathlib import Path
import pytest

from backend.app.correlation import (
    CorrelationConfig,
    CorrelationRelationship,
    CorrelationResult,
    check_entity_rule,
    check_network_flow_rule,
    check_temporal_rule,
    check_topology_rule,
    correlate_dataset,
    parse_timestamp,
)
from backend.app.normalization import (
    EvidenceEvent,
    NormalizedDataset,
    NormalizedTopology,
    normalize_evidence_from_paths,
)


def test_parse_timestamp_formats():
    """Test parsing ISO-8601 strings and float timestamps."""
    ts1 = parse_timestamp("2026-08-21T10:42:00Z")
    ts2 = parse_timestamp("2026-08-21T10:42:05Z")
    assert ts1 is not None and ts2 is not None
    assert ts2 - ts1 == 5.0

    ts_float = parse_timestamp(1700000000.5)
    assert ts_float == 1700000000.5


def test_temporal_correlation_within_window():
    """Test that events within the temporal window are correlated."""
    event1 = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1")
    event2 = EvidenceEvent("log_2", "2026-08-21T10:00:03Z", "event_log", "link_state", "SW2")
    dataset = NormalizedDataset(evidence_events=[event1, event2])

    config = CorrelationConfig(temporal_window_seconds=5.0)
    result = correlate_dataset(dataset, config)

    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert "temporal" in rel.relationship_types
    assert rel.time_delta == 3.0
    assert "within configured temporal window" in rel.explanation


def test_no_temporal_correlation_outside_window():
    """Test that events outside the temporal window do not get temporal correlation."""
    event1 = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1")
    event2 = EvidenceEvent("log_2", "2026-08-21T10:05:00Z", "event_log", "link_state", "SW2")
    dataset = NormalizedDataset(evidence_events=[event1, event2])

    config = CorrelationConfig(temporal_window_seconds=10.0)
    result = correlate_dataset(dataset, config)

    assert len(result.relationships) == 0


def test_same_entity_correlation():
    """Test that events referencing the same entity are correlated."""
    event1 = EvidenceEvent("log_1", None, "event_log", "link_state", "SW1")
    event2 = EvidenceEvent("log_2", None, "event_log", "system_event", "SW1")
    dataset = NormalizedDataset(evidence_events=[event1, event2])

    result = correlate_dataset(dataset)

    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert "entity" in rel.relationship_types
    assert "SW1" in rel.explanation


def test_topology_based_correlation():
    """Test topology link correlation between adjacent devices."""
    event1 = EvidenceEvent("log_1", None, "event_log", "link_state", "SW1")
    event2 = EvidenceEvent("log_2", None, "event_log", "link_state", "R1")
    topology = NormalizedTopology(
        devices=[{"id": "SW1"}, {"id": "R1"}],
        links=[{"id": "L1", "a": "SW1", "b": "R1", "a_interface": "Gi0/1", "b_interface": "Gi0/0"}],
    )
    dataset = NormalizedDataset(evidence_events=[event1, event2], topology=topology)

    result = correlate_dataset(dataset)

    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert "topology" in rel.relationship_types
    assert "L1" in rel.explanation


def test_network_flow_correlation():
    """Test packet flow correlation with log event details."""
    event_pcap = EvidenceEvent(
        id="pcap_0",
        timestamp="2026-08-21T10:00:00Z",
        source="pcap",
        category="packet",
        entity="10.0.0.11",
        attributes={"src_ip": "10.0.0.11", "dst_ip": "10.0.0.1", "protocol": "ICMP"},
    )
    event_log = EvidenceEvent(
        id="log_1",
        timestamp="2026-08-21T10:00:01Z",
        source="event_log",
        category="connectivity",
        entity="PC1",
        attributes={"details": "connectivity_timeout destination=10.0.0.1"},
    )
    dataset = NormalizedDataset(evidence_events=[event_pcap, event_log])

    result = correlate_dataset(dataset)

    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert "network_flow" in rel.relationship_types
    assert "10.0.0.1" in rel.explanation


def test_deterministic_relationship_generation():
    """Test that correlation output is 100% deterministic."""
    event1 = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1")
    event2 = EvidenceEvent("log_2", "2026-08-21T10:00:01Z", "event_log", "link_state", "SW1")
    dataset = NormalizedDataset(evidence_events=[event1, event2])

    res1 = correlate_dataset(dataset)
    res2 = correlate_dataset(dataset)

    assert res1.to_dict() == res2.to_dict()


def test_human_readable_explanations():
    """Test that relationship explanations are human readable and non-empty."""
    event1 = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "link_state", "SW1")
    event2 = EvidenceEvent("log_2", "2026-08-21T10:00:02Z", "event_log", "link_state", "SW1")
    dataset = NormalizedDataset(evidence_events=[event1, event2])

    result = correlate_dataset(dataset)
    assert len(result.relationships) > 0
    rel = result.relationships[0]
    assert isinstance(rel.explanation, str)
    assert len(rel.explanation) > 10


def test_empty_evidence_handling():
    """Test running correlator on empty normalized dataset."""
    dataset = NormalizedDataset()
    result = correlate_dataset(dataset)

    assert isinstance(result, CorrelationResult)
    assert len(result.relationships) == 0


def test_unrelated_events_no_relationship():
    """Test that completely unrelated events produce no false relationships."""
    event1 = EvidenceEvent("log_1", "2026-08-21T10:00:00Z", "event_log", "system_event", "SW1")
    event2 = EvidenceEvent("log_2", "2026-08-21T12:00:00Z", "event_log", "system_event", "SW2")
    topology = NormalizedTopology(devices=[{"id": "SW1"}, {"id": "SW2"}], links=[])
    dataset = NormalizedDataset(evidence_events=[event1, event2], topology=topology)

    result = correlate_dataset(dataset)
    assert len(result.relationships) == 0


def test_s01_scenario_correlation():
    """Integration test correlating scenario S01 dataset evidence."""
    s01_dir = Path("data/scenarios/S01_switch_uplink_failure")

    topo_path = s01_dir / "topology.json"
    events_path = s01_dir / "events.log"
    pcap_path = s01_dir / "traffic.pcap"

    assert topo_path.exists()
    assert events_path.exists()
    assert pcap_path.exists()

    dataset = normalize_evidence_from_paths(
        topology_path=topo_path,
        events_path=events_path,
        pcap_path=pcap_path,
    )

    result = correlate_dataset(dataset)

    assert isinstance(result, CorrelationResult)
    assert len(result.relationships) > 0

    # Verify SW1 link down log event correlates with R1 link down log event (topology + temporal)
    rel_sw_r1 = [
        r for r in result.relationships
        if ("topology" in r.relationship_types or "temporal" in r.relationship_types)
        and ("log_5" in (r.source_event_id, r.target_event_id) or "log_7" in (r.source_event_id, r.target_event_id))
    ]
    assert len(rel_sw_r1) > 0
