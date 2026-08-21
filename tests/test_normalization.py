"""
Unit test suite for NetForensics evidence normalization layer.
"""

from pathlib import Path
import pytest
from scapy.all import Ether, IP, ICMP, wrpcap

from backend.app.ingestion.event_log_loader import EventLogEntry, load_events
from backend.app.ingestion.exceptions import EventLogNotFoundError, TopologyNotFoundError
from backend.app.ingestion.pcap_loader import PacketRecord, load_pcap
from backend.app.ingestion.topology_loader import TopologyData, load_topology
from backend.app.normalization import (
    EvidenceEvent,
    NormalizedDataset,
    NormalizedTopology,
    normalize_dataset,
    normalize_event_log_entry,
    normalize_evidence_from_paths,
    normalize_packet_record,
    normalize_topology,
)


def test_normalize_event_log_entry():
    """Test normalizing a valid EventLogEntry."""
    entry = EventLogEntry(
        timestamp="2026-08-21T10:00:00Z",
        device="SW1",
        severity="CRITICAL",
        event_type="LINK_DOWN",
        interface="Gi0/1",
        details="peer=R1",
        raw="2026-08-21T10:00:00Z SW1 CRITICAL Gi0/1 LINK_DOWN peer=R1",
        line_number=5,
    )

    event = normalize_event_log_entry(entry)

    assert isinstance(event, EvidenceEvent)
    assert event.id == "log_5"
    assert event.source == "event_log"
    assert event.timestamp == "2026-08-21T10:00:00Z"
    assert event.category == "link_state"
    assert event.entity == "SW1"
    assert event.attributes["severity"] == "CRITICAL"
    assert event.attributes["event_type"] == "LINK_DOWN"
    assert event.attributes["interface"] == "Gi0/1"
    assert event.attributes["details"] == "peer=R1"
    assert event.raw_reference["line_number"] == 5
    assert event.raw_reference["raw_line"] == entry.raw


def test_normalize_packet_record():
    """Test normalizing a valid PacketRecord."""
    pkt = PacketRecord(
        packet_index=42,
        timestamp=1700000000.5,
        src_ip="10.0.0.11",
        dst_ip="10.0.0.1",
        protocol="ICMP",
        src_port=None,
        dst_port=None,
        length=64,
        summary="Ether / IP / ICMP 10.0.0.11 > 10.0.0.1 echo-request 0",
    )

    event = normalize_packet_record(pkt)

    assert isinstance(event, EvidenceEvent)
    assert event.id == "pcap_42"
    assert event.source == "pcap"
    assert event.timestamp == 1700000000.5
    assert event.category == "packet"
    assert event.entity == "10.0.0.11"
    assert event.attributes["src_ip"] == "10.0.0.11"
    assert event.attributes["dst_ip"] == "10.0.0.1"
    assert event.attributes["protocol"] == "ICMP"
    assert event.attributes["length"] == 64
    assert event.raw_reference["packet_index"] == 42


def test_packet_id_is_deterministic():
    """Test that packet IDs are completely deterministic."""
    pkt1 = PacketRecord(0, 100.0, "10.0.0.1", "10.0.0.2", "TCP", 80, 1234, 54, "summary")
    pkt2 = PacketRecord(0, 100.0, "10.0.0.1", "10.0.0.2", "TCP", 80, 1234, 54, "summary")

    event1 = normalize_packet_record(pkt1)
    event2 = normalize_packet_record(pkt2)

    assert event1.id == event2.id == "pcap_0"


def test_normalize_topology_separately():
    """Test normalizing topology independently from evidence events."""
    topo_data = TopologyData(
        schema_version="1.0",
        scenario_id="S01",
        description="Switch uplink failure",
        devices=[{"id": "SW1", "type": "switch"}, {"id": "R1", "type": "router"}],
        links=[{"id": "L1", "a": "SW1", "b": "R1"}],
        raw={"schema_version": "1.0", "scenario_id": "S01"},
    )

    norm_topo = normalize_topology(topo_data)

    assert isinstance(norm_topo, NormalizedTopology)
    assert len(norm_topo.devices) == 2
    assert len(norm_topo.links) == 1
    assert norm_topo.devices[0]["id"] == "SW1"
    assert norm_topo.links[0]["id"] == "L1"
    assert norm_topo.raw["scenario_id"] == "S01"


def test_normalize_dataset_combines_events_and_topology():
    """Test top-level normalize_dataset combining events and topology."""
    entry = EventLogEntry("2026-08-21T10:00:00Z", "R1", "INFO", "LINK_UP", "Gi0/0", None, "raw", 1)
    pkt = PacketRecord(0, 100.0, "10.0.0.1", "10.0.0.2", "ICMP", None, None, 64, "summary")
    topo = TopologyData("1.0", "S01", "desc", [{"id": "R1"}], [{"id": "L1"}], {})

    dataset = normalize_dataset(topo, [entry], [pkt])

    assert isinstance(dataset, NormalizedDataset)
    assert len(dataset.evidence_events) == 2
    assert dataset.evidence_events[0].source == "event_log"
    assert dataset.evidence_events[1].source == "pcap"
    assert len(dataset.topology.devices) == 1
    assert len(dataset.topology.links) == 1


def test_normalize_empty_collections():
    """Test handling of empty evidence collections."""
    dataset = normalize_dataset(None, [], [])

    assert isinstance(dataset, NormalizedDataset)
    assert len(dataset.evidence_events) == 0
    assert len(dataset.topology.devices) == 0
    assert len(dataset.topology.links) == 0


def test_phase1_ingestion_exceptions_propagated():
    """Test that missing evidence file exceptions from Phase 1 are not swallowed."""
    with pytest.raises(TopologyNotFoundError):
        normalize_evidence_from_paths(topology_path="non_existent/topology.json")

    with pytest.raises(EventLogNotFoundError):
        normalize_evidence_from_paths(events_path="non_existent/events.log")


def test_normalize_s01_scenario_dataset():
    """Integration test normalizing real scenario S01 dataset files."""
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

    assert isinstance(dataset, NormalizedDataset)
    assert len(dataset.topology.devices) > 0
    assert len(dataset.topology.links) > 0
    assert len(dataset.evidence_events) > 0

    log_events = [e for e in dataset.evidence_events if e.source == "event_log"]
    pcap_events = [e for e in dataset.evidence_events if e.source == "pcap"]

    assert len(log_events) > 0
    assert len(pcap_events) > 0
