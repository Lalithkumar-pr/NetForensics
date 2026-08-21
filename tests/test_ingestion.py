"""
Unit test suite for NetForensics evidence ingestion layer.
"""

from pathlib import Path
import pytest
from scapy.all import Ether, IP, ICMP, ARP, wrpcap

from backend.app.ingestion.exceptions import (
    EventLogNotFoundError,
    InvalidEventLogError,
    InvalidPcapError,
    InvalidTopologyError,
    PcapNotFoundError,
    TopologyNotFoundError,
)
from backend.app.ingestion.event_log_loader import EventLogEntry, load_events
from backend.app.ingestion.pcap_loader import PacketRecord, load_pcap
from backend.app.ingestion.topology_loader import TopologyData, load_topology


# ============================================================================
# TOPOLOGY LOADER TESTS
# ============================================================================

def test_load_valid_topology(tmp_path: Path):
    """Test loading a valid topology.json file."""
    topo_file = tmp_path / "topology.json"
    content = """{
        "schema_version": "1.0",
        "scenario_id": "TEST_01",
        "description": "Test topology",
        "devices": [
            {"id": "R1", "type": "router", "ip": "10.0.0.1"},
            {"id": "SW1", "type": "switch", "management_ip": "10.0.0.2"}
        ],
        "links": [
            {"id": "L1", "a": "R1", "b": "SW1", "a_interface": "Gi0/0", "b_interface": "Gi0/1", "status": "up"}
        ]
    }"""
    topo_file.write_text(content, encoding="utf-8")

    topo_data = load_topology(topo_file)

    assert isinstance(topo_data, TopologyData)
    assert topo_data.scenario_id == "TEST_01"
    assert topo_data.schema_version == "1.0"
    assert len(topo_data.devices) == 2
    assert len(topo_data.links) == 1
    assert topo_data.devices[0]["id"] == "R1"
    assert topo_data.links[0]["id"] == "L1"
    assert topo_data.to_dict()["description"] == "Test topology"


def test_missing_topology_file():
    """Test that missing topology file raises TopologyNotFoundError."""
    with pytest.raises(TopologyNotFoundError) as exc_info:
        load_topology("non_existent_path/topology.json")
    assert "not found" in str(exc_info.value)


def test_malformed_topology_json(tmp_path: Path):
    """Test that malformed JSON raises InvalidTopologyError."""
    topo_file = tmp_path / "topology.json"
    topo_file.write_text("{devices: [invalid_json", encoding="utf-8")

    with pytest.raises(InvalidTopologyError) as exc_info:
        load_topology(topo_file)
    assert "Invalid JSON syntax" in str(exc_info.value)


def test_invalid_topology_structure(tmp_path: Path):
    """Test that non-object JSON root or invalid list structure raises InvalidTopologyError."""
    topo_file = tmp_path / "topology.json"
    topo_file.write_text('{"devices": "not_a_list"}', encoding="utf-8")

    with pytest.raises(InvalidTopologyError) as exc_info:
        load_topology(topo_file)
    assert "must be a list" in str(exc_info.value)


# ============================================================================
# EVENT LOG LOADER TESTS
# ============================================================================

def test_load_valid_events(tmp_path: Path):
    """Test parsing valid events.log file entries."""
    log_file = tmp_path / "events.log"
    log_content = (
        "2026-08-21T10:00:00Z SW1 INFO Gi0/1 LINK_UP\n"
        "2026-08-21T10:00:01Z PC1 INFO ICMP_TEST gateway=10.0.0.1 result=success\n"
        "2026-08-21T10:00:02Z SW1 CRITICAL Gi0/1 LINK_DOWN peer=R1\n"
        "2026-08-21T10:00:03Z PC1 WARN connectivity_timeout destination=10.0.0.1\n"
    )
    log_file.write_text(log_content, encoding="utf-8")

    entries = load_events(log_file)

    assert len(entries) == 4

    # Entry 1 with interface
    e0 = entries[0]
    assert e0.timestamp == "2026-08-21T10:00:00Z"
    assert e0.device == "SW1"
    assert e0.severity == "INFO"
    assert e0.interface == "Gi0/1"
    assert e0.event_type == "LINK_UP"

    # Entry 2 without explicit interface parameter
    e1 = entries[1]
    assert e1.device == "PC1"
    assert e1.severity == "INFO"
    assert e1.event_type == "ICMP_TEST"
    assert e1.details == "gateway=10.0.0.1 result=success"

    # Entry 3 with details key-value
    e2 = entries[2]
    assert e2.severity == "CRITICAL"
    assert e2.interface == "Gi0/1"
    assert e2.event_type == "LINK_DOWN"
    assert e2.details == "peer=R1"


def test_missing_event_log_file():
    """Test that missing event log raises EventLogNotFoundError."""
    with pytest.raises(EventLogNotFoundError) as exc_info:
        load_events("non_existent_path/events.log")
    assert "not found" in str(exc_info.value)


def test_malformed_event_log_line(tmp_path: Path):
    """Test handling of malformed event log lines."""
    log_file = tmp_path / "events.log"
    log_file.write_text("2026-08-21T10:00:00Z INVALID_LINE_ONLY_TWO_TOKENS\n", encoding="utf-8")

    with pytest.raises(InvalidEventLogError) as exc_info:
        load_events(log_file)
    assert "Malformed log entry" in str(exc_info.value)


# ============================================================================
# PCAP LOADER TESTS
# ============================================================================

def test_load_valid_pcap_fixture(tmp_path: Path):
    """Test loading packet records from a generated test PCAP fixture."""
    pcap_file = tmp_path / "test_fixture.pcap"

    # Create test packets: 1 IP/ICMP, 1 ARP
    pkts = [
        Ether() / IP(src="10.0.0.11", dst="10.0.0.1") / ICMP(),
        Ether() / ARP(psrc="10.0.0.11", pdst="10.0.0.1"),
    ]
    wrpcap(str(pcap_file), pkts)

    records = load_pcap(pcap_file)

    assert len(records) == 2

    r0 = records[0]
    assert isinstance(r0, PacketRecord)
    assert r0.packet_index == 0
    assert r0.src_ip == "10.0.0.11"
    assert r0.dst_ip == "10.0.0.1"
    assert r0.protocol == "ICMP"

    r1 = records[1]
    assert r1.packet_index == 1
    assert r1.src_ip == "10.0.0.11"
    assert r1.dst_ip == "10.0.0.1"
    assert r1.protocol == "ARP"


def test_packet_without_ip_layer_does_not_crash(tmp_path: Path):
    """Test that non-IP packets (e.g. raw Ethernet) do not crash the PCAP loader."""
    pcap_file = tmp_path / "non_ip_test_fixture.pcap"

    # Raw Ethernet frame without IP or ARP
    pkts = [Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")]
    wrpcap(str(pcap_file), pkts)

    records = load_pcap(pcap_file)

    assert len(records) == 1
    r = records[0]
    assert r.src_ip is None
    assert r.dst_ip is None
    assert r.protocol != "UNKNOWN"


def test_missing_pcap_file():
    """Test that missing PCAP file raises PcapNotFoundError."""
    with pytest.raises(PcapNotFoundError) as exc_info:
        load_pcap("non_existent_path/traffic.pcap")
    assert "not found" in str(exc_info.value)


def test_invalid_pcap_file(tmp_path: Path):
    """Test that corrupt/invalid PCAP file raises InvalidPcapError."""
    pcap_file = tmp_path / "corrupt.pcap"
    pcap_file.write_text("NOT_A_VALID_PCAP_BINARY_DATA", encoding="utf-8")

    with pytest.raises(InvalidPcapError) as exc_info:
        load_pcap(pcap_file)
    assert "Could not read PCAP file" in str(exc_info.value)


def test_load_pcap_scenario_s01():
    """Smoke test running PCAP loader against S01 dataset traffic.pcap."""
    s01_pcap = Path("data/scenarios/S01_switch_uplink_failure/traffic.pcap")
    assert s01_pcap.exists(), "S01 traffic.pcap is missing"
    records = load_pcap(s01_pcap)
    assert len(records) > 0
    assert any(r.protocol == "ICMP" for r in records)
