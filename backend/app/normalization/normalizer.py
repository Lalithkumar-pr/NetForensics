"""
Evidence normalizer module for NetForensics.
Transforms outputs from Phase 1 ingestion loaders into a unified internal representation.
"""

from pathlib import Path
from typing import List, Optional, Union

from backend.app.ingestion.event_log_loader import EventLogEntry, load_events
from backend.app.ingestion.pcap_loader import PacketRecord, load_pcap
from backend.app.ingestion.topology_loader import TopologyData, load_topology
from .models import EvidenceEvent, NormalizedDataset, NormalizedTopology


def determine_event_category(event_type: Optional[str]) -> str:
    """
    Deterministically categorizes an event based on its event_type string.
    """
    if not event_type:
        return "system_event"

    upper_type = event_type.upper()
    if "LINK" in upper_type or "UPLINK" in upper_type:
        return "link_state"
    elif "OSPF" in upper_type or "ROUTE" in upper_type or "ROUTING" in upper_type:
        return "routing_event"
    elif "ICMP" in upper_type or "CONNECTIVITY" in upper_type or "TIMEOUT" in upper_type:
        return "connectivity"
    else:
        return "system_event"


def normalize_event_log_entry(entry: EventLogEntry) -> EvidenceEvent:
    """
    Normalizes a single Phase 1 EventLogEntry into an EvidenceEvent.
    """
    return EvidenceEvent(
        id=f"log_{entry.line_number}",
        timestamp=entry.timestamp,
        source="event_log",
        category=determine_event_category(entry.event_type),
        entity=entry.device,
        attributes={
            "severity": entry.severity,
            "event_type": entry.event_type,
            "interface": entry.interface,
            "details": entry.details,
        },
        raw_reference={
            "line_number": entry.line_number,
            "raw_line": entry.raw,
        },
    )


def normalize_packet_record(pkt: PacketRecord) -> EvidenceEvent:
    """
    Normalizes a single Phase 1 PacketRecord into an EvidenceEvent.
    """
    return EvidenceEvent(
        id=f"pcap_{pkt.packet_index}",
        timestamp=pkt.timestamp,
        source="pcap",
        category="packet",
        entity=pkt.src_ip,
        attributes={
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "protocol": pkt.protocol,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "length": pkt.length,
            "summary": pkt.summary,
        },
        raw_reference={
            "packet_index": pkt.packet_index,
            "summary": pkt.summary,
        },
    )


def normalize_topology(topology_data: TopologyData) -> NormalizedTopology:
    """
    Normalizes Phase 1 TopologyData into a NormalizedTopology representation.
    """
    return NormalizedTopology(
        devices=[dict(d) for d in topology_data.devices],
        links=[dict(l) for l in topology_data.links],
        raw=dict(topology_data.raw),
    )


def normalize_dataset(
    topology_data: Optional[TopologyData] = None,
    event_entries: Optional[List[EventLogEntry]] = None,
    packet_records: Optional[List[PacketRecord]] = None,
) -> NormalizedDataset:
    """
    Combines Phase 1 parsed inputs into a NormalizedDataset.
    """
    events: List[EvidenceEvent] = []

    if event_entries:
        events.extend(normalize_event_log_entry(entry) for entry in event_entries)

    if packet_records:
        events.extend(normalize_packet_record(pkt) for pkt in packet_records)

    norm_topo = normalize_topology(topology_data) if topology_data else NormalizedTopology()

    return NormalizedDataset(
        evidence_events=events,
        topology=norm_topo,
    )


def normalize_evidence_from_paths(
    topology_path: Optional[Union[str, Path]] = None,
    events_path: Optional[Union[str, Path]] = None,
    pcap_path: Optional[Union[str, Path]] = None,
) -> NormalizedDataset:
    """
    Convenience function that invokes Phase 1 loaders on file paths and normalizes the results.
    """
    topology_data = load_topology(topology_path) if topology_path else None
    event_entries = load_events(events_path) if events_path else None
    packet_records = load_pcap(pcap_path) if pcap_path else None

    return normalize_dataset(
        topology_data=topology_data,
        event_entries=event_entries,
        packet_records=packet_records,
    )
